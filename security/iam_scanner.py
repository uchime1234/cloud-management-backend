import boto3
from datetime import datetime, timedelta
from django.conf import settings
import logging
import requests

logger = logging.getLogger(__name__)

def assume_iam_role(role_arn, external_id):
    """Assume IAM role and return IAM client"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="IAMSecurityScanner",
            ExternalId=str(external_id)
        )
        
        credentials = response["Credentials"]
        
        iam = boto3.client(
            'iam',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        return iam
    except Exception as e:
        logger.error(f"Failed to assume role: {e}")
        return None


def get_all_iam_users(iam_client):
    """Get all IAM users in the account"""
    try:
        users = []
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page['Users'])
        return users
    except Exception as e:
        logger.error(f"Error getting IAM users: {e}")
        return []


def get_all_iam_roles(iam_client):
    """Get all IAM roles in the account"""
    try:
        roles = []
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            roles.extend(page['Roles'])
        return roles
    except Exception as e:
        logger.error(f"Error getting IAM roles: {e}")
        return []


def check_admin_access(iam_client, user_name):
    """Check if user has AdministratorAccess policy attached"""
    try:
        # Check attached managed policies
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies.get('AttachedPolicies', []):
            if 'AdministratorAccess' in policy['PolicyName']:
                return True, policy['PolicyArn']
        
        # Check inline policies
        inline_policies = iam_client.list_user_policies(UserName=user_name)
        for policy_name in inline_policies.get('PolicyNames', []):
            policy = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policy_doc = policy.get('PolicyDocument', {})
            # Check if policy grants admin access
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    action = statement.get('Action', '')
                    resource = statement.get('Resource', '')
                    if action == '*' or action == ['*']:
                        if resource == '*' or resource == ['*']:
                            return True, f"Inline policy: {policy_name}"
        
        return False, None
    except Exception as e:
        logger.error(f"Error checking admin access for {user_name}: {e}")
        return False, None


def check_mfa_enabled(iam_client, user_name):
    """Check if MFA is enabled for the user"""
    try:
        mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
        return len(mfa_devices.get('MFADevices', [])) > 0
    except Exception as e:
        logger.error(f"Error checking MFA for {user_name}: {e}")
        return False


def check_access_keys(iam_client, user_name):
    """Check access keys for age and count"""
    try:
        access_keys = iam_client.list_access_keys(UserName=user_name)
        keys = access_keys.get('AccessKeyMetadata', [])
        
        active_keys = [k for k in keys if k['Status'] == 'Active']
        old_keys = []
        
        for key in active_keys:
            create_date = key['CreateDate']
            age_days = (datetime.now(create_date.tzinfo) - create_date).days
            if age_days > 90:
                old_keys.append({
                    'key_id': key['AccessKeyId'],
                    'age_days': age_days,
                    'create_date': create_date
                })
        
        return {
            'total_keys': len(keys),
            'active_keys': len(active_keys),
            'old_keys': old_keys,
            'has_multiple_active': len(active_keys) >= 2
        }
    except Exception as e:
        logger.error(f"Error checking access keys for {user_name}: {e}")
        return {'total_keys': 0, 'active_keys': 0, 'old_keys': [], 'has_multiple_active': False}


def check_user_activity(iam_client, user_name):
    """Check when user was last active"""
    try:
        # Get user details including password last used
        user_info = iam_client.get_user(UserName=user_name)
        password_last_used = user_info['User'].get('PasswordLastUsed')
        
        # Check access key last used
        key_last_used = None
        access_keys = iam_client.list_access_keys(UserName=user_name)
        for key in access_keys.get('AccessKeyMetadata', []):
            if key['Status'] == 'Active':
                # Get last used time for this key
                try:
                    last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    key_last_used_time = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    if key_last_used_time:
                        if not key_last_used or key_last_used_time > key_last_used:
                            key_last_used = key_last_used_time
                except:
                    pass
        
        # Get most recent activity
        last_activity = None
        if password_last_used and key_last_used:
            last_activity = max(password_last_used, key_last_used)
        elif password_last_used:
            last_activity = password_last_used
        elif key_last_used:
            last_activity = key_last_used
        
        if last_activity:
            days_inactive = (datetime.now(last_activity.tzinfo) - last_activity).days
        else:
            days_inactive = None
        
        return {
            'has_never_been_used': last_activity is None,
            'days_inactive': days_inactive,
            'password_last_used': password_last_used,
            'key_last_used': key_last_used
        }
    except Exception as e:
        logger.error(f"Error checking user activity for {user_name}: {e}")
        return {'has_never_been_used': True, 'days_inactive': None}


def check_wildcard_role(iam_client, role_name):
    """Check if role has wildcard (*) permissions"""
    try:
        # Check attached policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies.get('AttachedPolicies', []):
            # Get policy version
            policy_versions = iam_client.list_policy_versions(PolicyArn=policy['PolicyArn'])
            default_version = next((v for v in policy_versions['Versions'] if v['IsDefaultVersion']), None)
            if default_version:
                policy_doc = iam_client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=default_version['VersionId']
                )
                doc = policy_doc.get('PolicyVersion', {}).get('Document', {})
                for statement in doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        action = statement.get('Action', '')
                        resource = statement.get('Resource', '')
                        if action == '*' or action == ['*']:
                            if resource == '*' or resource == ['*']:
                                return True, f"Policy: {policy['PolicyName']}"
        
        # Check inline policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies.get('PolicyNames', []):
            policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policy_doc = policy.get('PolicyDocument', {})
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    action = statement.get('Action', '')
                    resource = statement.get('Resource', '')
                    if action == '*' or action == ['*']:
                        if resource == '*' or resource == ['*']:
                            return True, f"Inline policy: {policy_name}"
        
        return False, None
    except Exception as e:
        logger.error(f"Error checking wildcard for role {role_name}: {e}")
        return False, None


def scan_iam_security(role_arn, external_id):
    """Complete IAM security scan"""
    print("=" * 80)
    print("🔐 STARTING IAM SECURITY SCAN")
    print("=" * 80)
    
    # Assume role and get IAM client
    iam_client = assume_iam_role(role_arn, external_id)
    if not iam_client:
        return {'error': 'Failed to assume IAM role', 'findings': []}
    
    findings = []
    
    # 1. Scan IAM Users
    print("\n📊 Scanning IAM Users...")
    users = get_all_iam_users(iam_client)
    print(f"✅ Found {len(users)} IAM users")
    
    for user in users:
        user_name = user['UserName']
        user_arn = user['Arn']
        print(f"\n  🔍 Checking user: {user_name}")
        
        # Check MFA
        has_mfa = check_mfa_enabled(iam_client, user_name)
        if not has_mfa:
            findings.append({
                'finding_type': 'no_mfa',
                'severity': 'high',
                'resource_name': user_name,
                'title': f'IAM user {user_name} has no MFA enabled',
                'description': f'User {user_name} can authenticate without Multi-Factor Authentication',
                'recommendation': 'Enable MFA for this user immediately. Use virtual MFA (Google Authenticator) or hardware MFA.',
                'metadata': {'user_arn': user_arn}
            })
            print(f"    ❌ No MFA enabled")
        
        # Check Admin Access
        is_admin, policy_name = check_admin_access(iam_client, user_name)
        if is_admin:
            severity = 'critical' if not has_mfa else 'high'
            findings.append({
                'finding_type': 'admin_user',
                'severity': severity,
                'resource_name': user_name,
                'title': f'IAM user {user_name} has administrator access',
                'description': f'User {user_name} has full administrator privileges via {policy_name}',
                'recommendation': 'Remove admin privileges unless absolutely necessary. Use least privilege principle.',
                'metadata': {'policy': policy_name, 'has_mfa': has_mfa}
            })
            print(f"    ⚠️ Admin access detected")
        
        # Check Access Keys
        key_info = check_access_keys(iam_client, user_name)
        if key_info['has_multiple_active']:
            findings.append({
                'finding_type': 'multiple_keys',
                'severity': 'medium',
                'resource_name': user_name,
                'title': f'User {user_name} has {key_info["active_keys"]} active access keys',
                'description': f'Having multiple active access keys increases security risk',
                'recommendation': 'Remove unused access keys. Keep only one active key per user.',
                'metadata': {'active_keys': key_info['active_keys']}
            })
            print(f"    ⚠️ Multiple active keys: {key_info['active_keys']}")
        
        for old_key in key_info['old_keys']:
            findings.append({
                'finding_type': 'old_key',
                'severity': 'medium',
                'resource_name': user_name,
                'title': f'Access key for {user_name} is {old_key["age_days"]} days old',
                'description': f'Access key {old_key["key_id"][:10]}... was created {old_key["age_days"]} days ago',
                'recommendation': 'Rotate access keys every 90 days. Create new key, update applications, then delete old key.',
                'metadata': {'key_id': old_key['key_id'], 'age_days': old_key['age_days']}
            })
            print(f"    ⚠️ Old key: {old_key['age_days']} days")
        
        # Check User Activity (Unused Users)
        activity = check_user_activity(iam_client, user_name)
        if activity['has_never_been_used'] or (activity['days_inactive'] and activity['days_inactive'] > 90):
            days = activity['days_inactive'] if activity['days_inactive'] else 'never'
            findings.append({
                'finding_type': 'unused_user',
                'severity': 'low',
                'resource_name': user_name,
                'title': f'IAM user {user_name} is inactive',
                'description': f'User has not been active for {days} days',
                'recommendation': 'Delete or deactivate unused IAM users to reduce attack surface.',
                'metadata': {'days_inactive': days, 'never_used': activity['has_never_been_used']}
            })
            print(f"    ⚠️ Inactive user: {days} days")
    
    # 2. Scan IAM Roles for Wildcard Permissions
    print("\n📊 Scanning IAM Roles for wildcard permissions...")
    roles = get_all_iam_roles(iam_client)
    print(f"✅ Found {len(roles)} IAM roles")
    
    for role in roles:
        role_name = role['RoleName']
        has_wildcard, policy_name = check_wildcard_role(iam_client, role_name)
        if has_wildcard:
            findings.append({
                'finding_type': 'wildcard_role',
                'severity': 'high',
                'resource_name': role_name,
                'title': f'IAM role {role_name} has wildcard (*) permissions',
                'description': f'Role {role_name} allows full access via {policy_name}',
                'recommendation': 'Scope permissions to specific actions and resources. Avoid using * in IAM policies.',
                'metadata': {'role_arn': role['Arn'], 'policy': policy_name}
            })
            print(f"  ⚠️ Wildcard role: {role_name}")
    
    print("\n" + "=" * 80)
    print(f"✅ IAM SCAN COMPLETE - Found {len(findings)} issues")
    print("=" * 80)
    
    return {
        'success': True,
        'total_findings': len(findings),
        'findings': findings
    }


def generate_ai_recommendations(findings, account_alias):
    """
    Generate AI-powered security recommendations using Groq API
    """
    if not findings:
        return "No security issues found. Your IAM configuration looks secure! 🎉"
    
    # Prepare findings summary for AI
    critical_count = len([f for f in findings if f['severity'] == 'critical'])
    high_count = len([f for f in findings if f['severity'] == 'high'])
    medium_count = len([f for f in findings if f['severity'] == 'medium'])
    low_count = len([f for f in findings if f['severity'] == 'low'])
    
    # Build a concise summary of findings
    findings_text = ""
    for f in findings[:15]:  # Limit to 15 findings to avoid token limits
        findings_text += f"- [{f['severity'].upper()}] {f['title']}: {f['recommendation']}\n"
    
    prompt = f"""As a Senior AWS Security Expert, analyze these IAM security findings for AWS account "{account_alias}":

SUMMARY:
- Critical: {critical_count}
- High: {high_count}  
- Medium: {medium_count}
- Low: {low_count}
- Total Issues: {len(findings)}

TOP FINDINGS:
{findings_text}

Provide a concise security analysis with:
1. Overall risk assessment (1 sentence)
2. Top 3 most critical issues that need immediate attention
3. Quick wins (issues that can be fixed in under 5 minutes)
4. Estimated time to fix all issues

Keep your response under 300 words. Use emojis for visual appeal. Be actionable and specific."""

    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": "You are a Senior AWS Security Expert. Provide concise, actionable security advice. Use emojis. Be specific about risks."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7,
        "max_tokens": 500
    }
    
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            logger.error(f"Groq API error: {response.status_code}")
            return generate_fallback_recommendations(critical_count, high_count, medium_count, low_count)
            
    except Exception as e:
        logger.error(f"Error generating AI recommendations: {e}")
        return generate_fallback_recommendations(critical_count, high_count, medium_count, low_count)


def generate_fallback_recommendations(critical, high, medium, low):
    """Fallback recommendations if AI API fails"""
    recommendations = "🔐 **IAM Security Summary**\n\n"
    
    if critical > 0:
        recommendations += f"🚨 **CRITICAL ({critical})**: Remove root access, enable MFA immediately!\n"
    if high > 0:
        recommendations += f"⚠️ **HIGH ({high})**: Review admin privileges and wildcard permissions\n"
    if medium > 0:
        recommendations += f"📌 **MEDIUM ({medium})**: Rotate old access keys and enable MFA\n"
    if low > 0:
        recommendations += f"✅ **LOW ({low})**: Clean up unused users and keys\n"
    
    recommendations += "\n💡 **Priority**: Fix critical and high severity issues first."
    return recommendations


def scan_iam_security(role_arn, external_id, account_alias=""):
    """Complete IAM security scan with AI recommendations"""
    print("=" * 80)
    print("🔐 STARTING IAM SECURITY SCAN")
    print("=" * 80)
    
    # Assume role and get IAM client
    iam_client = assume_iam_role(role_arn, external_id)
    if not iam_client:
        return {'error': 'Failed to assume IAM role', 'findings': [], 'ai_recommendations': None}
    
    findings = []
    
    # 1. Scan IAM Users
    print("\n📊 Scanning IAM Users...")
    users = get_all_iam_users(iam_client)
    print(f"✅ Found {len(users)} IAM users")
    
    for user in users:
        user_name = user['UserName']
        user_arn = user['Arn']
        print(f"\n  🔍 Checking user: {user_name}")
        
        # Check MFA
        has_mfa = check_mfa_enabled(iam_client, user_name)
        if not has_mfa:
            findings.append({
                'finding_type': 'no_mfa',
                'severity': 'high',
                'resource_name': user_name,
                'title': f'IAM user {user_name} has no MFA enabled',
                'description': f'User {user_name} can authenticate without Multi-Factor Authentication',
                'recommendation': 'Enable MFA for this user immediately. Use virtual MFA (Google Authenticator) or hardware MFA.',
                'metadata': {'user_arn': user_arn}
            })
            print(f"    ❌ No MFA enabled")
        
        # Check Admin Access
        is_admin, policy_name = check_admin_access(iam_client, user_name)
        if is_admin:
            severity = 'critical' if not has_mfa else 'high'
            findings.append({
                'finding_type': 'admin_user',
                'severity': severity,
                'resource_name': user_name,
                'title': f'IAM user {user_name} has administrator access',
                'description': f'User {user_name} has full administrator privileges via {policy_name}',
                'recommendation': 'Remove admin privileges unless absolutely necessary. Use least privilege principle.',
                'metadata': {'policy': policy_name, 'has_mfa': has_mfa}
            })
            print(f"    ⚠️ Admin access detected")
        
        # Check Access Keys
        key_info = check_access_keys(iam_client, user_name)
        if key_info['has_multiple_active']:
            findings.append({
                'finding_type': 'multiple_keys',
                'severity': 'medium',
                'resource_name': user_name,
                'title': f'User {user_name} has {key_info["active_keys"]} active access keys',
                'description': f'Having multiple active access keys increases security risk',
                'recommendation': 'Remove unused access keys. Keep only one active key per user.',
                'metadata': {'active_keys': key_info['active_keys']}
            })
            print(f"    ⚠️ Multiple active keys: {key_info['active_keys']}")
        
        for old_key in key_info['old_keys']:
            findings.append({
                'finding_type': 'old_key',
                'severity': 'medium',
                'resource_name': user_name,
                'title': f'Access key for {user_name} is {old_key["age_days"]} days old',
                'description': f'Access key {old_key["key_id"][:10]}... was created {old_key["age_days"]} days ago',
                'recommendation': 'Rotate access keys every 90 days. Create new key, update applications, then delete old key.',
                'metadata': {'key_id': old_key['key_id'], 'age_days': old_key['age_days']}
            })
            print(f"    ⚠️ Old key: {old_key['age_days']} days")
        
        # Check User Activity (Unused Users)
        activity = check_user_activity(iam_client, user_name)
        if activity['has_never_been_used'] or (activity['days_inactive'] and activity['days_inactive'] > 90):
            days = activity['days_inactive'] if activity['days_inactive'] else 'never'
            findings.append({
                'finding_type': 'unused_user',
                'severity': 'low',
                'resource_name': user_name,
                'title': f'IAM user {user_name} is inactive',
                'description': f'User has not been active for {days} days',
                'recommendation': 'Delete or deactivate unused IAM users to reduce attack surface.',
                'metadata': {'days_inactive': days, 'never_used': activity['has_never_been_used']}
            })
            print(f"    ⚠️ Inactive user: {days} days")
    
    # 2. Scan IAM Roles for Wildcard Permissions
    print("\n📊 Scanning IAM Roles for wildcard permissions...")
    roles = get_all_iam_roles(iam_client)
    print(f"✅ Found {len(roles)} IAM roles")
    
    for role in roles:
        role_name = role['RoleName']
        has_wildcard, policy_name = check_wildcard_role(iam_client, role_name)
        if has_wildcard:
            findings.append({
                'finding_type': 'wildcard_role',
                'severity': 'high',
                'resource_name': role_name,
                'title': f'IAM role {role_name} has wildcard (*) permissions',
                'description': f'Role {role_name} allows full access via {policy_name}',
                'recommendation': 'Scope permissions to specific actions and resources. Avoid using * in IAM policies.',
                'metadata': {'role_arn': role['Arn'], 'policy': policy_name}
            })
            print(f"  ⚠️ Wildcard role: {role_name}")
    
    print("\n" + "=" * 80)
    print(f"✅ IAM SCAN COMPLETE - Found {len(findings)} issues")
    print("=" * 80)
    
    # Generate AI recommendations automatically
    print("\n🤖 Generating AI security recommendations...")
    ai_recommendations = generate_ai_recommendations(findings, account_alias)
    print("✅ AI recommendations generated")
    
    return {
        'success': True,
        'total_findings': len(findings),
        'findings': findings,
        'ai_recommendations': ai_recommendations
    }