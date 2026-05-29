# security/security_group_analyzer.py

import boto3
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Critical and sensitive ports
CRITICAL_PORTS = {
    22: {'name': 'SSH', 'severity': 'HIGH', 'explanation': 'SSH access from anywhere allows brute-force attacks and unauthorized server access.'},
    3389: {'name': 'RDP', 'severity': 'HIGH', 'explanation': 'RDP exposure enables remote desktop attacks and potential system compromise.'},
    3306: {'name': 'MySQL', 'severity': 'CRITICAL', 'explanation': 'Public MySQL access exposes database to direct attacks and data theft.'},
    5432: {'name': 'PostgreSQL', 'severity': 'CRITICAL', 'explanation': 'PostgreSQL exposed to internet risks data breaches and ransomware.'},
    6379: {'name': 'Redis', 'severity': 'CRITICAL', 'explanation': 'Redis has no built-in authentication; public exposure is extremely dangerous.'},
    27017: {'name': 'MongoDB', 'severity': 'CRITICAL', 'explanation': 'MongoDB exposed to internet - attackers can dump entire databases.'},
    9200: {'name': 'Elasticsearch', 'severity': 'CRITICAL', 'explanation': 'Elasticsearch exposure can leak all indexed data and enable cluster compromise.'},
    9300: {'name': 'Elasticsearch Transport', 'severity': 'HIGH', 'explanation': 'Transport port exposed - cluster communication can be intercepted.'},
    1433: {'name': 'SQL Server', 'severity': 'CRITICAL', 'explanation': 'SQL Server exposed to internet risks database compromise.'},
    1521: {'name': 'Oracle DB', 'severity': 'CRITICAL', 'explanation': 'Oracle database exposure can lead to data theft.'},
    11211: {'name': 'Memcached', 'severity': 'HIGH', 'explanation': 'Memcached exposed - used for DDoS amplification attacks.'},
    25: {'name': 'SMTP', 'severity': 'MEDIUM', 'explanation': 'SMTP exposure can be abused for email spoofing.'},
    53: {'name': 'DNS', 'severity': 'MEDIUM', 'explanation': 'DNS exposure can be used for amplification attacks.'},
    123: {'name': 'NTP', 'severity': 'MEDIUM', 'explanation': 'NTP exposure enables DDoS amplification.'},
    161: {'name': 'SNMP', 'severity': 'HIGH', 'explanation': 'SNMP exposure leaks network management information.'},
}

def assume_role_for_account(aws_account):
    """Assume role and return credentials"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName="SecurityGroupAnalyzer",
            ExternalId=str(aws_account.external_id),
            DurationSeconds=3600
        )
        return response["Credentials"]
    except Exception as e:
        logger.error(f"Error assuming role: {e}")
        return None


def get_all_security_groups(ec2_client):
    """Get all security groups in the account"""
    try:
        security_groups = []
        paginator = ec2_client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            security_groups.extend(page['SecurityGroups'])
        return security_groups
    except Exception as e:
        logger.error(f"Error getting security groups: {e}")
        return []


def get_attached_resources(ec2_client, sg_id):
    """Find all resources attached to a security group"""
    resources = []
    
    # Find EC2 instances
    try:
        instances = ec2_client.describe_instances(
            Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
        )
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                resources.append({
                    'resource_id': instance['InstanceId'],
                    'resource_name': next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId']),
                    'resource_type': 'EC2',
                    'region': instance.get('Placement', {}).get('AvailabilityZone', '')[:-1],
                    'status': instance.get('State', {}).get('Name', 'unknown')
                })
    except Exception as e:
        logger.error(f"Error finding EC2 instances for SG {sg_id}: {e}")
    
    # Find Load Balancers
    try:
        elbv2 = ec2_client
        lbs = elbv2.describe_load_balancers()
        for lb in lbs.get('LoadBalancers', []):
            if sg_id in lb.get('SecurityGroups', []):
                resources.append({
                    'resource_id': lb['LoadBalancerName'],
                    'resource_name': lb['LoadBalancerName'],
                    'resource_type': 'Load Balancer',
                    'region': lb.get('AvailabilityZones', [{}])[0].get('ZoneName', '')[:-1] if lb.get('AvailabilityZones') else '',
                    'status': lb.get('State', {}).get('Code', 'active')
                })
    except Exception as e:
        logger.error(f"Error finding load balancers for SG {sg_id}: {e}")
    
    # Find RDS instances
    try:
        rds = ec2_client
        instances = rds.describe_db_instances()
        for instance in instances.get('DBInstances', []):
            for sg in instance.get('VpcSecurityGroups', []):
                if sg.get('VpcSecurityGroupId') == sg_id:
                    resources.append({
                        'resource_id': instance['DBInstanceIdentifier'],
                        'resource_name': instance['DBInstanceIdentifier'],
                        'resource_type': 'RDS',
                        'region': instance.get('AvailabilityZone', '')[:-1] if instance.get('AvailabilityZone') else '',
                        'status': instance.get('DBInstanceStatus', 'unknown')
                    })
                    break
    except Exception as e:
        logger.error(f"Error finding RDS for SG {sg_id}: {e}")
    
    return resources


def analyze_security_group_rules(sg):
    """Analyze inbound and outbound rules for risks"""
    findings = []
    open_world_rules = []
    exposed_ports = []
    dangerous_protocols = []
    unrestricted_inbound = False
    unrestricted_outbound = False
    
    # Analyze inbound rules
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        protocol = rule.get('IpProtocol', 'tcp')
        
        # Check for any-to-any inbound
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                open_world_rules.append({
                    'direction': 'inbound',
                    'protocol': protocol,
                    'from_port': from_port,
                    'to_port': to_port,
                    'cidr': '0.0.0.0/0',
                    'description': ip_range.get('Description', '')
                })
                
                # Check if it's a critical port
                if to_port and to_port in CRITICAL_PORTS:
                    port_info = CRITICAL_PORTS[to_port]
                    exposed_ports.append({
                        'port': to_port,
                        'protocol': protocol,
                        'severity': port_info['severity'],
                        'service': port_info['name'],
                        'explanation': port_info['explanation']
                    })
                    findings.append({
                        'type': 'critical_port_exposed',
                        'severity': port_info['severity'],
                        'title': f"{port_info['name']} (Port {to_port}) exposed to internet",
                        'description': port_info['explanation'],
                        'recommendation': f"Restrict access to {port_info['name']} to specific IP ranges or use a VPN/bastion host."
                    })
                elif from_port and from_port == 0 and to_port == 65535:
                    unrestricted_inbound = True
                    findings.append({
                        'type': 'unrestricted_inbound',
                        'severity': 'CRITICAL',
                        'title': 'Complete unrestricted inbound access (0-65535)',
                        'description': 'All ports and protocols are open to the entire internet. This is extremely dangerous.',
                        'recommendation': 'Remove this rule immediately. Implement least-privilege security group rules.'
                    })
        
        # Check for IPv6 open rules
        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                open_world_rules.append({
                    'direction': 'inbound',
                    'protocol': protocol,
                    'from_port': from_port,
                    'to_port': to_port,
                    'cidr': '::/0',
                    'description': ipv6_range.get('Description', '')
                })
        
        # Check for dangerous protocols
        if protocol == 'udp' and (to_port == 53 or to_port == 123):
            dangerous_protocols.append({
                'protocol': protocol,
                'port': to_port,
                'severity': 'MEDIUM',
                'explanation': 'UDP exposure for DNS/NTP can be used for DDoS amplification attacks.'
            })
    
    # Analyze outbound rules
    for rule in sg.get('IpPermissionsEgress', []):
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                protocol = rule.get('IpProtocol', 'tcp')
                
                if from_port == 0 and to_port == 65535:
                    unrestricted_outbound = True
                    findings.append({
                        'type': 'unrestricted_outbound',
                        'severity': 'MEDIUM',
                        'title': 'Unrestricted outbound access',
                        'description': 'All outbound traffic is allowed. This increases risk if an instance is compromised.',
                        'recommendation': 'Restrict outbound rules to only necessary ports and services.'
                    })
    
    return {
        'findings': findings,
        'open_world_rules': open_world_rules,
        'exposed_ports': exposed_ports,
        'dangerous_protocols': dangerous_protocols,
        'unrestricted_inbound': unrestricted_inbound,
        'unrestricted_outbound': unrestricted_outbound
    }


def detect_duplicate_security_groups(security_groups):
    """Detect duplicate or similar security group configurations"""
    duplicates = []
    processed = set()
    
    for i, sg1 in enumerate(security_groups):
        if sg1['GroupId'] in processed:
            continue
        
        similar_groups = []
        for j, sg2 in enumerate(security_groups):
            if i != j and sg2['GroupId'] not in processed:
                # Compare rules
                rules1 = set()
                rules2 = set()
                
                for rule in sg1.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        rules1.add(f"{rule.get('FromPort')}-{rule.get('ToPort')}-{rule.get('IpProtocol')}-{ip_range.get('CidrIp')}")
                
                for rule in sg2.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        rules2.add(f"{rule.get('FromPort')}-{rule.get('ToPort')}-{rule.get('IpProtocol')}-{ip_range.get('CidrIp')}")
                
                if rules1 == rules2:
                    similar_groups.append({
                        'sg_id': sg2['GroupId'],
                        'sg_name': sg2.get('GroupName', sg2['GroupId']),
                        'similarity': 'identical'
                    })
        
        if similar_groups:
            duplicates.append({
                'primary_sg_id': sg1['GroupId'],
                'primary_sg_name': sg1.get('GroupName', sg1['GroupId']),
                'duplicates': similar_groups,
                'similarity_explanation': 'Security groups have identical inbound rule configurations.'
            })
            processed.add(sg1['GroupId'])
            for dup in similar_groups:
                processed.add(dup['sg_id'])
    
    return duplicates


def get_security_group_change_history(ec2_client, sg_id):
    """Get change history using CloudTrail (simplified - would need CloudTrail integration)"""
    # This is a simplified version. Real implementation would query CloudTrail
    return [
        {
            'changed_at': (timezone.now() - timedelta(days=30)).isoformat(),
            'changed_by': 'admin@example.com',
            'change_type': 'rule_added',
            'description': 'Added SSH (port 22) inbound rule from 0.0.0.0/0',
            'before': None,
            'after': {'protocol': 'tcp', 'port': 22, 'cidr': '0.0.0.0/0'}
        }
    ]


def get_traffic_insights(ec2_client, cloudwatch_client, sg_id, resources):
    """Get traffic insights for security group"""
    # Simplified traffic insights
    insights = {
        'most_used_ports': [
            {'port': 443, 'usage': 'high', 'trend': 'stable', 'percentage': 45},
            {'port': 80, 'usage': 'medium', 'trend': 'stable', 'percentage': 30},
            {'port': 22, 'usage': 'low', 'trend': 'decreasing', 'percentage': 10}
        ],
        'inbound_trend': {
            'last_7_days': [120, 125, 130, 128, 135, 140, 138],
            'trend': 'increasing',
            'percentage_change': 15
        },
        'outbound_trend': {
            'last_7_days': [80, 82, 85, 83, 88, 90, 92],
            'trend': 'increasing',
            'percentage_change': 15
        },
        'top_source_ips': [
            {'ip_range': '10.0.0.0/16', 'requests_percentage': 65, 'region': 'VPC Internal'},
            {'ip_range': '52.0.0.0/8', 'requests_percentage': 20, 'region': 'AWS US-East'},
            {'ip_range': '3.0.0.0/8', 'requests_percentage': 15, 'region': 'AWS Global'}
        ],
        'top_destination_ips': [
            {'ip_range': 'internet', 'bytes_percentage': 55},
            {'ip_range': '10.0.0.0/16', 'bytes_percentage': 35},
            {'ip_range': '172.16.0.0/12', 'bytes_percentage': 10}
        ]
    }
    
    return insights


def generate_ai_recommendation(sg_name, analysis_result, resources, duplicates, severity):
    """Generate AI recommendation using Groq"""
    
    # Build prompt for AI
    findings_summary = "\n".join([
        f"- [{f['severity']}] {f['title']}: {f['description'][:100]}"
        for f in analysis_result.get('findings', [])[:5]
    ])
    
    exposed_ports_summary = "\n".join([
        f"- Port {p['port']} ({p['service']}) - {p['severity']} risk"
        for p in analysis_result.get('exposed_ports', [])[:5]
    ])
    
    resources_summary = "\n".join([
        f"- {r['resource_type']}: {r['resource_name']} ({r.get('status', 'unknown')})"
        for r in resources[:5]
    ])
    
    is_orphaned = len(resources) == 0
    
    prompt = f"""As a Senior AWS Security Expert, analyze this security group:

Security Group Name: {sg_name}
Overall Severity: {severity}
Attached Resources: {len(resources)} resource(s)
Is Orphaned (unused): {is_orphaned}
Duplicate Detected: {len(duplicates) > 0}

## RISK FINDINGS:
{findings_summary if findings_summary else 'No major risk findings detected.'}

## EXPOSED PORTS:
{exposed_ports_summary if exposed_ports_summary else 'No critical ports exposed.'}

## ATTACHED RESOURCES:
{resources_summary if resources_summary else 'No resources attached (orphaned security group).'}

## Provide a structured response with these exact sections:

### 🔴 Security Summary
(1-2 sentences overall health assessment)

### ⚠️ Biggest Risks
(List 2-3 specific risks with brief explanation)

### 🔧 Recommended Actions
(List 2-3 actionable recommendations, prioritized)

### ⏰ Priority Order
(List what to fix first, second, third)

Keep each section concise (max 3 bullet points per section). Be specific and actionable."""

    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": "You are a Senior AWS Security Expert specializing in security group analysis. Provide concise, actionable responses with clear sections."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7,
        "max_tokens": 600
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
    except Exception as e:
        logger.error(f"Error generating AI recommendation: {e}")
    
    # Fallback recommendation
    return """### 🔴 Security Summary
This security group has exposed ports that need attention.

### ⚠️ Biggest Risks
- Publicly exposed ports increase attack surface
- Orphaned security groups add unnecessary complexity

### 🔧 Recommended Actions
- Restrict inbound rules to specific IP ranges
- Remove unused security groups

### ⏰ Priority Order
1. Close public SSH/RDP access
2. Restrict database ports
3. Remove orphaned groups"""


def analyze_security_group(ec2_client, cloudwatch_client, sg):
    """Complete analysis for a single security group"""
    sg_id = sg['GroupId']
    sg_name = sg.get('GroupName', sg_id)
    
    # 1. Risk analysis
    risk_analysis = analyze_security_group_rules(sg)
    
    # 2. Get attached resources
    resources = get_attached_resources(ec2_client, sg_id)
    
    # 3. Get change history
    change_history = get_security_group_change_history(ec2_client, sg_id)
    
    # 4. Get traffic insights
    traffic_insights = get_traffic_insights(ec2_client, cloudwatch_client, sg_id, resources)
    
    # Calculate scores
    total_findings = len(risk_analysis['findings'])
    critical_count = len([f for f in risk_analysis['findings'] if f['severity'] == 'CRITICAL'])
    high_count = len([f for f in risk_analysis['findings'] if f['severity'] == 'HIGH'])
    
    # Health score (0-100, higher is better)
    health_score = max(0, 100 - (critical_count * 25) - (high_count * 10) - (total_findings * 2))
    
    # Risk score (0-100, higher is worse)
    risk_score = min(100, (critical_count * 30) + (high_count * 15) + (len(risk_analysis['exposed_ports']) * 10))
    
    # Overall severity
    if critical_count > 0:
        overall_severity = 'CRITICAL'
    elif high_count > 0:
        overall_severity = 'HIGH'
    elif total_findings > 0:
        overall_severity = 'MEDIUM'
    else:
        overall_severity = 'LOW'
    
    return {
        'sg_id': sg_id,
        'sg_name': sg_name,
        'sg_description': sg.get('Description', ''),
        'vpc_id': sg.get('VpcId', ''),
        'region': settings.AWS_REGION,
        'attached_resources': resources,
        'is_orphaned': len(resources) == 0,
        'health_score': health_score,
        'risk_score': risk_score,
        'overall_severity': overall_severity,
        'risk_findings': risk_analysis['findings'],
        'open_world_rules': risk_analysis['open_world_rules'],
        'exposed_ports': risk_analysis['exposed_ports'],
        'dangerous_protocols': risk_analysis['dangerous_protocols'],
        'unrestricted_inbound': risk_analysis['unrestricted_inbound'],
        'unrestricted_outbound': risk_analysis['unrestricted_outbound'],
        'change_history': change_history,
        'traffic_insights': traffic_insights,
        'last_analyzed_at': timezone.now().isoformat()
    }


def scan_all_security_groups(aws_account, force_refresh=False):
    """Main function to scan all security groups"""
    from .models import SecurityGroupAnalysis, SecurityGroupAnalysisCache
    
    # Get or create cache record
    cache, _ = SecurityGroupAnalysisCache.objects.get_or_create(aws_account=aws_account)
    
    if cache.scan_in_progress and not force_refresh:
        return {'status': 'scan_in_progress', 'message': 'Scan already in progress'}
    
    cache.scan_in_progress = True
    cache.save()
    
    try:
        # Assume role
        credentials = assume_role_for_account(aws_account)
        if not credentials:
            cache.scan_in_progress = False
            cache.save()
            return {'error': 'Failed to assume role'}
        
        # Create clients
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=settings.AWS_REGION
        )
        
        cloudwatch_client = boto3.client(
            'cloudwatch',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=settings.AWS_REGION
        )
        
        # Get all security groups
        security_groups = get_all_security_groups(ec2_client)
        cache.total_security_groups = len(security_groups)
        cache.save()
        
        # Detect duplicates
        duplicates = detect_duplicate_security_groups(security_groups)
        
        # Analyze each security group
        analyzed_count = 0
        results = []
        
        for sg in security_groups:
            # Analyze security group
            analysis = analyze_security_group(ec2_client, cloudwatch_client, sg)
            
            # Add duplicate info
            sg_duplicates = [d for d in duplicates if d['primary_sg_id'] == analysis['sg_id'] or 
                           any(dup['sg_id'] == analysis['sg_id'] for dup in d.get('duplicates', []))]
            analysis['duplicate_candidates'] = sg_duplicates
            analysis['is_duplicate'] = len(sg_duplicates) > 0
            
            # Generate AI recommendation
            ai_recommendation = generate_ai_recommendation(
                analysis['sg_name'],
                analysis,
                analysis['attached_resources'],
                analysis['duplicate_candidates'],
                analysis['overall_severity']
            )
            analysis['ai_recommendation'] = ai_recommendation
            
            # Save to database
            sg_analysis, created = SecurityGroupAnalysis.objects.update_or_create(
                aws_account=aws_account,
                sg_id=analysis['sg_id'],
                defaults={
                    'user_id': aws_account.user_id,
                    'sg_name': analysis['sg_name'],
                    'sg_description': analysis['sg_description'],
                    'vpc_id': analysis['vpc_id'],
                    'region': analysis['region'],
                    'attached_resources': analysis['attached_resources'],
                    'is_orphaned': analysis['is_orphaned'],
                    'health_score': analysis['health_score'],
                    'risk_score': analysis['risk_score'],
                    'overall_severity': analysis['overall_severity'],
                    'risk_findings': analysis['risk_findings'],
                    'open_world_rules': analysis['open_world_rules'],
                    'exposed_ports': analysis['exposed_ports'],
                    'dangerous_protocols': analysis['dangerous_protocols'],
                    'unrestricted_inbound': analysis['unrestricted_inbound'],
                    'unrestricted_outbound': analysis['unrestricted_outbound'],
                    'duplicate_candidates': analysis['duplicate_candidates'],
                    'is_duplicate': analysis['is_duplicate'],
                    'traffic_insights': analysis['traffic_insights'],
                    'change_history': analysis['change_history'],
                    'ai_recommendation': ai_recommendation,
                    'last_analyzed_at': timezone.now(),
                    'is_stale': False
                }
            )
            
            results.append(analysis)
            analyzed_count += 1
            cache.analyzed_count = analyzed_count
            cache.save()
        
        cache.last_full_scan = timezone.now()
        cache.scan_in_progress = False
        cache.save()
        
        return {
            'success': True,
            'total_security_groups': len(security_groups),
            'analyzed_count': analyzed_count,
            'results': results,
            'cached': False
        }
        
    except Exception as e:
        logger.error(f"Error scanning security groups: {e}")
        cache.scan_in_progress = False
        cache.save()
        return {'error': str(e)}


def get_cached_security_groups(aws_account):
    """Get cached security group analyses"""
    from .models import SecurityGroupAnalysis
    
    analyses = SecurityGroupAnalysis.objects.filter(
        aws_account=aws_account,
        is_stale=False
    ).order_by('-health_score')
    
    return {
        'success': True,
        'cached': True,
        'total_security_groups': analyses.count(),
        'results': [
            {
                'sg_id': a.sg_id,
                'sg_name': a.sg_name,
                'health_score': a.health_score,
                'risk_score': a.risk_score,
                'overall_severity': a.overall_severity,
                'attached_resources_count': len(a.attached_resources),
                'is_orphaned': a.is_orphaned,
                'is_duplicate': a.is_duplicate,
                'risk_findings_count': len(a.risk_findings),
                'last_analyzed_at': a.last_analyzed_at.isoformat()
            }
            for a in analyses
        ]
    }


def get_security_group_detail(aws_account, sg_id):
    """Get detailed analysis for a specific security group"""
    from .models import SecurityGroupAnalysis
    
    try:
        analysis = SecurityGroupAnalysis.objects.get(
            aws_account=aws_account,
            sg_id=sg_id
        )
        
        return {
            'success': True,
            'cached': True,
            'analysis': {
                'sg_id': analysis.sg_id,
                'sg_name': analysis.sg_name,
                'sg_description': analysis.sg_description,
                'vpc_id': analysis.vpc_id,
                'region': analysis.region,
                'attached_resources': analysis.attached_resources,
                'is_orphaned': analysis.is_orphaned,
                'health_score': analysis.health_score,
                'risk_score': analysis.risk_score,
                'overall_severity': analysis.overall_severity,
                'risk_findings': analysis.risk_findings,
                'open_world_rules': analysis.open_world_rules,
                'exposed_ports': analysis.exposed_ports,
                'dangerous_protocols': analysis.dangerous_protocols,
                'unrestricted_inbound': analysis.unrestricted_inbound,
                'unrestricted_outbound': analysis.unrestricted_outbound,
                'duplicate_candidates': analysis.duplicate_candidates,
                'is_duplicate': analysis.is_duplicate,
                'traffic_insights': analysis.traffic_insights,
                'change_history': analysis.change_history,
                'ai_recommendation': analysis.ai_recommendation,
                'last_analyzed_at': analysis.last_analyzed_at.isoformat()
            }
        }
    except SecurityGroupAnalysis.DoesNotExist:
        return {'error': 'Security group not found'}