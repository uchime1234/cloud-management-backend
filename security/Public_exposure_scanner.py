# Add to security/iam_scanner.py

import boto3
from datetime import datetime, timedelta
from django.conf import settings
import logging
import requests

logger = logging.getLogger(__name__)

# ============================================================
# PUBLIC EXPOSURE SCANNER
# ============================================================

def assume_iam_role(role_arn, external_id):
    """Assume IAM role and return clients"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SecurityScanner",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        return credentials
    except Exception as e:
        logger.error(f"Failed to assume role: {e}")
        return None


def get_ec2_public_instances(ec2_client, region):
    """Get EC2 instances with public IPs"""
    public_instances = []
    try:
        instances = ec2_client.describe_instances()
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance.get('InstanceId')
                instance_name = next(
                    (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'),
                    instance_id
                )
                public_ip = instance.get('PublicIpAddress')
                elastic_ip = None
                
                # Check if using Elastic IP
                for association in instance.get('NetworkInterfaces', []):
                    for assoc in association.get('Association', {}):
                        if assoc.get('PublicIp'):
                            elastic_ip = assoc.get('PublicIp')
                            break
                
                if public_ip or elastic_ip:
                    # Get security groups
                    security_groups = []
                    open_ports = []
                    for sg in instance.get('SecurityGroups', []):
                        sg_id = sg['GroupId']
                        sg_name = sg.get('GroupName', sg_id)
                        security_groups.append({
                            'id': sg_id,
                            'name': sg_name
                        })
                        # Get SG rules (separate call)
                        try:
                            sg_rules = ec2_client.describe_security_groups(GroupIds=[sg_id])
                            for rule in sg_rules.get('SecurityGroups', []):
                                for ip_perm in rule.get('IpPermissions', []):
                                    for ip_range in ip_perm.get('IpRanges', []):
                                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                                            port = ip_perm.get('ToPort', 'All')
                                            open_ports.append({
                                                'port': port,
                                                'protocol': ip_perm.get('IpProtocol', 'tcp'),
                                                'description': ip_range.get('Description', '')
                                            })
                        except:
                            pass
                    
                    # Determine risk level
                    risk_level = 'MEDIUM'
                    critical_ports = [22, 3389, 3306, 5432, 6379, 27017, 9200, 9300]
                    for port_info in open_ports:
                        if port_info['port'] in critical_ports:
                            risk_level = 'CRITICAL'
                            break
                    if not open_ports:
                        risk_level = 'LOW'
                    
                    public_instances.append({
                        'instance_id': instance_id,
                        'instance_name': instance_name,
                        'instance_type': instance.get('InstanceType'),
                        'public_ip': public_ip or elastic_ip,
                        'elastic_ip': elastic_ip,
                        'region': region,
                        'state': instance.get('State', {}).get('Name'),
                        'security_groups': security_groups,
                        'open_ports': open_ports,
                        'risk_level': risk_level,
                        'finding_type': 'public_ec2'
                    })
    except Exception as e:
        logger.error(f"Error scanning EC2 in {region}: {e}")
    return public_instances


def check_open_security_group_rules(ec2_client):
    """Check for open security group rules (0.0.0.0/0)"""
    open_rules = []
    try:
        security_groups = ec2_client.describe_security_groups()
        for sg in security_groups.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', sg_id)
            vpc_id = sg.get('VpcId', 'default')
            
            for ip_perm in sg.get('IpPermissions', []):
                from_port = ip_perm.get('FromPort')
                to_port = ip_perm.get('ToPort')
                protocol = ip_perm.get('IpProtocol', 'tcp')
                
                # Check IPv4 ranges
                for ip_range in ip_perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_display = f"{from_port}-{to_port}" if from_port != to_port else str(to_port) if to_port else 'All'
                        
                        # Determine severity
                        severity = 'MEDIUM'
                        critical_ports = [22, 3389, 3306, 5432, 6379, 27017, 9200, 9300]
                        if to_port in critical_ports or (from_port and from_port in critical_ports):
                            severity = 'CRITICAL'
                        
                        open_rules.append({
                            'security_group_id': sg_id,
                            'security_group_name': sg_name,
                            'vpc_id': vpc_id,
                            'protocol': protocol,
                            'port': port_display,
                            'from_port': from_port,
                            'to_port': to_port,
                            'cidr': '0.0.0.0/0',
                            'description': ip_range.get('Description', 'No description'),
                            'severity': severity,
                            'finding_type': 'open_sg_rule'
                        })
                
                # Check IPv6 ranges
                for ipv6_range in ip_perm.get('Ipv6Ranges', []):
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        port_display = f"{from_port}-{to_port}" if from_port != to_port else str(to_port) if to_port else 'All'
                        
                        severity = 'MEDIUM'
                        critical_ports = [22, 3389, 3306, 5432, 6379, 27017, 9200, 9300]
                        if to_port in critical_ports or (from_port and from_port in critical_ports):
                            severity = 'CRITICAL'
                        
                        open_rules.append({
                            'security_group_id': sg_id,
                            'security_group_name': sg_name,
                            'vpc_id': vpc_id,
                            'protocol': protocol,
                            'port': port_display,
                            'from_port': from_port,
                            'to_port': to_port,
                            'cidr': '::/0',
                            'description': ipv6_range.get('Description', 'No description'),
                            'severity': severity,
                            'finding_type': 'open_sg_rule'
                        })
    except Exception as e:
        logger.error(f"Error scanning security groups: {e}")
    return open_rules


def check_public_rds_instances(rds_client, region):
    """Check for publicly accessible RDS instances"""
    public_rds = []
    try:
        instances = rds_client.describe_db_instances()
        for instance in instances.get('DBInstances', []):
            publicly_accessible = instance.get('PubliclyAccessible', False)
            if publicly_accessible:
                instance_id = instance.get('DBInstanceIdentifier')
                port = instance.get('DbInstancePort', 3306)
                engine = instance.get('Engine', 'mysql')
                
                public_rds.append({
                    'instance_id': instance_id,
                    'engine': engine,
                    'port': port,
                    'publicly_accessible': True,
                    'region': region,
                    'status': instance.get('DBInstanceStatus'),
                    'security_groups': instance.get('VpcSecurityGroups', []),
                    'finding_type': 'public_rds',
                    'severity': 'CRITICAL'
                })
    except Exception as e:
        logger.error(f"Error scanning RDS in {region}: {e}")
    return public_rds


def check_public_s3_buckets(s3_client):
    """Check for public S3 buckets"""
    public_buckets = []
    try:
        buckets = s3_client.list_buckets()
        for bucket in buckets.get('Buckets', []):
            bucket_name = bucket['Name']
            is_public = False
            public_details = []
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        is_public = True
                        public_details.append(f"ACL: {grant.get('Permission')} access to Everyone")
            except:
                pass
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                import json
                policy_doc = json.loads(policy.get('Policy', '{}'))
                for statement in policy_doc.get('Statement', []):
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        effect = statement.get('Effect', '')
                        if effect == 'Allow':
                            is_public = True
                            public_details.append(f"Policy: {effect} access to *")
            except:
                pass
            
            # Check block public access
            try:
                block_public = s3_client.get_public_access_block(Bucket=bucket_name)
                block_config = block_public.get('PublicAccessBlockConfiguration', {})
                if block_config.get('BlockPublicAcls') and block_config.get('BlockPublicPolicy'):
                    is_public = False  # Blocked by configuration
            except:
                pass
            
            if is_public:
                public_buckets.append({
                    'bucket_name': bucket_name,
                    'creation_date': bucket.get('CreationDate'),
                    'public_details': public_details,
                    'finding_type': 'public_s3',
                    'severity': 'CRITICAL',
                    'has_backups': 'backup' in bucket_name.lower(),
                    'has_logs': 'log' in bucket_name.lower()
                })
    except Exception as e:
        logger.error(f"Error scanning S3: {e}")
    return public_buckets


def check_public_load_balancers(elbv2_client, region):
    """Check for internet-facing load balancers"""
    public_lbs = []
    try:
        lbs = elbv2_client.describe_load_balancers()
        for lb in lbs.get('LoadBalancers', []):
            scheme = lb.get('Scheme', 'internal')
            if scheme == 'internet-facing':
                lb_name = lb.get('LoadBalancerName')
                lb_type = lb.get('Type', 'application')
                dns_name = lb.get('DNSName')
                
                # Check if WAF is attached
                waf_attached = False
                try:
                    wafv2 = boto3.client('wafv2')
                    # Check for WAF association (simplified)
                    web_acls = wafv2.list_web_acls(Scope='REGIONAL')
                    for acl in web_acls.get('WebACLs', []):
                        if lb_name in acl.get('Name', ''):
                            waf_attached = True
                            break
                except:
                    pass
                
                public_lbs.append({
                    'lb_name': lb_name,
                    'lb_type': lb_type,
                    'dns_name': dns_name,
                    'scheme': scheme,
                    'region': region,
                    'state': lb.get('State', {}).get('Code'),
                    'waf_attached': waf_attached,
                    'finding_type': 'public_lb',
                    'severity': 'MEDIUM' if waf_attached else 'HIGH'
                })
    except Exception as e:
        logger.error(f"Error scanning load balancers in {region}: {e}")
    return public_lbs


def check_public_eks_clusters(eks_client, region):
    """Check for publicly accessible EKS clusters"""
    public_clusters = []
    try:
        clusters = eks_client.list_clusters()
        for cluster_name in clusters.get('clusters', []):
            cluster = eks_client.describe_cluster(name=cluster_name)
            cluster_info = cluster.get('cluster', {})
            endpoint = cluster_info.get('endpoint', '')
            endpoint_public_access = cluster_info.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False)
            
            if endpoint_public_access:
                public_clusters.append({
                    'cluster_name': cluster_name,
                    'endpoint': endpoint,
                    'endpoint_public_access': True,
                    'region': region,
                    'status': cluster_info.get('status'),
                    'finding_type': 'public_eks',
                    'severity': 'CRITICAL'
                })
    except Exception as e:
        logger.error(f"Error scanning EKS in {region}: {e}")
    return public_clusters


def check_public_redis_elasticache(elasticache_client, region):
    """Check for publicly accessible Redis/Memcached clusters"""
    public_clusters = []
    try:
        # Check Redis clusters
        redis_clusters = elasticache_client.describe_cache_clusters()
        for cluster in redis_clusters.get('CacheClusters', []):
            cluster_id = cluster.get('CacheClusterId')
            engine = cluster.get('Engine', 'redis')
            is_public = False
            
            # Check if cluster has public endpoint
            endpoint = cluster.get('ConfigurationEndpoint', cluster.get('CacheNodes', [{}])[0].get('Endpoint'))
            if endpoint and endpoint.get('Address'):
                # Check security groups for public access
                security_groups = cluster.get('SecurityGroups', [])
                for sg in security_groups:
                    sg_id = sg.get('SecurityGroupId')
                    if sg_id:
                        # Check if SG allows 0.0.0.0/0 (simplified)
                        is_public = True
                        break
                
                if is_public:
                    public_clusters.append({
                        'cluster_id': cluster_id,
                        'engine': engine,
                        'endpoint': endpoint.get('Address'),
                        'port': endpoint.get('Port', 6379),
                        'region': region,
                        'status': cluster.get('CacheClusterStatus'),
                        'finding_type': 'public_redis',
                        'severity': 'HIGH'
                    })
    except Exception as e:
        logger.error(f"Error scanning ElastiCache in {region}: {e}")
    return public_clusters


def check_public_opensearch(opensearch_client, region):
    """Check for publicly accessible OpenSearch/Elasticsearch domains"""
    public_domains = []
    try:
        domains = opensearch_client.list_domain_names()
        for domain in domains.get('DomainNames', []):
            domain_name = domain.get('DomainName')
            domain_info = opensearch_client.describe_domain(DomainName=domain_name)
            domain_config = domain_info.get('DomainStatus', {})
            
            endpoint = domain_config.get('Endpoint')
            endpoints = domain_config.get('Endpoints', {})
            public_access = False
            
            # Check if domain is publicly accessible
            access_policies = domain_config.get('AccessPolicies', '{}')
            import json
            try:
                policies = json.loads(access_policies)
                for statement in policies.get('Statement', []):
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        if statement.get('Effect') == 'Allow':
                            public_access = True
                            break
            except:
                pass
            
            if public_access and endpoint:
                public_domains.append({
                    'domain_name': domain_name,
                    'endpoint': endpoint,
                    'engine_version': domain_config.get('EngineVersion'),
                    'region': region,
                    'finding_type': 'public_opensearch',
                    'severity': 'CRITICAL'
                })
    except Exception as e:
        logger.error(f"Error scanning OpenSearch in {region}: {e}")
    return public_domains


def check_public_api_gateways(apigw_client, apigwv2_client, region):
    """Check for public API Gateways without authentication"""
    public_apis = []
    try:
        # Check REST APIs
        rest_apis = apigw_client.get_rest_apis()
        for api in rest_apis.get('items', []):
            api_id = api.get('id')
            api_name = api.get('name', api_id)
            api_key_required = api.get('apiKeySource', '') == 'AUTHORIZER'
            
            # Check if API has authorizer
            has_authorizer = False
            try:
                authorizers = apigw_client.get_authorizers(restApiId=api_id)
                if authorizers.get('items'):
                    has_authorizer = True
            except:
                pass
            
            if not api_key_required and not has_authorizer:
                public_apis.append({
                    'api_id': api_id,
                    'api_name': api_name,
                    'api_type': 'REST',
                    'endpoint': f"https://{api_id}.execute-api.{region}.amazonaws.com",
                    'has_authentication': False,
                    'has_authorizer': has_authorizer,
                    'api_key_required': api_key_required,
                    'region': region,
                    'finding_type': 'public_api',
                    'severity': 'HIGH'
                })
        
        # Check HTTP APIs
        http_apis = apigwv2_client.get_apis()
        for api in http_apis.get('Items', []):
            api_id = api.get('ApiId')
            api_name = api.get('Name', api_id)
            api_type = api.get('ProtocolType', 'HTTP')
            
            # Check for authorizers
            has_authorizer = False
            try:
                authorizers = apigwv2_client.get_authorizers(ApiId=api_id)
                if authorizers.get('Items'):
                    has_authorizer = True
            except:
                pass
            
            if not has_authorizer:
                public_apis.append({
                    'api_id': api_id,
                    'api_name': api_name,
                    'api_type': api_type,
                    'endpoint': f"https://{api_id}.execute-api.{region}.amazonaws.com",
                    'has_authentication': False,
                    'has_authorizer': has_authorizer,
                    'region': region,
                    'finding_type': 'public_api',
                    'severity': 'HIGH'
                })
    except Exception as e:
        logger.error(f"Error scanning API Gateway in {region}: {e}")
    return public_apis


def check_missing_waf(public_lbs, public_apis):
    """Check for public resources without WAF protection"""
    missing_waf = []
    for lb in public_lbs:
        if not lb.get('waf_attached', False):
            missing_waf.append({
                'resource_type': 'Load Balancer',
                'resource_name': lb['lb_name'],
                'finding_type': 'missing_waf',
                'severity': 'HIGH',
                'recommendation': 'Attach AWS WAF to protect against common web exploits'
            })
    return missing_waf


def scan_public_exposures(role_arn, external_id, region='us-east-1'):
    """
    Complete public exposure security scan
    """
    print("=" * 80)
    print("🌐 STARTING PUBLIC EXPOSURE SECURITY SCAN")
    print("=" * 80)
    
    # Assume role and get credentials
    credentials = assume_iam_role(role_arn, external_id)
    if not credentials:
        return {'error': 'Failed to assume IAM role', 'findings': []}
    
    # Create clients
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    rds_client = boto3.client(
        'rds',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    elbv2_client = boto3.client(
        'elbv2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    eks_client = boto3.client(
        'eks',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    elasticache_client = boto3.client(
        'elasticache',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    opensearch_client = boto3.client(
        'es',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    apigw_client = boto3.client(
        'apigateway',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    apigwv2_client = boto3.client(
        'apigatewayv2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    findings = []
    
    # 1. Public EC2 Instances
    print("\n📊 Scanning EC2 public instances...")
    ec2_findings = get_ec2_public_instances(ec2_client, region)
    findings.extend(ec2_findings)
    print(f"   Found {len(ec2_findings)} public EC2 instances")
    
    # 2. Open Security Group Rules
    print("\n📊 Scanning open security group rules...")
    sg_findings = check_open_security_group_rules(ec2_client)
    findings.extend(sg_findings)
    print(f"   Found {len(sg_findings)} open security group rules")
    
    # 3. Public RDS Instances
    print("\n📊 Scanning public RDS instances...")
    rds_findings = check_public_rds_instances(rds_client, region)
    findings.extend(rds_findings)
    print(f"   Found {len(rds_findings)} public RDS instances")
    
    # 4. Public S3 Buckets
    print("\n📊 Scanning public S3 buckets...")
    s3_findings = check_public_s3_buckets(s3_client)
    findings.extend(s3_findings)
    print(f"   Found {len(s3_findings)} public S3 buckets")
    
    # 5. Public Load Balancers
    print("\n📊 Scanning public load balancers...")
    lb_findings = check_public_load_balancers(elbv2_client, region)
    findings.extend(lb_findings)
    print(f"   Found {len(lb_findings)} public load balancers")
    
    # 6. Public EKS Clusters
    print("\n📊 Scanning public EKS clusters...")
    eks_findings = check_public_eks_clusters(eks_client, region)
    findings.extend(eks_findings)
    print(f"   Found {len(eks_findings)} public EKS clusters")
    
    # 7. Public Redis/ElastiCache
    print("\n📊 Scanning public Redis clusters...")
    redis_findings = check_public_redis_elasticache(elasticache_client, region)
    findings.extend(redis_findings)
    print(f"   Found {len(redis_findings)} public Redis clusters")
    
    # 8. Public OpenSearch
    print("\n📊 Scanning public OpenSearch domains...")
    opensearch_findings = check_public_opensearch(opensearch_client, region)
    findings.extend(opensearch_findings)
    print(f"   Found {len(opensearch_findings)} public OpenSearch domains")
    
    # 9. Public API Gateways
    print("\n📊 Scanning public API Gateways...")
    api_findings = check_public_api_gateways(apigw_client, apigwv2_client, region)
    findings.extend(api_findings)
    print(f"   Found {len(api_findings)} public API Gateways")
    
    # 10. Missing WAF
    print("\n📊 Checking missing WAF protections...")
    waf_findings = check_missing_waf(lb_findings, api_findings)
    findings.extend(waf_findings)
    print(f"   Found {len(waf_findings)} resources missing WAF")
    
    print("\n" + "=" * 80)
    print(f"✅ PUBLIC EXPOSURE SCAN COMPLETE - Found {len(findings)} issues")
    print("=" * 80)
    
    return {
        'success': True,
        'total_findings': len(findings),
        'findings': findings
    }


def generate_public_exposure_ai_analysis(findings, account_alias):
    """
    Generate AI-powered risk analysis for public exposures
    """
    if not findings:
        return "✅ No public exposure issues found. Your AWS resources are not publicly exposed! 🎉"
    
    # Categorize findings by severity
    critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
    high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
    medium_count = len([f for f in findings if f.get('severity') == 'MEDIUM'])
    low_count = len([f for f in findings if f.get('severity') == 'LOW'])
    
    # Build findings summary with context
    findings_summary = []
    for f in findings[:20]:
        finding_type = f.get('finding_type', 'unknown')
        resource = f.get('instance_name') or f.get('bucket_name') or f.get('lb_name') or f.get('resource_name') or f.get('security_group_name') or f.get('api_name') or 'Unknown'
        
        if finding_type == 'public_ec2':
            risk_context = f"SSH/RDP access from anywhere" if any(p.get('port') in [22, 3389] for p in f.get('open_ports', [])) else "Public IP exposed"
            findings_summary.append(f"• [{f.get('severity')}] EC2 '{resource}' has public IP {f.get('public_ip')}. {risk_context}.")
        
        elif finding_type == 'open_sg_rule':
            findings_summary.append(f"• [{f.get('severity')}] Security Group '{resource}' allows {f.get('protocol')}:{f.get('port')} from 0.0.0.0/0.")
        
        elif finding_type == 'public_rds':
            findings_summary.append(f"• [CRITICAL] RDS '{resource}' is publicly accessible on port {f.get('port')}.")
        
        elif finding_type == 'public_s3':
            findings_summary.append(f"• [CRITICAL] S3 bucket '{resource}' has public access: {', '.join(f.get('public_details', ['Unknown']))}.")
        
        elif finding_type == 'public_lb':
            findings_summary.append(f"• [{f.get('severity')}] Load Balancer '{resource}' is internet-facing. WAF: {'Yes' if f.get('waf_attached') else 'No'}.")
        
        elif finding_type == 'public_eks':
            findings_summary.append(f"• [CRITICAL] EKS cluster '{resource}' has public API endpoint exposed.")
        
        elif finding_type == 'public_redis':
            findings_summary.append(f"• [HIGH] Redis cluster '{resource}' is publicly accessible on port {f.get('port')}.")
        
        elif finding_type == 'public_opensearch':
            findings_summary.append(f"• [CRITICAL] OpenSearch domain '{resource}' has public access.")
        
        elif finding_type == 'public_api':
            findings_summary.append(f"• [HIGH] API Gateway '{resource}' has no authentication/authorizer configured.")
        
        elif finding_type == 'missing_waf':
            findings_summary.append(f"• [HIGH] '{resource}' has no WAF protection.")
    
    findings_text = "\n".join(findings_summary[:15])
    
    prompt = f"""As a Senior AWS Security Expert, analyze these PUBLIC EXPOSURE security findings for AWS account "{account_alias}":

## SUMMARY:
- CRITICAL: {critical_count}
- HIGH: {high_count}
- MEDIUM: {medium_count}
- LOW: {low_count}
- Total Exposures: {len(findings)}

## DETAILED FINDINGS:
{findings_text}

## RISK ANALYSIS REQUIRED:
Provide a comprehensive security analysis in the following format:

### 🔴 CRITICAL RISKS (Immediate Action Required)
[List 3-5 most dangerous exposures with EXPLANATION of WHY each is dangerous]

### 🟡 HIGH RISKS (Fix Soon)
[List 3-5 high-risk exposures with potential attack vectors]

### 🟢 MEDIUM/LOW RISKS (Best Practices)
[List other exposures and improvement suggestions]

## ACTIONABLE SOLUTIONS:
For EACH risk category above, provide:
1. **Immediate mitigation steps** (can be done in <5 minutes)
2. **Long-term fixes** (architecture improvements)
3. **AWS services that can help** (WAF, Security Groups, etc.)

## RISK EXPLANATION FORMAT:
Instead of just saying "Port 22 open", explain:
> "This server allows SSH access from anywhere on the internet, increasing brute-force attack risk. Attackers can continuously try passwords and potentially gain unauthorized access."

Do this for each major finding type.

Keep response under 800 words but be thorough. Use emojis for visual clarity."""

    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": "You are a Senior AWS Security Expert. Provide detailed, actionable security analysis. ALWAYS explain WHY a finding is dangerous, not just WHAT it is. Use the exact format requested."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7,
        "max_tokens": 1200
    }
    
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=45
        )
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            logger.error(f"Groq API error: {response.status_code}")
            return generate_public_exposure_fallback(critical_count, high_count, medium_count, low_count)
    except Exception as e:
        logger.error(f"Error generating AI analysis: {e}")
        return generate_public_exposure_fallback(critical_count, high_count, medium_count, low_count)


def generate_public_exposure_fallback(critical, high, medium, low):
    """Fallback recommendations if AI API fails"""
    recommendations = """🔐 **PUBLIC EXPOSURE RISK ANALYSIS**

## 🔴 CRITICAL RISKS (Fix IMMEDIATELY)

**What:**
- Public RDS databases
- Public S3 buckets
- OpenSSH/RDP from anywhere
- Public EKS API endpoints
- Public OpenSearch/Elasticsearch

**Why these are dangerous:**
Attackers scan AWS IP ranges 24/7 looking for these exact exposures. A publicly accessible database can be breached in minutes, leading to data theft, ransomware, or cryptomining.

**Immediate fixes:**
1. Remove `0.0.0.0/0` from security groups immediately
2. Enable `Block Public Access` on all S3 buckets
3. Set RDS `PubliclyAccessible = false`
4. Use AWS WAF and Auth0/Cognito for APIs

## 🟡 HIGH RISKS

**What:**
- Internet-facing Load Balancers without WAF
- Public APIs without authentication
- Public Redis clusters

**Why:**
These are prime targets for DDoS, credential stuffing, and data scraping attacks.

**Fix:**
- Attach AWS WAF to all public ALBs
- Add API keys, JWT, or Cognito authorizers
- Move Redis to private subnets with VPN access

## 🟢 Best Practices

- Use VPC endpoints instead of public endpoints
- Implement least-privilege security groups
- Enable AWS Config and GuardDuty
- Regular security scans (weekly)

**Estimated Fix Time:**
- Critical: 5-30 minutes
- High: 1-2 hours
- All issues: 1-2 days"""
    
    return recommendations