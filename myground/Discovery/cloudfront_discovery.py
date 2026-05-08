# discovery/cloudfront_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

# Add this to the top of each discovery file (vpc_discovery.py, ec2_discovery.py, etc.)
import boto3
import urllib3
from botocore.config import Config

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_boto3_client(service, creds, region):
    """Create boto3 client with SSL verification disabled"""
    return boto3.client(
        service,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region,
        config=Config(
            connect_timeout=30,
            read_timeout=30,
            retries={'max_attempts': 3}
        ),
        verify=False  # Disable SSL verification
    )

def discover_cloudfront_distributions(creds):
    """Discover CloudFront distributions (global service)"""
    services = []
    try:
        client = boto3.client(
            'cloudfront',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region,
              config=Config(
            connect_timeout=30,
            read_timeout=30,
            retries={'max_attempts': 3}
        ),
        verify=False
        )
        
        # ========== CLOUDFRONT DISTRIBUTIONS ==========
        distributions = client.list_distributions()
        if 'DistributionList' in distributions and 'Items' in distributions['DistributionList']:
            for dist in distributions['DistributionList']['Items']:
                dist_id = dist['Id']
                domain_name = dist['DomainName']
                enabled = dist.get('Enabled', False)
                status = dist.get('Status')
                
                # Distribution configuration is free
                services.append({
                    'service_id': 'distribution',
                    'resource_id': dist['ARN'],
                    'resource_name': dist_id,
                    'region': 'global',
                    'service_type': 'Networking',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'distribution_id': dist_id,
                        'arn': dist['ARN'],
                        'domain_name': domain_name,
                        'status': status,
                        'enabled': enabled,
                        'aliases': dist.get('Aliases', {}).get('Items', []),
                        'origins': dist.get('Origins', {}).get('Items', []),
                        'default_cache_behavior': dist.get('DefaultCacheBehavior', {}),
                        'cache_behaviors': dist.get('CacheBehaviors', {}).get('Items', []),
                        'price_class': dist.get('PriceClass'),
                        'web_acl_id': dist.get('WebACLId'),
                        'http_version': dist.get('HttpVersion'),
                        'is_ipv6_enabled': dist.get('IsIPV6Enabled', False),
                        'comment': dist.get('Comment'),
                        'last_modified_time': dist.get('LastModifiedTime').isoformat() if dist.get('LastModifiedTime') else None,
                        'viewer_certificate': dist.get('ViewerCertificate', {}),
                        'restrictions': dist.get('Restrictions', {}),
                        'tags': get_cloudfront_tags(client, dist['ARN'])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== CLOUDFRONT FUNCTIONS ==========
                try:
                    functions = client.list_functions()
                    for function in functions.get('FunctionList', {}).get('Items', []):
                        services.append({
                            'service_id': 'cloudfront_functions',
                            'resource_id': function['FunctionMetadata']['FunctionARN'],
                            'resource_name': function['Name'],
                            'region': 'global',
                            'service_type': 'Compute',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.10 per million invocations
                            'details': {
                                'function_name': function['Name'],
                                'function_arn': function['FunctionMetadata']['FunctionARN'],
                                'status': function['FunctionMetadata'].get('Status'),
                                'stage': function.get('Stage'),
                                'created_time': function['FunctionMetadata'].get('CreatedTime').isoformat() if function['FunctionMetadata'].get('CreatedTime') else None,
                                'last_modified_time': function['FunctionMetadata'].get('LastModifiedTime').isoformat() if function['FunctionMetadata'].get('LastModifiedTime') else None
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
                
                # ========== FIELD-LEVEL ENCRYPTION ==========
                try:
                    fle_configs = client.list_field_level_encryption_configs()
                    for fle in fle_configs.get('FieldLevelEncryptionList', {}).get('Items', []):
                        services.append({
                            'service_id': 'field_level_encryption',
                            'resource_id': fle['Id'],
                            'resource_name': fle.get('Comment', fle['Id']),
                            'region': 'global',
                            'service_type': 'Security',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.0075 per 10,000 requests
                            'details': {
                                'fle_config_id': fle['Id'],
                                'last_modified_time': fle.get('LastModifiedTime').isoformat() if fle.get('LastModifiedTime') else None,
                                'query_arg_profile_config': fle.get('QueryArgProfileConfig', {}),
                                'content_type_profile_config': fle.get('ContentTypeProfileConfig', {})
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
                
                # ========== ORIGIN SHIELD ==========
                if dist.get('OriginShield', {}).get('Enabled', False):
                    services.append({
                        'service_id': 'origin_shield',
                        'resource_id': f"{dist['ARN']}/origin-shield",
                        'resource_name': f"{dist_id} Origin Shield",
                        'region': 'global',
                        'service_type': 'Networking',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.0075 per 10,000 requests
                        'details': {
                            'distribution_id': dist_id,
                            'enabled': True,
                            'origin_shield_region': dist['OriginShield'].get('OriginShieldRegion')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                
                # ========== REAL-TIME LOGS ==========
                try:
                    rt_logs = client.list_realtime_log_configs()
                    for rt_log in rt_logs.get('RealtimeLogConfigs', {}).get('Items', []):
                        services.append({
                            'service_id': 'realtime_logs',
                            'resource_id': rt_log['ARN'],
                            'resource_name': rt_log['Name'],
                            'region': 'global',
                            'service_type': 'Monitoring',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.0075 per GB processed
                            'details': {
                                'name': rt_log['Name'],
                                'arn': rt_log['ARN'],
                                'sampling_rate': rt_log.get('SamplingRate'),
                                'endpoints': rt_log.get('EndPoints', []),
                                'fields': rt_log.get('Fields', [])
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
        
        # ========== LAMBDA@EDGE ==========
        try:
            lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name='us-east-1'  # Lambda@Edge must be in us-east-1
            )
            
            functions = lambda_client.list_functions()
            for function in functions.get('Functions', []):
                # Check if this is a Lambda@Edge function
                tags = lambda_client.list_tags(Resource=function['FunctionArn'])
                is_edge = False
                
                for key, value in tags.get('Tags', {}).items():
                    if key.lower() == 'lambda-edge' or key.lower() == 'lambdaedge':
                        is_edge = True
                        break
                
                if is_edge or 'edge' in function.get('Description', '').lower():
                    memory_size = function.get('MemorySize', 128)
                    
                    # Estimate cost (assume 1 million requests, 50ms duration)
                    monthly_requests = 1000000
                    avg_duration_seconds = 0.05
                    gb_seconds = memory_size / 1024 * avg_duration_seconds * monthly_requests
                    
                    request_cost = 0.60  # $0.60 per million requests
                    compute_cost = gb_seconds * 0.00005001
                    monthly_cost = request_cost + compute_cost
                    
                    services.append({
                        'service_id': 'lambda_at_edge',
                        'resource_id': function['FunctionArn'],
                        'resource_name': function['FunctionName'],
                        'region': 'global',
                        'service_type': 'Compute',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'function_name': function['FunctionName'],
                            'function_arn': function['FunctionArn'],
                            'runtime': function.get('Runtime'),
                            'handler': function.get('Handler'),
                            'memory_size_mb': memory_size,
                            'timeout_seconds': function.get('Timeout', 1),
                            'description': function.get('Description'),
                            'last_modified': function.get('LastModified'),
                            'version': function.get('Version'),
                            'tags': tags.get('Tags', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        except:
            pass
        
        # ========== CLOUDFRONT KEY GROUPS ==========
        try:
            key_groups = client.list_key_groups()
            for key_group in key_groups.get('KeyGroupList', {}).get('Items', []):
                services.append({
                    'service_id': 'key_group',
                    'resource_id': key_group['KeyGroup']['Id'],
                    'resource_name': key_group['KeyGroup'].get('Name'),
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'key_group_id': key_group['KeyGroup']['Id'],
                        'name': key_group['KeyGroup'].get('Name'),
                        'items': key_group['KeyGroup'].get('Items', []),
                        'last_modified_time': key_group.get('LastModifiedTime').isoformat() if key_group.get('LastModifiedTime') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDFRONT PUBLIC KEYS ==========
        try:
            public_keys = client.list_public_keys()
            for public_key in public_keys.get('PublicKeyList', {}).get('Items', []):
                services.append({
                    'service_id': 'public_key',
                    'resource_id': public_key['Id'],
                    'resource_name': public_key.get('Name'),
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'public_key_id': public_key['Id'],
                        'name': public_key.get('Name'),
                        'created_time': public_key.get('CreatedTime').isoformat() if public_key.get('CreatedTime') else None,
                        'encoded_key': public_key.get('EncodedKey')[:50] + '...' if public_key.get('EncodedKey') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDFRONT ORIGIN ACCESS CONTROLS ==========
        try:
            oacs = client.list_origin_access_controls()
            for oac in oacs.get('OriginAccessControlList', {}).get('Items', []):
                services.append({
                    'service_id': 'origin_access_control',
                    'resource_id': oac['Id'],
                    'resource_name': oac.get('Name'),
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'oac_id': oac['Id'],
                        'name': oac.get('Name'),
                        'description': oac.get('Description'),
                        'signing_protocol': oac.get('SigningProtocol'),
                        'signing_behavior': oac.get('SigningBehavior'),
                        'origin_access_control_origin_type': oac.get('OriginAccessControlOriginType')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDFRONT MONITORING SUBSCRIPTIONS ==========
        try:
            for dist in distributions.get('DistributionList', {}).get('Items', []):
                try:
                    monitoring = client.get_monitoring_subscription(DistributionId=dist['Id'])
                    subscription = monitoring.get('MonitoringSubscription', {})
                    if subscription:
                        services.append({
                            'service_id': 'cloudfront_monitoring',
                            'resource_id': f"{dist['ARN']}/monitoring",
                            'resource_name': f"{dist['Id']} Monitoring",
                            'region': 'global',
                            'service_type': 'Monitoring',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # CloudWatch metrics pricing applies
                            'details': {
                                'distribution_id': dist['Id'],
                                'monitoring_subscription': subscription
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering CloudFront distributions: {str(e)}")
    
    return services

def get_cloudfront_tags(client, resource_arn):
    """Get tags for CloudFront resource"""
    try:
        response = client.list_tags_for_resource(Resource=resource_arn)
        return response.get('Tags', {}).get('Items', [])
    except:
        return []