# discovery/apigateway_discovery.py
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

def discover_apigateway_services(creds, region):
    """Discover API Gateway REST APIs, HTTP APIs, WebSocket APIs and related resources"""
    services = []
    try:
        # ========== REST APIs ==========
        client = boto3.client(
            'apigateway',
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
        
        rest_apis = client.get_rest_apis()
        for api in rest_apis.get('items', []):
            api_id = api['id']
            api_name = api.get('name', api_id)
            api_version = api.get('version', 'N/A')
            created_date = api.get('createdDate')
            
            # Get API stages
            stages = client.get_stages(restApiId=api_id)
            for stage in stages.get('item', []):
                stage_name = stage['stageName']
                
                # Estimate cost (simplified - assume 1M requests/month)
                # REST API: $3.50 per million requests + $0.09 per GB
                monthly_request_cost = 3.50
                monthly_data_cost = 0.09 * 10  # Assume 10GB data transfer
                total_monthly_cost = monthly_request_cost + monthly_data_cost
                
                services.append({
                    'service_id': 'api_requests',
                    'resource_id': f"{api_id}/{stage_name}",
                    'resource_name': f"{api_name} ({stage_name})",
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                    'details': {
                        'api_id': api_id,
                        'api_name': api_name,
                        'stage_name': stage_name,
                        'created_date': created_date.isoformat() if created_date else None,
                        'api_version': api_version,
                        'description': api.get('description'),
                        'endpoint_configuration': api.get('endpointConfiguration', {}),
                        'api_key_source': api.get('apiKeySource'),
                        'minimum_compression_size': api.get('minimumCompressionSize'),
                        'binary_media_types': api.get('binaryMediaTypes', []),
                        'tags': api.get('tags', {}),
                        'waf_web_acl_arn': api.get('wafWebAclArn'),
                        'disable_execute_api_endpoint': api.get('disableExecuteApiEndpoint', False)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== API CACHING ==========
                if stage.get('cacheClusterEnabled', False):
                    cache_size = stage.get('cacheClusterSize', '0.5')
                    cache_status = stage.get('cacheClusterStatus', 'AVAILABLE')
                    
                    # Cache pricing
                    cache_pricing = {
                        '0.5': 0.020, '1.6': 0.038, '6.1': 0.148,
                        '13.5': 0.298, '28.4': 0.608, '58.2': 1.208, '118': 2.408
                    }
                    hourly_rate = cache_pricing.get(cache_size, 0.020)
                    monthly_cost = hourly_rate * 730
                    
                    services.append({
                        'service_id': f"api_caching_{cache_size.replace('.', '')}gb",
                        'resource_id': f"{api_id}/{stage_name}/cache",
                        'resource_name': f"{api_name} {stage_name} Cache",
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'api_id': api_id,
                            'stage_name': stage_name,
                            'cache_cluster_enabled': True,
                            'cache_cluster_size': cache_size,
                            'cache_cluster_status': cache_status,
                            'cache_cluster_ttl': stage.get('cacheTtlInSeconds', 300),
                            'cache_data_encrypted': stage.get('cacheDataEncrypted', False)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            
            # ========== API GATEWAY RESOURCES ==========
            try:
                resources = client.get_resources(restApiId=api_id, limit=500)
                resource_count = len(resources.get('items', []))
                
                services.append({
                    'service_id': 'api_resources',
                    'resource_id': f"{api_id}/resources",
                    'resource_name': f"{api_name} Resources",
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'api_id': api_id,
                        'resource_count': resource_count,
                        'resources': [
                            {
                                'path': r.get('path'),
                                'path_part': r.get('pathPart'),
                                'resource_methods': list(r.get('resourceMethods', {}).keys())
                            } for r in resources.get('items', [])[:10]  # Limit to 10 for brevity
                        ]
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            except:
                pass
        
        # ========== HTTP APIs ==========
        try:
            http_client = boto3.client(
                'apigatewayv2',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region
            )
            
            http_apis = http_client.get_apis()
            for api in http_apis.get('Items', []):
                api_id = api['ApiId']
                api_name = api.get('Name', api_id)
                protocol_type = api.get('ProtocolType', 'HTTP')
                
                # HTTP API: $1.00 per million requests + $0.09 per GB
                monthly_request_cost = 1.00
                monthly_data_cost = 0.09 * 10  # Assume 10GB data transfer
                total_monthly_cost = monthly_request_cost + monthly_data_cost
                
                service_id = 'http_api_requests' if protocol_type == 'HTTP' else 'websocket_connection'
                
                services.append({
                    'service_id': service_id,
                    'resource_id': api['ApiEndpoint'],
                    'resource_name': api_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                    'details': {
                        'api_id': api_id,
                        'api_name': api_name,
                        'api_endpoint': api.get('ApiEndpoint'),
                        'protocol_type': protocol_type,
                        'api_version': api.get('Version'),
                        'description': api.get('Description'),
                        'created_date': api.get('CreatedDate').isoformat() if api.get('CreatedDate') else None,
                        'cors_configuration': api.get('CorsConfiguration', {}),
                        'tags': api.get('Tags', {}),
                        'disable_execute_api_endpoint': api.get('DisableExecuteApiEndpoint', False)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== WEBSOCKET CONNECTIONS ==========
                if protocol_type == 'WEBSOCKET':
                    # WebSocket connection pricing
                    # $1.00 per million messages, $0.00000139 per connection-minute
                    services.append({
                        'service_id': 'websocket_messages',
                        'resource_id': f"{api_id}/websocket",
                        'resource_name': f"{api_name} WebSocket",
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Usage-based
                        'details': {
                            'api_id': api_id,
                            'api_name': api_name,
                            'route_selection_expression': api.get('RouteSelectionExpression'),
                            'api_key_selection_expression': api.get('ApiKeySelectionExpression'),
                            'auto_deploy': api.get('AutoDeploy', False)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                
                # ========== API STAGES ==========
                stages = http_client.get_stages(ApiId=api_id)
                for stage in stages.get('Items', []):
                    services.append({
                        'service_id': 'api_stage',
                        'resource_id': f"{api_id}/{stage['StageName']}",
                        'resource_name': f"{api_name} - {stage['StageName']}",
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'api_id': api_id,
                            'stage_name': stage['StageName'],
                            'auto_deploy': stage.get('AutoDeploy', False),
                            'deployment_id': stage.get('DeploymentId'),
                            'description': stage.get('Description'),
                            'default_route_settings': stage.get('DefaultRouteSettings', {}),
                            'route_settings': stage.get('RouteSettings', {}),
                            'stage_variables': stage.get('StageVariables', {}),
                            'access_log_settings': stage.get('AccessLogSettings', {}),
                            'created_date': stage.get('CreatedDate').isoformat() if stage.get('CreatedDate') else None,
                            'last_updated_date': stage.get('LastUpdatedDate').isoformat() if stage.get('LastUpdatedDate') else None,
                            'tags': stage.get('Tags', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        except:
            pass
        
        # ========== API GATEWAY USAGE PLANS ==========
        try:
            usage_plans = client.get_usage_plans()
            for plan in usage_plans.get('items', []):
                plan_id = plan['id']
                plan_name = plan.get('name', plan_id)
                
                services.append({
                    'service_id': 'api_gateway_throttling',
                    'resource_id': plan_id,
                    'resource_name': plan_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'usage_plan_id': plan_id,
                        'name': plan_name,
                        'description': plan.get('description'),
                        'api_stages': plan.get('apiStages', []),
                        'throttle': plan.get('throttle', {}),
                        'quota': plan.get('quota', {}),
                        'product_code': plan.get('productCode'),
                        'tags': plan.get('tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== API GATEWAY API KEYS ==========
        try:
            api_keys = client.get_api_keys()
            for key in api_keys.get('items', []):
                services.append({
                    'service_id': 'api_gateway_throttling',
                    'resource_id': key['id'],
                    'resource_name': key.get('name', key['id']),
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'api_key_id': key['id'],
                        'name': key.get('name'),
                        'enabled': key.get('enabled', False),
                        'created_date': key.get('createdDate').isoformat() if key.get('createdDate') else None,
                        'last_updated_date': key.get('lastUpdatedDate').isoformat() if key.get('lastUpdatedDate') else None,
                        'stage_keys': key.get('stageKeys', []),
                        'value': key.get('value')[:10] + '...' if key.get('value') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== API GATEWAY DOMAIN NAMES ==========
        try:
            domain_names = client.get_domain_names()
            for domain in domain_names.get('items', []):
                services.append({
                    'service_id': 'api_gateway_custom_domain',
                    'resource_id': domain['domainName'],
                    'resource_name': domain['domainName'],
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # ACM pricing applies
                    'details': {
                        'domain_name': domain['domainName'],
                        'certificate_name': domain.get('certificateName'),
                        'certificate_arn': domain.get('certificateArn'),
                        'certificate_upload_date': domain.get('certificateUploadDate').isoformat() if domain.get('certificateUploadDate') else None,
                        'regional_domain_name': domain.get('regionalDomainName'),
                        'regional_hosted_zone_id': domain.get('regionalHostedZoneId'),
                        'endpoint_configuration': domain.get('endpointConfiguration', {}),
                        'domain_name_status': domain.get('domainNameStatus'),
                        'domain_name_status_message': domain.get('domainNameStatusMessage'),
                        'security_policy': domain.get('securityPolicy'),
                        'tags': domain.get('tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== API GATEWAY VPC LINKS ==========
        try:
            vpc_links = client.get_vpc_links()
            for link in vpc_links.get('items', []):
                services.append({
                    'service_id': 'api_gateway_vpc_link',
                    'resource_id': link['id'],
                    'resource_name': link.get('name', link['id']),
                    'region': region,
                    'service_type': 'Networking',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # VPC endpoint pricing applies
                    'details': {
                        'vpc_link_id': link['id'],
                        'name': link.get('name'),
                        'description': link.get('description'),
                        'status': link.get('status'),
                        'target_arns': link.get('targetArns', []),
                        'target_arns_count': len(link.get('targetArns', [])),
                        'tags': link.get('tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== API GATEWAY CLIENT CERTIFICATES ==========
        try:
            client_certs = client.get_client_certificates()
            for cert in client_certs.get('items', []):
                services.append({
                    'service_id': 'api_gateway_client_certificate',
                    'resource_id': cert['clientCertificateId'],
                    'resource_name': cert.get('description', cert['clientCertificateId']),
                    'region': region,
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'client_certificate_id': cert['clientCertificateId'],
                        'description': cert.get('description'),
                        'pem_encoded_certificate': cert.get('pemEncodedCertificate')[:50] + '...' if cert.get('pemEncodedCertificate') else None,
                        'created_date': cert.get('createdDate').isoformat() if cert.get('createdDate') else None,
                        'expiration_date': cert.get('expirationDate').isoformat() if cert.get('expirationDate') else None,
                        'tags': cert.get('tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering API Gateway services in {region}: {str(e)}")
    
    return services