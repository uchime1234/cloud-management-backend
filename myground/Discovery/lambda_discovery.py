# discovery/lambda_discovery.py
import boto3
from datetime import datetime

from datetime import timezone
# and then using:
timezone.utc

def discover_lambda_services(creds, region):
    """Discover Lambda functions and related services"""
    services = []
    try:
        client = boto3.client(
            'lambda',
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
        
        # ========== LAMBDA FUNCTIONS ==========
        functions = client.list_functions()
        for function in functions.get('Functions', []):
            function_name = function['FunctionName']
            runtime = function.get('Runtime', 'unknown')
            memory_size = function.get('MemorySize', 128)
            timeout = function.get('Timeout', 3)
            
            # Estimate cost (simplified)
            # Assume 1 million requests per month, 100ms average duration
            # $0.20 per million requests + $0.0000166667 per GB-second
            monthly_requests = 1000000  # Assumption
            avg_duration_seconds = 0.1  # 100ms
            gb_seconds = memory_size / 1024 * avg_duration_seconds * monthly_requests
            
            request_cost = 0.20  # $0.20 per million requests
            compute_cost = gb_seconds * 0.0000166667
            
            # Check if ARM/Graviton (20% cheaper)
            if function.get('Architectures') and 'arm64' in function.get('Architectures', []):
                compute_cost *= 0.8
                request_cost *= 0.8
                service_id = 'lambda_duration_arm'
            else:
                service_id = 'lambda_duration_x86'
            
            total_monthly_cost = request_cost + compute_cost
            
            services.append({
                'service_id': 'lambda_execution',
                'resource_id': function['FunctionArn'],
                'resource_name': function_name,
                'region': region,
                'service_type': 'Compute',
                'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                'details': {
                    'function_name': function_name,
                    'function_arn': function['FunctionArn'],
                    'runtime': runtime,
                    'handler': function.get('Handler'),
                    'memory_size_mb': memory_size,
                    'timeout_seconds': timeout,
                    'description': function.get('Description'),
                    'role': function.get('Role'),
                    'code_size': function.get('CodeSize'),
                    'last_modified': function.get('LastModified'),
                    'version': function.get('Version'),
                    'architectures': function.get('Architectures', ['x86_64']),
                    'package_type': function.get('PackageType', 'Zip'),
                    'tracing_config': function.get('TracingConfig', {}),
                    'tags': function.get('Tags', {}),
                    'environment_variables': function.get('Environment', {}).get('Variables', {}) if function.get('Environment') else {}
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== PROVISIONED CONCURRENCY ==========
            try:
                provisioned = client.get_provisioned_concurrency_config(
                    FunctionName=function_name,
                    Qualifier='$LATEST'
                )
                if provisioned:
                    provisioned_count = provisioned.get('ProvisionedConcurrentExecutions', 0)
                    # Cost: $0.0000041667 per GB-second
                    provisioned_gb_seconds = memory_size / 1024 * provisioned_count * 730 * 3600
                    provisioned_cost = provisioned_gb_seconds * 0.0000041667
                    
                    services.append({
                        'service_id': 'lambda_provisioned_concurrency',
                        'resource_id': f"{function['FunctionArn']}-provisioned",
                        'resource_name': f"{function_name} Provisioned Concurrency",
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': round(provisioned_cost, 2),
                'count': 1,
                        'details': {
                            'function_name': function_name,
                            'provisioned_concurrent_executions': provisioned_count,
                            'status': provisioned.get('Status')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
            
            # ========== FUNCTION URLS ==========
            try:
                function_urls = client.get_function_url_config(FunctionName=function_name)
                if function_urls:
                    services.append({
                        'service_id': 'lambda_function_url',
                        'resource_id': f"{function['FunctionArn']}-url",
                        'resource_name': f"{function_name} URL",
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Billed as requests
                        'details': {
                            'function_name': function_name,
                            'function_url': function_urls.get('FunctionUrl'),
                            'auth_type': function_urls.get('AuthType'),
                            'cors': function_urls.get('Cors', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== LAMBDA LAYERS ==========
        layers = client.list_layers()
        for layer in layers.get('Layers', []):
            layer_name = layer['LayerName']
            layer_arn = layer['LayerArn']
            
            # Get layer versions
            versions = client.list_layer_versions(LayerName=layer_name)
            for version in versions.get('LayerVersions', []):
                version_number = version.get('Version', 1)
                
                services.append({
                    'service_id': 'lambda_layers',
                    'resource_id': f"{layer_arn}:{version_number}",
                    'resource_name': f"{layer_name} (v{version_number})",
                    'region': region,
                    'service_type': 'Compute',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per GB-second when used
                    'details': {
                        'layer_name': layer_name,
                        'layer_arn': layer_arn,
                        'version': version_number,
                        'description': version.get('Description'),
                        'created_date': version.get('CreatedDate'),
                        'compatible_runtimes': version.get('CompatibleRuntimes', []),
                        'compatible_architectures': version.get('CompatibleArchitectures', []),
                        'license_info': version.get('LicenseInfo')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
        # ========== EVENT SOURCE MAPPINGS ==========
        for function in functions.get('Functions', []):
            try:
                event_sources = client.list_event_source_mappings(FunctionName=function['FunctionName'])
                for source in event_sources.get('EventSourceMappings', []):
                    services.append({
                        'service_id': 'lambda_event_source_mapping',
                        'resource_id': source['UUID'],
                        'resource_name': f"{function['FunctionName']} -> {source.get('EventSourceArn', 'unknown')}",
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'uuid': source['UUID'],
                            'function_name': function['FunctionName'],
                            'event_source_arn': source.get('EventSourceArn'),
                            'state': source.get('State'),
                            'state_transition_reason': source.get('StateTransitionReason'),
                            'batch_size': source.get('BatchSize'),
                            'maximum_batching_window_in_seconds': source.get('MaximumBatchingWindowInSeconds'),
                            'starting_position': source.get('StartingPosition'),
                            'enabled': source.get('Enabled', False)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== CODE SIGNING CONFIGS ==========
        try:
            signing_configs = client.list_code_signing_configs()
            for config in signing_configs.get('CodeSigningConfigs', []):
                monthly_cost = 0.05  # $0.05 per signing profile-month
                
                services.append({
                    'service_id': 'lambda_code_signing',
                    'resource_id': config['CodeSigningConfigArn'],
                    'resource_name': config.get('Description', config['CodeSigningConfigId']),
                    'region': region,
                    'service_type': 'Compute',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'code_signing_config_id': config['CodeSigningConfigId'],
                        'code_signing_config_arn': config['CodeSigningConfigArn'],
                        'description': config.get('Description'),
                        'allowed_publishers': config.get('AllowedPublishers', {}),
                        'code_signing_policies': config.get('CodeSigningPolicies', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== ALIASES ==========
        for function in functions.get('Functions', []):
            try:
                aliases = client.list_aliases(FunctionName=function['FunctionName'])
                for alias in aliases.get('Aliases', []):
                    services.append({
                        'service_id': 'lambda_aliases',
                        'resource_id': alias['AliasArn'],
                        'resource_name': alias['Name'],
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'function_name': function['FunctionName'],
                            'alias_name': alias['Name'],
                            'alias_arn': alias['AliasArn'],
                            'function_version': alias.get('FunctionVersion'),
                            'description': alias.get('Description'),
                            'routing_config': alias.get('RoutingConfig', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
    except Exception as e:
        print(f"Error discovering Lambda services in {region}: {str(e)}")
    
    return services