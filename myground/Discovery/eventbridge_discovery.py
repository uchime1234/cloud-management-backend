# discovery/eventbridge_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_eventbridge_services(creds, region):
    """Discover EventBridge buses, rules, schemas, and pipes"""
    services = []
    try:
        client = boto3.client(
            'events',
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
        
        # ========== EVENT BUSES ==========
        buses = client.list_event_buses()
        for bus in buses.get('EventBuses', []):
            bus_name = bus['Name']
            bus_arn = bus['Arn']
            
            # Default event bus is free, custom buses cost $1 per million events
            is_default = bus_name == 'default'
            monthly_cost = 0.00 if is_default else 1.00  # Assume 1M events
            
            services.append({
                'service_id': 'eventbridge_custom_event',
                'resource_id': bus_arn,
                'resource_name': bus_name,
                'region': region,
                'service_type': 'Application Integration',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'event_bus_name': bus_name,
                    'event_bus_arn': bus_arn,
                    'policy': bus.get('Policy'),
                    'creation_time': bus.get('CreationTime').isoformat() if bus.get('CreationTime') else None,
                    'tags': get_eventbridge_bus_tags(client, bus_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== EVENT RULES ==========
            rules = client.list_rules(EventBusName=bus_name)
            for rule in rules.get('Rules', []):
                rule_name = rule['Name']
                rule_arn = rule['Arn']
                schedule = rule.get('ScheduleExpression')
                event_pattern = rule.get('EventPattern')
                state = rule.get('State', 'ENABLED')
                
                services.append({
                    'service_id': 'eventbridge_rule',
                    'resource_id': rule_arn,
                    'resource_name': rule_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Free, pay for invocations
                    'details': {
                        'rule_name': rule_name,
                        'rule_arn': rule_arn,
                        'event_bus_name': bus_name,
                        'description': rule.get('Description'),
                        'state': state,
                        'schedule_expression': schedule,
                        'event_pattern': parse_json(event_pattern),
                        'role_arn': rule.get('RoleArn'),
                        'managed_by': rule.get('ManagedBy'),
                        'created_by': rule.get('CreatedBy'),
                        'targets': get_eventbridge_targets(client, rule_name, bus_name),
                        'tags': get_eventbridge_rule_tags(client, rule_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
        # ========== EVENTBRIDGE SCHEMAS ==========
        try:
            schemas_client = boto3.client(
                'schemas',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region
            )
            
            registries = schemas_client.list_registries()
            for registry in registries.get('Registries', []):
                registry_name = registry['RegistryName']
                registry_arn = registry['RegistryArn']
                
                # $0.40 per registry per month
                monthly_cost = 0.40
                
                services.append({
                    'service_id': 'eventbridge_schema_registry',
                    'resource_id': registry_arn,
                    'resource_name': registry_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'registry_name': registry_name,
                        'registry_arn': registry_arn,
                        'description': registry.get('Description'),
                        'tags': registry.get('Tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== SCHEMAS ==========
                schemas_list = schemas_client.list_schemas(RegistryName=registry_name)
                for schema in schemas_list.get('Schemas', []):
                    schema_name = schema['SchemaName']
                    schema_arn = schema['SchemaArn']
                    
                    services.append({
                        'service_id': 'eventbridge_schema',
                        'resource_id': schema_arn,
                        'resource_name': schema_name,
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Pay for schema discovery
                        'details': {
                            'schema_name': schema_name,
                            'schema_arn': schema_arn,
                            'registry_name': registry_name,
                            'type': schema.get('Type'),
                            'version_count': schema.get('VersionCount'),
                            'description': schema.get('Description'),
                            'last_modified': schema.get('LastModified').isoformat() if schema.get('LastModified') else None,
                            'tags': schema.get('Tags', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        except:
            pass
        
        # ========== EVENTBRIDGE API DESTINATIONS ==========
        try:
            connections = client.list_connections()
            for connection in connections.get('Connections', []):
                connection_name = connection['Name']
                connection_arn = connection['ConnectionArn']
                
                # $0.10 per connection per month
                monthly_cost = 0.10
                
                services.append({
                    'service_id': 'eventbridge_connection',
                    'resource_id': connection_arn,
                    'resource_name': connection_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'connection_name': connection_name,
                        'connection_arn': connection_arn,
                        'connection_state': connection.get('ConnectionState'),
                        'authorization_type': connection.get('AuthorizationType'),
                        'creation_time': connection.get('CreationTime').isoformat() if connection.get('CreationTime') else None,
                        'last_modified_time': connection.get('LastModifiedTime').isoformat() if connection.get('LastModifiedTime') else None,
                        'tags': connection.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            
            destinations = client.list_api_destinations()
            for dest in destinations.get('ApiDestinations', []):
                dest_name = dest['Name']
                dest_arn = dest['ApiDestinationArn']
                
                # $0.001 per invocation
                monthly_cost = 1.00  # Assume 1000 invocations
                
                services.append({
                    'service_id': 'eventbridge_api_destination',
                    'resource_id': dest_arn,
                    'resource_name': dest_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'api_destination_name': dest_name,
                        'api_destination_arn': dest_arn,
                        'api_destination_state': dest.get('ApiDestinationState'),
                        'connection_arn': dest.get('ConnectionArn'),
                        'invocation_endpoint': dest.get('InvocationEndpoint'),
                        'http_method': dest.get('HttpMethod'),
                        'invocation_rate_limit_per_second': dest.get('InvocationRateLimitPerSecond'),
                        'creation_time': dest.get('CreationTime').isoformat() if dest.get('CreationTime') else None,
                        'last_modified_time': dest.get('LastModifiedTime').isoformat() if dest.get('LastModifiedTime') else None,
                        'tags': dest.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== EVENTBRIDGE ARCHIVES ==========
        for bus in buses.get('EventBuses', []):
            try:
                archives = client.list_archives(EventSourceArn=bus['Arn'])
                for archive in archives.get('Archives', []):
                    archive_name = archive['ArchiveName']
                    archive_arn = archive['ArchiveArn']
                    
                    # $0.02 per GB-month for archived events
                    estimated_size_gb = 1.0  # Assume 1GB
                    monthly_cost = estimated_size_gb * 0.02
                    
                    services.append({
                        'service_id': 'eventbridge_archive',
                        'resource_id': archive_arn,
                        'resource_name': archive_name,
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'archive_name': archive_name,
                            'archive_arn': archive_arn,
                            'event_bus_arn': bus['Arn'],
                            'description': archive.get('Description'),
                            'event_pattern': archive.get('EventPattern'),
                            'state': archive.get('State'),
                            'retention_days': archive.get('RetentionDays'),
                            'size_bytes': archive.get('SizeBytes'),
                            'event_count': archive.get('EventCount'),
                            'creation_time': archive.get('CreationTime').isoformat() if archive.get('CreationTime') else None,
                            'tags': archive.get('Tags', [])
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== EVENTBRIDGE PIPES ==========
        try:
            pipes_client = boto3.client(
                'pipes',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region
            )
            
            pipes = pipes_client.list_pipes()
            for pipe in pipes.get('Pipes', []):
                pipe_name = pipe['Name']
                pipe_arn = pipe['Arn']
                
                # $0.40 per GB processed, assume 10GB
                monthly_cost = 4.00
                
                services.append({
                    'service_id': 'eventbridge_pipe',
                    'resource_id': pipe_arn,
                    'resource_name': pipe_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'pipe_name': pipe_name,
                        'pipe_arn': pipe_arn,
                        'state': pipe.get('State'),
                        'source': pipe.get('Source'),
                        'target': pipe.get('Target'),
                        'enrichment': pipe.get('Enrichment'),
                        'creation_time': pipe.get('CreationTime').isoformat() if pipe.get('CreationTime') else None,
                        'last_modified_time': pipe.get('LastModifiedTime').isoformat() if pipe.get('LastModifiedTime') else None,
                        'tags': pipe.get('Tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering EventBridge services in {region}: {str(e)}")
    
    return services

def get_eventbridge_bus_tags(client, bus_arn):
    """Get tags for EventBridge bus"""
    try:
        response = client.list_tags_for_resource(ResourceARN=bus_arn)
        return response.get('Tags', [])
    except:
        return []

def get_eventbridge_rule_tags(client, rule_arn):
    """Get tags for EventBridge rule"""
    try:
        response = client.list_tags_for_resource(ResourceARN=rule_arn)
        return response.get('Tags', [])
    except:
        return []

def get_eventbridge_targets(client, rule_name, bus_name=None):
    """Get targets for EventBridge rule"""
    try:
        params = {'Rule': rule_name}
        if bus_name:
            params['EventBusName'] = bus_name
        response = client.list_targets_by_rule(**params)
        return [
            {
                'id': t.get('Id'),
                'arn': t.get('Arn'),
                'input': t.get('Input'),
                'input_path': t.get('InputPath'),
                'role_arn': t.get('RoleArn'),
                'dead_letter_config': t.get('DeadLetterConfig'),
                'retry_policy': t.get('RetryPolicy')
            }
            for t in response.get('Targets', [])
        ]
    except:
        return []