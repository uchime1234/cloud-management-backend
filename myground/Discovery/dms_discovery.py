# discovery/dms_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_dms_services(creds, region):
    """Discover Database Migration Service resources: replication instances, tasks, endpoints"""
    services = []
    try:
        client = boto3.client(
            'dms',
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
        
        # ========== DMS REPLICATION INSTANCES ==========
        replication_instances = client.describe_replication_instances()
        for instance in replication_instances.get('ReplicationInstances', []):
            instance_id = instance['ReplicationInstanceIdentifier']
            instance_arn = instance['ReplicationInstanceArn']
            instance_class = instance.get('ReplicationInstanceClass', 'dms.t3.micro')
            instance_status = instance.get('ReplicationInstanceStatus', 'active')
            allocated_storage = instance.get('AllocatedStorage', 100)
            engine_version = instance.get('EngineVersion', '3.4.7')
            vpc_security_group_ids = instance.get('VpcSecurityGroups', [])
            availability_zone = instance.get('AvailabilityZone')
            multi_az = instance.get('MultiAZ', False)
            publicly_accessible = instance.get('PubliclyAccessible', False)
            auto_minor_version_upgrade = instance.get('AutoMinorVersionUpgrade', True)
            preferred_maintenance_window = instance.get('PreferredMaintenanceWindow')
            instance_create_time = instance.get('InstanceCreateTime')
            
            # DMS replication instance pricing
            # Based on instance class (approximate hourly rates)
            instance_pricing = {
                'dms.t3.micro': 0.041,
                'dms.t3.small': 0.082,
                'dms.t3.medium': 0.165,
                'dms.c5.large': 0.096,
                'dms.c5.xlarge': 0.192,
                'dms.c5.2xlarge': 0.384,
                'dms.c5.4xlarge': 0.768,
                'dms.r5.large': 0.152,
                'dms.r5.xlarge': 0.304,
                'dms.r5.2xlarge': 0.608,
                'dms.r5.4xlarge': 1.216
            }
            
            # Get base hourly rate
            hourly_rate = 0.115  # Default small instance rate
            for key in instance_pricing:
                if key in instance_class:
                    hourly_rate = instance_pricing[key]
                    break
            
            # Multi-AZ doubles the cost
            if multi_az:
                hourly_rate *= 2
            
            # Storage cost: $0.115 per GB-month for gp2
            monthly_storage_cost = (allocated_storage * 0.115)
            
            # Instance cost
            monthly_instance_cost = hourly_rate * 730
            
            total_monthly_cost = monthly_instance_cost + monthly_storage_cost
            
            # Determine service ID based on instance size
            if 't3.micro' in instance_class:
                service_id = 'dms_replication_instance_small'
            elif 't3.small' in instance_class:
                service_id = 'dms_replication_instance_small'
            elif 't3.medium' in instance_class:
                service_id = 'dms_replication_instance_medium'
            elif 'c5.large' in instance_class:
                service_id = 'dms_replication_instance_medium'
            elif 'c5.xlarge' in instance_class:
                service_id = 'dms_replication_instance_large'
            elif 'c5.2xlarge' in instance_class:
                service_id = 'dms_replication_instance_large'
            elif 'c5.4xlarge' in instance_class:
                service_id = 'dms_replication_instance_xlarge'
            else:
                service_id = 'dms_replication_instance_large'
            
            services.append({
                'service_id': service_id,
                'resource_id': instance_arn,
                'resource_name': instance_id,
                'region': region,
                'service_type': 'Migration & Transfer',
                'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                'details': {
                    'replication_instance_arn': instance_arn,
                    'replication_instance_identifier': instance_id,
                    'replication_instance_class': instance_class,
                    'instance_status': instance_status,
                    'allocated_storage_gb': allocated_storage,
                    'engine_version': engine_version,
                    'vpc_security_group_ids': [sg['VpcSecurityGroupId'] for sg in vpc_security_group_ids],
                    'vpc_security_group_count': len(vpc_security_group_ids),
                    'availability_zone': availability_zone,
                    'multi_az': multi_az,
                    'publicly_accessible': publicly_accessible,
                    'auto_minor_version_upgrade': auto_minor_version_upgrade,
                    'preferred_maintenance_window': preferred_maintenance_window,
                    'instance_create_time': instance_create_time.isoformat() if instance_create_time else None,
                    'kms_key_id': instance.get('KmsKeyId'),
                    'replication_subnet_group': instance.get('ReplicationSubnetGroup', {}),
                    'tags': get_dms_resource_tags(client, instance_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== DMS REPLICATION TASKS ==========
        replication_tasks = client.describe_replication_tasks()
        for task in replication_tasks.get('ReplicationTasks', []):
            task_id = task['ReplicationTaskIdentifier']
            task_arn = task['ReplicationTaskArn']
            task_status = task.get('Status', 'stopped')
            migration_type = task.get('MigrationType', 'full-load')
            source_endpoint_arn = task.get('SourceEndpointArn')
            target_endpoint_arn = task.get('TargetEndpointArn')
            replication_instance_arn = task.get('ReplicationInstanceArn')
            table_mappings = parse_json(task.get('TableMappings', '{}'))
            replication_task_settings = parse_json(task.get('ReplicationTaskSettings', '{}'))
            task_start_date = task.get('ReplicationTaskStartDate')
            task_creation_date = task.get('ReplicationTaskCreationDate')
            
            # Get task statistics
            try:
                stats = client.describe_replication_task_statistics(
                    ReplicationTaskArn=task_arn
                )
                task_stats = stats.get('ReplicationTaskStatistics', {})
            except:
                task_stats = {}
            
            services.append({
                'service_id': 'dms_replication_task',
                'resource_id': task_arn,
                'resource_name': task_id,
                'region': region,
                'service_type': 'Migration & Transfer',
                'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost included in replication instance
                'details': {
                    'replication_task_arn': task_arn,
                    'replication_task_identifier': task_id,
                    'source_endpoint_arn': source_endpoint_arn,
                    'target_endpoint_arn': target_endpoint_arn,
                    'replication_instance_arn': replication_instance_arn,
                    'migration_type': migration_type,
                    'table_mappings': table_mappings,
                    'replication_task_settings': replication_task_settings,
                    'status': task_status,
                    'last_failure_message': task.get('LastFailureMessage'),
                    'stop_reason': task.get('StopReason'),
                    'replication_task_start_date': task_start_date.isoformat() if task_start_date else None,
                    'replication_task_creation_date': task_creation_date.isoformat() if task_creation_date else None,
                    'replication_task_stats': {
                        'full_load_progress_percent': task_stats.get('FullLoadProgressPercent', 0),
                        'tables_loaded': task_stats.get('TablesLoaded', 0),
                        'tables_loading': task_stats.get('TablesLoading', 0),
                        'tables_queued': task_stats.get('TablesQueued', 0),
                        'tables_errored': task_stats.get('TablesErrored', 0)
                    },
                    'tags': get_dms_resource_tags(client, task_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== DMS ENDPOINTS ==========
        endpoints = client.describe_endpoints()
        for endpoint in endpoints.get('Endpoints', []):
            endpoint_id = endpoint['EndpointIdentifier']
            endpoint_arn = endpoint['EndpointArn']
            endpoint_type = endpoint.get('EndpointType', 'source')
            engine_name = endpoint.get('EngineName', 'mysql')
            endpoint_status = endpoint.get('EndpointStatus', 'active')
            port = endpoint.get('Port', 3306)
            server_name = endpoint.get('ServerName', '')
            database_name = endpoint.get('DatabaseName', '')
            ssl_mode = endpoint.get('SslMode', 'none')
            
            services.append({
                'service_id': 'dms_endpoint',
                'resource_id': endpoint_arn,
                'resource_name': endpoint_id,
                'region': region,
                'service_type': 'Migration & Transfer',
                'estimated_monthly_cost': 0.00,
                'count': 1,  # No separate cost
                'details': {
                    'endpoint_arn': endpoint_arn,
                    'endpoint_identifier': endpoint_id,
                    'endpoint_type': endpoint_type,
                    'engine_name': engine_name,
                    'endpoint_status': endpoint_status,
                    'port': port,
                    'server_name': server_name,
                    'database_name': database_name,
                    'ssl_mode': ssl_mode,
                    'certificate_arn': endpoint.get('CertificateArn'),
                    'ssl_mode': endpoint.get('SslMode'),
                    'service_access_role_arn': endpoint.get('ServiceAccessRoleArn'),
                    'external_table_definition': endpoint.get('ExternalTableDefinition')[:100] + '...' if endpoint.get('ExternalTableDefinition') else None,
                    'extra_connection_attributes': endpoint.get('ExtraConnectionAttributes'),
                    'kms_key_id': endpoint.get('KmsKeyId'),
                    'tags': get_dms_resource_tags(client, endpoint_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== DMS EVENT SUBSCRIPTIONS ==========
        try:
            subscriptions = client.describe_event_subscriptions()
            for sub in subscriptions.get('EventSubscriptionsList', []):
                sub_id = sub['CustSubscriptionId']
                sub_arn = sub.get('EventSubscriptionArn', sub_id)
                sns_topic_arn = sub.get('SnsTopicArn', '')
                status = sub.get('Status', 'active')
                
                services.append({
                    'service_id': 'dms_event_subscription',
                    'resource_id': sub_arn,
                    'resource_name': sub_id,
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # SNS costs apply
                    'details': {
                        'subscription_id': sub_id,
                        'subscription_arn': sub_arn,
                        'sns_topic_arn': sns_topic_arn,
                        'status': status,
                        'source_type': sub.get('SourceType'),
                        'source_ids_list': sub.get('SourceIdsList', []),
                        'event_categories_list': sub.get('EventCategoriesList', []),
                        'enabled': sub.get('Enabled', True),
                        'subscription_creation_time': sub.get('SubscriptionCreationTime').isoformat() if sub.get('SubscriptionCreationTime') else None,
                        'tags': get_dms_resource_tags(client, sub_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DMS CERTIFICATES ==========
        try:
            certificates = client.describe_certificates()
            for cert in certificates.get('Certificates', []):
                cert_id = cert['CertificateIdentifier']
                cert_arn = cert.get('CertificateArn', cert_id)
                
                services.append({
                    'service_id': 'dms_certificate',
                    'resource_id': cert_arn,
                    'resource_name': cert_id,
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'certificate_identifier': cert_id,
                        'certificate_arn': cert_arn,
                        'certificate_creation_date': cert.get('CertificateCreationDate').isoformat() if cert.get('CertificateCreationDate') else None,
                        'certificate_valid_from_date': cert.get('CertificateValidFromDate').isoformat() if cert.get('CertificateValidFromDate') else None,
                        'certificate_valid_to_date': cert.get('CertificateValidToDate').isoformat() if cert.get('CertificateValidToDate') else None,
                        'key_length': cert.get('KeyLength'),
                        'signing_algorithm': cert.get('SigningAlgorithm'),
                        'certificate_owner': cert.get('CertificateOwner'),
                        'certificate_wallet': 'present' if cert.get('CertificateWallet') else None,
                        'tags': get_dms_resource_tags(client, cert_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DMS REPLICATION SUBNET GROUPS ==========
        try:
            subnet_groups = client.describe_replication_subnet_groups()
            for sg in subnet_groups.get('ReplicationSubnetGroups', []):
                sg_id = sg['ReplicationSubnetGroupIdentifier']
                sg_arn = sg.get('ReplicationSubnetGroupArn', sg_id)
                vpc_id = sg.get('VpcId', '')
                subnet_group_status = sg.get('SubnetGroupStatus', 'complete')
                
                services.append({
                    'service_id': 'dms_replication_subnet_group',
                    'resource_id': sg_arn,
                    'resource_name': sg_id,
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'replication_subnet_group_identifier': sg_id,
                        'replication_subnet_group_description': sg.get('ReplicationSubnetGroupDescription'),
                        'vpc_id': vpc_id,
                        'subnet_group_status': subnet_group_status,
                        'subnets': [
                            {
                                'subnet_identifier': s['SubnetIdentifier'],
                                'subnet_availability_zone': s['SubnetAvailabilityZone']['Name'],
                                'subnet_status': s['SubnetStatus']
                            }
                            for s in sg.get('Subnets', [])
                        ],
                        'recommended_network_acls': 'The subnet group uses VPC networking',
                        'tags': get_dms_resource_tags(client, sg_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DMS FLEET ADVISOR ==========
        try:
            # Check if Fleet Advisor has collected data
            collector_health = client.describe_fleet_advisor_collectors()
            collectors = collector_health.get('Collectors', [])
            
            for collector in collectors:
                collector_id = collector.get('CollectorReferencedId', collector.get('CollectorName', 'unknown'))
                
                services.append({
                    'service_id': 'dms_fleet_advisor',
                    'resource_id': collector.get('CollectorName', collector_id),
                    'resource_name': collector.get('CollectorName', 'Fleet Advisor'),
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Premium support may apply
                    'details': {
                        'collector_name': collector.get('CollectorName'),
                        'collector_version': collector.get('CollectorVersion'),
                        'collector_status': collector.get('CollectorStatus'),
                        's3_bucket_name': collector.get('S3BucketName'),
                        'service_access_role_arn': collector.get('ServiceAccessRoleArn'),
                        'number_of_databases': collector.get('NumberOfDatabases', 0),
                        'last_modified': collector.get('LastModified').isoformat() if collector.get('LastModified') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DMS DATA PROVIDERS ==========
        try:
            # For DMS Serverless
            data_providers = client.describe_data_providers()
            for provider in data_providers.get('DataProviders', []):
                provider_id = provider['DataProviderIdentifier']
                provider_name = provider.get('DataProviderName', provider_id)
                engine = provider.get('Engine', 'mysql')
                
                services.append({
                    'service_id': 'dms_data_provider',
                    'resource_id': provider.get('DataProviderArn', provider_id),
                    'resource_name': provider_name,
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'data_provider_name': provider_name,
                        'data_provider_arn': provider.get('DataProviderArn'),
                        'data_provider_identifier': provider_id,
                        'description': provider.get('Description'),
                        'engine': engine,
                        'settings': provider.get('Settings', {}),
                        'creation_date': provider.get('CreationDate').isoformat() if provider.get('CreationDate') else None,
                        'tags': get_dms_resource_tags(client, provider.get('DataProviderArn', ''))
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DMS MIGRATION PROJECTS ==========
        try:
            # For DMS Serverless
            projects = client.describe_migration_projects()
            for project in projects.get('MigrationProjects', []):
                project_id = project['MigrationProjectIdentifier']
                project_name = project.get('MigrationProjectName', project_id)
                
                services.append({
                    'service_id': 'dms_migration_project',
                    'resource_id': project.get('MigrationProjectArn', project_id),
                    'resource_name': project_name,
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'migration_project_name': project_name,
                        'migration_project_arn': project.get('MigrationProjectArn'),
                        'migration_project_identifier': project_id,
                        'description': project.get('Description'),
                        'source_data_provider_descriptors': project.get('SourceDataProviderDescriptors', []),
                        'target_data_provider_descriptors': project.get('TargetDataProviderDescriptors', []),
                        'instance_profile_arn': project.get('InstanceProfileArn'),
                        'transformation_rules': project.get('TransformationRules', {}),
                        'schema_conversion_application_attributes': project.get('SchemaConversionApplicationAttributes', {}),
                        'creation_date': project.get('CreationDate').isoformat() if project.get('CreationDate') else None,
                        'tags': get_dms_resource_tags(client, project.get('MigrationProjectArn', ''))
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DMS INSTANCE PROFILES ==========
        try:
            instance_profiles = client.describe_instance_profiles()
            for profile in instance_profiles.get('InstanceProfiles', []):
                profile_id = profile['InstanceProfileIdentifier']
                profile_name = profile.get('InstanceProfileName', profile_id)
                
                services.append({
                    'service_id': 'dms_instance_profile',
                    'resource_id': profile.get('InstanceProfileArn', profile_id),
                    'resource_name': profile_name,
                    'region': region,
                    'service_type': 'Migration & Transfer',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'instance_profile_name': profile_name,
                        'instance_profile_arn': profile.get('InstanceProfileArn'),
                        'instance_profile_identifier': profile_id,
                        'description': profile.get('Description'),
                        'availability_zone': profile.get('AvailabilityZone'),
                        'kms_key_id': profile.get('KmsKeyId'),
                        'publicly_accessible': profile.get('PubliclyAccessible', False),
                        'network_type': profile.get('NetworkType'),
                        'subnet_group_identifier': profile.get('SubnetGroupIdentifier'),
                        'vpc_security_groups': profile.get('VpcSecurityGroups', []),
                        'creation_date': profile.get('CreationDate').isoformat() if profile.get('CreationDate') else None,
                        'tags': get_dms_resource_tags(client, profile.get('InstanceProfileArn', ''))
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering DMS services in {region}: {str(e)}")
    
    return services

def get_dms_resource_tags(client, resource_arn):
    """Get tags for DMS resource"""
    try:
        response = client.list_tags_for_resource(ResourceArn=resource_arn)
        return response.get('TagList', [])
    except:
        return []

def parse_json(json_str):
    """Parse JSON string safely"""
    if not json_str:
        return {}
    try:
        import json
        if isinstance(json_str, str):
            return json.loads(json_str)
        return json_str
    except:
        return {}