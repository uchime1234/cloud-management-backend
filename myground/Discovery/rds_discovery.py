# discovery/rds_discovery.py
import boto3
from datetime import datetime

from datetime import timezone
# and then using:
timezone.utc

def discover_rds_services(creds, region):
    """Discover all RDS-related services and components"""
    services = []
    try:
        client = boto3.client(
            'rds',
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
        
        # ========== RDS INSTANCES ==========
        instances = client.describe_db_instances()
        for instance in instances.get('DBInstances', []):
            instance_id = instance['DBInstanceIdentifier']
            instance_class = instance.get('DBInstanceClass', '')
            engine = instance.get('Engine', '')
            storage_type = instance.get('StorageType', 'gp2')
            allocated_storage = instance.get('AllocatedStorage', 0)
            multi_az = instance.get('MultiAZ', False)
            iops = instance.get('Iops', 0)
            
            # Estimate cost (simplified)
            # Instance hourly rate based on class (simplified)
            hourly_rates = {
                'db.t3.micro': 0.017, 'db.t3.small': 0.034, 'db.t3.medium': 0.068,
                'db.t3.large': 0.136, 'db.t3.xlarge': 0.272, 'db.t3.2xlarge': 0.544,
                'db.m5.large': 0.155, 'db.m5.xlarge': 0.31, 'db.m5.2xlarge': 0.62,
                'db.m5.4xlarge': 1.24, 'db.m5.8xlarge': 2.48, 'db.m5.12xlarge': 3.72,
                'db.m5.16xlarge': 4.96, 'db.m5.24xlarge': 7.44,
                'db.r5.large': 0.24, 'db.r5.xlarge': 0.48, 'db.r5.2xlarge': 0.96,
                'db.r5.4xlarge': 1.92, 'db.r5.8xlarge': 3.84, 'db.r5.12xlarge': 5.76,
                'db.r5.16xlarge': 7.68, 'db.r5.24xlarge': 11.52
            }
            
            hourly_rate = hourly_rates.get(instance_class, 0.10)
            monthly_instance_cost = hourly_rate * 730
            
            # Storage cost
            storage_pricing = {
                'gp2': 0.115, 'gp3': 0.108, 'io1': 0.125, 'standard': 0.115,
                'aurora': 0.10
            }
            storage_rate = storage_pricing.get(storage_type, 0.115)
            monthly_storage_cost = storage_rate * allocated_storage
            
            # IOPS cost for io1
            if storage_type == 'io1' and iops > 0:
                monthly_iops_cost = 0.10 * iops
            else:
                monthly_iops_cost = 0
            
            # Multi-AZ doubles the instance cost
            if multi_az:
                monthly_instance_cost *= 2
            
            total_monthly_cost = monthly_instance_cost + monthly_storage_cost + monthly_iops_cost
            
            services.append({
                'service_id': 'rds_db_instance',
                'resource_id': instance['DBInstanceArn'],
                'resource_name': instance_id,
                'region': region,
                'service_type': 'Database',
                'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                'details': {
                    'db_instance_identifier': instance_id,
                    'db_instance_class': instance_class,
                    'engine': engine,
                    'engine_version': instance.get('EngineVersion'),
                    'db_instance_status': instance.get('DBInstanceStatus'),
                    'allocated_storage_gb': allocated_storage,
                    'storage_type': storage_type,
                    'iops': iops,
                    'availability_zone': instance.get('AvailabilityZone'),
                    'multi_az': multi_az,
                    'vpc_id': instance.get('DBSubnetGroup', {}).get('VpcId'),
                    'subnet_group_name': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName'),
                    'publicly_accessible': instance.get('PubliclyAccessible', False),
                    'endpoint': instance.get('Endpoint', {}).get('Address'),
                    'port': instance.get('Endpoint', {}).get('Port'),
                    'backup_retention_period': instance.get('BackupRetentionPeriod'),
                    'backup_window': instance.get('PreferredBackupWindow'),
                    'maintenance_window': instance.get('PreferredMaintenanceWindow'),
                    'auto_minor_version_upgrade': instance.get('AutoMinorVersionUpgrade', False),
                    'license_model': instance.get('LicenseModel'),
                    'performance_insights_enabled': instance.get('PerformanceInsightsEnabled', False),
                    'deletion_protection': instance.get('DeletionProtection', False),
                    'tags': instance.get('TagList', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== RDS READ REPLICAS ==========
            if instance.get('ReadReplicaDBInstanceIdentifiers'):
                for replica_id in instance['ReadReplicaDBInstanceIdentifiers']:
                    services.append({
                        'service_id': 'rds_read_replica',
                        'resource_id': f"{instance_id}-replica-{replica_id}",
                        'resource_name': replica_id,
                        'region': region,
                        'service_type': 'Database',
                        'estimated_monthly_cost': round(total_monthly_cost * 0.5, 2),
                'count': 1,  # Approx 50% of primary
                        'details': {
                            'source_db_instance': instance_id,
                            'replica_db_instance': replica_id,
                            'engine': engine,
                            'status': 'active'
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        
        # ========== RDS PROXIES ==========
        try:
            proxies = client.describe_db_proxies()
            for proxy in proxies.get('DBProxies', []):
                proxy_hourly_cost = 0.015
                monthly_cost = proxy_hourly_cost * 730
                
                services.append({
                    'service_id': 'rds_proxy',
                    'resource_id': proxy['DBProxyArn'],
                    'resource_name': proxy['DBProxyName'],
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'db_proxy_name': proxy.get('DBProxyName'),
                        'status': proxy.get('Status'),
                        'engine_family': proxy.get('EngineFamily'),
                        'vpc_id': proxy.get('VpcId'),
                        'vpc_subnet_ids': proxy.get('VpcSubnetIds', []),
                        'vpc_security_group_ids': proxy.get('VpcSecurityGroupIds', []),
                        'auth_description': proxy.get('Auth', []),
                        'role_arn': proxy.get('RoleArn'),
                        'endpoint': proxy.get('Endpoint'),
                        'created_date': proxy.get('CreatedDate').isoformat() if proxy.get('CreatedDate') else None,
                        'updated_date': proxy.get('UpdatedDate').isoformat() if proxy.get('UpdatedDate') else None,
                        'tags': proxy.get('TagList', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== RDS SNAPSHOTS ==========
        snapshots = client.describe_db_snapshots(SnapshotType='manual')
        for snapshot in snapshots.get('DBSnapshots', []):
            allocated_storage = snapshot.get('AllocatedStorage', 0)
            monthly_cost = 0.095 * allocated_storage  # $0.095 per GB-month
            
            services.append({
                'service_id': 'rds_snapshot',
                'resource_id': snapshot['DBSnapshotArn'],
                'resource_name': snapshot['DBSnapshotIdentifier'],
                'region': region,
                'service_type': 'Database',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'db_snapshot_identifier': snapshot.get('DBSnapshotIdentifier'),
                    'db_instance_identifier': snapshot.get('DBInstanceIdentifier'),
                    'snapshot_create_time': snapshot.get('SnapshotCreateTime').isoformat() if snapshot.get('SnapshotCreateTime') else None,
                    'engine': snapshot.get('Engine'),
                    'allocated_storage_gb': allocated_storage,
                    'status': snapshot.get('Status'),
                    'percent_progress': snapshot.get('PercentProgress'),
                    'snapshot_type': snapshot.get('SnapshotType'),
                    'tags': snapshot.get('TagList', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== RDS AUTOMATED BACKUPS ==========
        # Automated backups are included in the instance, but we can track them
        for instance in instances.get('DBInstances', []):
            backup_retention = instance.get('BackupRetentionPeriod', 0)
            allocated_storage = instance.get('AllocatedStorage', 0)
            
            if backup_retention > 0:
                # Estimate backup storage (simplified - usually less than allocated storage)
                estimated_backup_size = allocated_storage * 0.5
                monthly_cost = 0.095 * estimated_backup_size
                
                services.append({
                    'service_id': 'rds_backup',
                    'resource_id': f"{instance['DBInstanceArn']}-backup",
                    'resource_name': f"{instance['DBInstanceIdentifier']} Automated Backups",
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'db_instance_identifier': instance['DBInstanceIdentifier'],
                        'backup_retention_period': backup_retention,
                        'backup_window': instance.get('PreferredBackupWindow'),
                        'estimated_backup_size_gb': estimated_backup_size
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
        # ========== RDS PARAMETER GROUPS ==========
        param_groups = client.describe_db_parameter_groups()
        for param_group in param_groups.get('DBParameterGroups', []):
            services.append({
                'service_id': 'rds_parameter_group',
                'resource_id': param_group['DBParameterGroupArn'],
                'resource_name': param_group['DBParameterGroupName'],
                'region': region,
                'service_type': 'Database',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'db_parameter_group_name': param_group.get('DBParameterGroupName'),
                    'db_parameter_group_family': param_group.get('DBParameterGroupFamily'),
                    'description': param_group.get('Description'),
                    'tags': param_group.get('TagList', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== RDS OPTION GROUPS ==========
        option_groups = client.describe_option_groups()
        for option_group in option_groups.get('OptionGroupsList', []):
            services.append({
                'service_id': 'rds_option_group',
                'resource_id': option_group['OptionGroupArn'],
                'resource_name': option_group['OptionGroupName'],
                'region': region,
                'service_type': 'Database',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'option_group_name': option_group.get('OptionGroupName'),
                    'option_group_description': option_group.get('OptionGroupDescription'),
                    'engine_name': option_group.get('EngineName'),
                    'major_engine_version': option_group.get('MajorEngineVersion'),
                    'options': option_group.get('Options', []),
                    'tags': option_group.get('TagList', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== RDS SUBNET GROUPS ==========
        subnet_groups = client.describe_db_subnet_groups()
        for subnet_group in subnet_groups.get('DBSubnetGroups', []):
            services.append({
                'service_id': 'rds_subnet_group',
                'resource_id': subnet_group['DBSubnetGroupArn'],
                'resource_name': subnet_group['DBSubnetGroupName'],
                'region': region,
                'service_type': 'Database',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'db_subnet_group_name': subnet_group.get('DBSubnetGroupName'),
                    'db_subnet_group_description': subnet_group.get('DBSubnetGroupDescription'),
                    'vpc_id': subnet_group.get('VpcId'),
                    'subnet_group_status': subnet_group.get('SubnetGroupStatus'),
                    'subnets': subnet_group.get('Subnets', []),
                    'tags': subnet_group.get('TagList', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== AURORA CLUSTERS ==========
        try:
            clusters = client.describe_db_clusters()
            for cluster in clusters.get('DBClusters', []):
                engine = cluster.get('Engine', '')
                allocated_storage = cluster.get('AllocatedStorage', 0)
                
                # Aurora uses different pricing
                monthly_storage_cost = 0.10 * allocated_storage
                
                services.append({
                    'service_id': 'rds_aurora_cluster',
                    'resource_id': cluster['DBClusterArn'],
                    'resource_name': cluster['DBClusterIdentifier'],
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(monthly_storage_cost, 2),
                'count': 1,  # Instances billed separately
                    'details': {
                        'db_cluster_identifier': cluster.get('DBClusterIdentifier'),
                        'engine': engine,
                        'engine_version': cluster.get('EngineVersion'),
                        'status': cluster.get('Status'),
                        'allocated_storage_gb': allocated_storage,
                        'database_name': cluster.get('DatabaseName'),
                        'vpc_id': cluster.get('DBSubnetGroup', {}).get('VpcId'),
                        'availability_zones': cluster.get('AvailabilityZones', []),
                        'multi_az': cluster.get('MultiAZ', False),
                        'endpoint': cluster.get('Endpoint'),
                        'reader_endpoint': cluster.get('ReaderEndpoint'),
                        'port': cluster.get('Port'),
                        'master_username': cluster.get('MasterUsername'),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod'),
                        'backup_window': cluster.get('PreferredBackupWindow'),
                        'maintenance_window': cluster.get('PreferredMaintenanceWindow'),
                        'tags': cluster.get('TagList', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== AURORA BACKTRACK ==========
                if cluster.get('BacktrackWindow', 0) > 0:
                    services.append({
                        'service_id': 'rds_aurora_backtrack',
                        'resource_id': f"{cluster['DBClusterArn']}-backtrack",
                        'resource_name': f"{cluster['DBClusterIdentifier']} Backtrack",
                        'region': region,
                        'service_type': 'Database',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.020 per GB-month of change records
                        'details': {
                            'db_cluster_identifier': cluster['DBClusterIdentifier'],
                            'backtrack_window_hours': cluster.get('BacktrackWindow'),
                            'enabled': True
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        except:
            pass
        
        # ========== RDS PERFORMANCE INSIGHTS ==========
        for instance in instances.get('DBInstances', []):
            if instance.get('PerformanceInsightsEnabled', False):
                hourly_cost = 0.10
                monthly_cost = hourly_cost * 730
                
                services.append({
                    'service_id': 'rds_performance_insights',
                    'resource_id': f"{instance['DBInstanceArn']}-pi",
                    'resource_name': f"{instance['DBInstanceIdentifier']} Performance Insights",
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'db_instance_identifier': instance['DBInstanceIdentifier'],
                        'performance_insights_enabled': True,
                        'performance_insights_kms_key_id': instance.get('PerformanceInsightsKMSKeyId'),
                        'performance_insights_retention_period': instance.get('PerformanceInsightsRetentionPeriod', 7)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
    except Exception as e:
        print(f"Error discovering RDS services in {region}: {str(e)}")
    
    return services