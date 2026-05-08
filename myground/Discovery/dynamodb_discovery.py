# discovery/dynamodb_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_dynamodb_services(creds, region):
    """Discover DynamoDB tables and related services"""
    services = []
    try:
        client = boto3.client(
            'dynamodb',
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
        
        # ========== DYNAMODB TABLES ==========
        tables = client.list_tables()
        for table_name in tables.get('TableNames', []):
            try:
                table = client.describe_table(TableName=table_name)
                table_info = table['Table']
                
                billing_mode = table_info.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                table_status = table_info.get('TableStatus', 'ACTIVE')
                item_count = table_info.get('ItemCount', 0)
                table_size_bytes = table_info.get('TableSizeBytes', 0)
                table_size_gb = table_size_bytes / (1024 * 1024 * 1024)
                
                # Estimate cost
                if billing_mode == 'PROVISIONED':
                    # Provisioned capacity
                    provisioned_throughput = table_info.get('ProvisionedThroughput', {})
                    read_capacity = provisioned_throughput.get('ReadCapacityUnits', 0)
                    write_capacity = provisioned_throughput.get('WriteCapacityUnits', 0)
                    
                    # $0.00013 per RCU-hour, $0.00065 per WCU-hour
                    monthly_read_cost = read_capacity * 0.00013 * 730
                    monthly_write_cost = write_capacity * 0.00065 * 730
                    capacity_cost = monthly_read_cost + monthly_write_cost
                else:
                    # On-demand
                    # Assume 1 million reads and 1 million writes per month
                    monthly_read_cost = 0.25  # $0.25 per million reads
                    monthly_write_cost = 1.25  # $1.25 per million writes
                    capacity_cost = monthly_read_cost + monthly_write_cost
                
                # Storage cost - $0.25 per GB-month
                storage_cost = table_size_gb * 0.25
                
                total_monthly_cost = capacity_cost + storage_cost
                
                services.append({
                    'service_id': 'dynamodb_table',
                    'resource_id': table_info['TableArn'],
                    'resource_name': table_name,
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                    'details': {
                        'table_name': table_name,
                        'table_arn': table_info['TableArn'],
                        'table_status': table_status,
                        'billing_mode': billing_mode,
                        'item_count': item_count,
                        'table_size_bytes': table_size_bytes,
                        'table_size_gb': round(table_size_gb, 2),
                        'provisioned_throughput': table_info.get('ProvisionedThroughput', {}),
                        'creation_date': table_info.get('CreationDateTime').isoformat() if table_info.get('CreationDateTime') else None,
                        'key_schema': table_info.get('KeySchema', []),
                        'attribute_definitions': table_info.get('AttributeDefinitions', []),
                        'global_secondary_indexes': table_info.get('GlobalSecondaryIndexes', []),
                        'local_secondary_indexes': table_info.get('LocalSecondaryIndexes', []),
                        'stream_specification': table_info.get('StreamSpecification', {}),
                        'sse_description': table_info.get('SSEDescription', {}),
                        'tags': get_dynamodb_tags(client, table_info['TableArn'])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== DYNAMODB GLOBAL SECONDARY INDEXES ==========
                for gsi in table_info.get('GlobalSecondaryIndexes', []):
                    gsi_name = gsi['IndexName']
                    gsi_size_bytes = gsi.get('IndexSizeBytes', 0)
                    gsi_size_gb = gsi_size_bytes / (1024 * 1024 * 1024)
                    
                    services.append({
                        'service_id': 'dynamodb_gsi',
                        'resource_id': f"{table_info['TableArn']}/index/{gsi_name}",
                        'resource_name': f"{table_name}.{gsi_name}",
                        'region': region,
                        'service_type': 'Database',
                        'estimated_monthly_cost': round(gsi_size_gb * 0.25, 2),
                'count': 1,  # Storage cost only
                        'details': {
                            'table_name': table_name,
                            'index_name': gsi_name,
                            'index_arn': gsi.get('IndexArn'),
                            'index_size_bytes': gsi_size_bytes,
                            'index_size_gb': round(gsi_size_gb, 2),
                            'item_count': gsi.get('ItemCount', 0),
                            'key_schema': gsi.get('KeySchema', []),
                            'projection': gsi.get('Projection', {}),
                            'index_status': gsi.get('IndexStatus'),
                            'provisioned_throughput': gsi.get('ProvisionedThroughput', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                
                # ========== DYNAMODB STREAMS ==========
                if table_info.get('StreamSpecification', {}).get('StreamEnabled', False):
                    services.append({
                        'service_id': 'dynamodb_streams',
                        'resource_id': f"{table_info['TableArn']}/stream",
                        'resource_name': f"{table_name} Stream",
                        'region': region,
                        'service_type': 'Database',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.02 per million read requests
                        'details': {
                            'table_name': table_name,
                            'stream_enabled': True,
                            'stream_view_type': table_info['StreamSpecification'].get('StreamViewType'),
                            'latest_stream_arn': table_info.get('LatestStreamArn'),
                            'latest_stream_label': table_info.get('LatestStreamLabel')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
            except Exception as e:
                print(f"Error describing DynamoDB table {table_name}: {str(e)}")
        
        # ========== DYNAMODB BACKUPS ==========
        try:
            backups = client.list_backups()
            for backup in backups.get('BackupSummaries', []):
                backup_size_bytes = backup.get('BackupSizeBytes', 0)
                backup_size_gb = backup_size_bytes / (1024 * 1024 * 1024)
                
                # On-demand backup: $0.10 per GB-month
                monthly_cost = backup_size_gb * 0.10
                
                services.append({
                    'service_id': 'dynamodb_on_demand_backup',
                    'resource_id': backup['BackupArn'],
                    'resource_name': backup['BackupName'],
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'table_name': backup.get('TableName'),
                        'backup_name': backup.get('BackupName'),
                        'backup_arn': backup.get('BackupArn'),
                        'backup_size_bytes': backup_size_bytes,
                        'backup_size_gb': round(backup_size_gb, 2),
                        'backup_status': backup.get('BackupStatus'),
                        'backup_type': backup.get('BackupType'),
                        'backup_creation_time': backup.get('BackupCreationDateTime').isoformat() if backup.get('BackupCreationDateTime') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DYNAMODB DAX CLUSTERS ==========
        try:
            dax_client = boto3.client(
                'dax',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region
            )
            
            clusters = dax_client.describe_clusters()
            for cluster in clusters.get('Clusters', []):
                node_count = len(cluster.get('Nodes', []))
                node_type = cluster.get('NodeType', 'dax.r4.large')
                
                # Node pricing (approximate)
                node_pricing = {
                    'dax.r4.large': 0.12, 'dax.r4.xlarge': 0.24, 'dax.r4.2xlarge': 0.48,
                    'dax.r4.4xlarge': 0.96, 'dax.r4.8xlarge': 1.92, 'dax.r4.16xlarge': 3.84
                }
                hourly_rate = node_pricing.get(node_type, 0.12)
                monthly_cost = hourly_rate * node_count * 730
                
                services.append({
                    'service_id': 'dynamodb_dax_node',
                    'resource_id': cluster['ClusterArn'],
                    'resource_name': cluster['ClusterName'],
                    'region': region,
                    'service_type': 'Database',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'cluster_name': cluster.get('ClusterName'),
                        'cluster_arn': cluster.get('ClusterArn'),
                        'status': cluster.get('Status'),
                        'node_type': node_type,
                        'node_count': node_count,
                        'nodes': cluster.get('Nodes', []),
                        'subnet_group': cluster.get('SubnetGroup'),
                        'security_groups': cluster.get('SecurityGroups', []),
                        'iam_role_arn': cluster.get('IamRoleArn'),
                        'sse_description': cluster.get('SSEDescription', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DYNAMODB CONTINUOUS BACKUPS (PITR) ==========
        for table_name in tables.get('TableNames', []):
            try:
                pitr = client.describe_continuous_backups(TableName=table_name)
                pitr_status = pitr.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus', 'DISABLED')
                
                if pitr_status == 'ENABLED':
                    # Estimate storage cost (assume 100% of table size)
                    table_info = client.describe_table(TableName=table_name)
                    table_size_bytes = table_info['Table'].get('TableSizeBytes', 0)
                    table_size_gb = table_size_bytes / (1024 * 1024 * 1024)
                    
                    # $0.20 per GB-month for continuous backups
                    monthly_cost = table_size_gb * 0.20
                    
                    services.append({
                        'service_id': 'dynamodb_continuous_backup',
                        'resource_id': f"{table_info['Table']['TableArn']}/pitr",
                        'resource_name': f"{table_name} Point-in-Time Recovery",
                        'region': region,
                        'service_type': 'Database',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'table_name': table_name,
                            'pitr_enabled': True,
                            'pitr_status': pitr_status,
                            'earliest_restorable_time': pitr.get('ContinuousBackupsDescription', {})
                                .get('PointInTimeRecoveryDescription', {}).get('EarliestRestorableDateTime', '').isoformat() if pitr.get('ContinuousBackupsDescription', {})
                                .get('PointInTimeRecoveryDescription', {}).get('EarliestRestorableDateTime') else None,
                            'latest_restorable_time': pitr.get('ContinuousBackupsDescription', {})
                                .get('PointInTimeRecoveryDescription', {}).get('LatestRestorableDateTime', '').isoformat() if pitr.get('ContinuousBackupsDescription', {})
                                .get('PointInTimeRecoveryDescription', {}).get('LatestRestorableDateTime') else None
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== DYNAMODB GLOBAL TABLES ==========
        try:
            global_tables = client.list_global_tables()
            for global_table in global_tables.get('GlobalTables', []):
                global_table_name = global_table['GlobalTableName']
                try:
                    table_info = client.describe_global_table(GlobalTableName=global_table_name)
                    replication_group = table_info.get('GlobalTableDescription', {}).get('ReplicationGroup', [])
                    
                    services.append({
                        'service_id': 'dynamodb_global_table',
                        'resource_id': f"global-table/{global_table_name}",
                        'resource_name': global_table_name,
                        'region': region,
                        'service_type': 'Database',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.15 per million replicated writes
                        'details': {
                            'global_table_name': global_table_name,
                            'replication_group': replication_group,
                            'global_table_status': table_info.get('GlobalTableDescription', {}).get('GlobalTableStatus'),
                            'creation_time': table_info.get('GlobalTableDescription', {}).get('CreationDateTime').isoformat() if table_info.get('GlobalTableDescription', {}).get('CreationDateTime') else None
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                except:
                    pass
        except:
            pass
            
    except Exception as e:
        print(f"Error discovering DynamoDB services in {region}: {str(e)}")
    
    return services

def get_dynamodb_tags(client, resource_arn):
    """Get tags for DynamoDB resource"""
    try:
        response = client.list_tags_of_resource(ResourceArn=resource_arn)
        return response.get('Tags', [])
    except:
        return []