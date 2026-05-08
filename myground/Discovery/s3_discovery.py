# discovery/s3_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_s3_services(creds, region):
    """Discover S3 buckets and related services"""
    services = []
    try:
        client = boto3.client(
            's3',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name='us-east-1',  
            config=Config(
            connect_timeout=30,
            read_timeout=30,
            retries={'max_attempts': 3}
        ),
        verify=False 
            
        )
        
        # ========== S3 BUCKETS ==========
        buckets = client.list_buckets()
        for bucket in buckets.get('Buckets', []):
            bucket_name = bucket['Name']
            creation_date = bucket.get('CreationDate')
            
            try:
                # Get bucket location
                location = client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location.get('LocationConstraint', 'us-east-1')
                if bucket_region is None:
                    bucket_region = 'us-east-1'
                
                # Only process if this is the region we're scanning or it's global
                if region == 'us-east-1' or bucket_region == region:
                    # Get bucket versioning
                    try:
                        versioning = client.get_bucket_versioning(Bucket=bucket_name)
                        versioning_enabled = versioning.get('Status') == 'Enabled'
                    except:
                        versioning_enabled = False
                    
                    # Get bucket encryption
                    try:
                        encryption = client.get_bucket_encryption(Bucket=bucket_name)
                        encryption_enabled = True
                    except:
                        encryption_enabled = False
                    
                    # Get bucket lifecycle
                    try:
                        lifecycle = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                        has_lifecycle = True
                    except:
                        has_lifecycle = False
                    
                    # Get bucket policies
                    try:
                        policy = client.get_bucket_policy(Bucket=bucket_name)
                        has_policy = True
                    except:
                        has_policy = False
                    
                    # Get bucket tags
                    try:
                        tags_response = client.get_bucket_tagging(Bucket=bucket_name)
                        bucket_tags = tags_response.get('TagSet', [])
                    except:
                        bucket_tags = []
                    
                    # Get bucket size (would need CloudWatch or S3 Inventory for actual size)
                    # For now, estimate based on typical usage or leave as 0
                    estimated_size_gb = 0  # Would need actual metrics
                    
                    # Estimate cost (simplified)
                    # Standard storage: $0.023 per GB-month
                    monthly_cost = 0.023 * estimated_size_gb
                    
                    services.append({
                        'service_id': 's3_bucket',
                        'resource_id': bucket_name,
                        'resource_name': bucket_name,
                        'region': bucket_region,
                        'service_type': 'Storage',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'bucket_name': bucket_name,
                            'creation_date': creation_date.isoformat() if creation_date else None,
                            'region': bucket_region,
                            'versioning_enabled': versioning_enabled,
                            'encryption_enabled': encryption_enabled,
                            'has_lifecycle_policy': has_lifecycle,
                            'has_bucket_policy': has_policy,
                            'tags': bucket_tags
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
                    # ========== BUCKET LIFECYCLE RULES ==========
                    if has_lifecycle:
                        lifecycle_config = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                        for rule in lifecycle_config.get('Rules', []):
                            services.append({
                                'service_id': 's3_lifecycle_transition',
                                'resource_id': f"{bucket_name}-{rule.get('ID', 'unknown')}",
                                'resource_name': rule.get('ID', 'Lifecycle Rule'),
                                'region': bucket_region,
                                'service_type': 'Storage',
                                'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per transition
                                'details': {
                                    'bucket_name': bucket_name,
                                    'rule_id': rule.get('ID'),
                                    'status': rule.get('Status'),
                                    'filter': rule.get('Filter', {}),
                                    'transitions': rule.get('Transitions', []),
                                    'expiration': rule.get('Expiration', {}),
                                    'noncurrent_version_transitions': rule.get('NoncurrentVersionTransitions', []),
                                    'noncurrent_version_expiration': rule.get('NoncurrentVersionExpiration', {})
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    
                    # ========== BUCKET REPLICATION ==========
                    try:
                        replication = client.get_bucket_replication(Bucket=bucket_name)
                        replication_config = replication.get('ReplicationConfiguration', {})
                        services.append({
                            'service_id': 's3_replication',
                            'resource_id': f"{bucket_name}-replication",
                            'resource_name': f"{bucket_name} Replication",
                            'region': bucket_region,
                            'service_type': 'Storage',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per GB replicated
                            'details': {
                                'bucket_name': bucket_name,
                                'role': replication_config.get('Role'),
                                'rules': replication_config.get('Rules', [])
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                    except:
                        pass
                    
                    # ========== BUCKET INVENTORY ==========
                    try:
                        inventory = client.list_bucket_inventory_configurations(Bucket=bucket_name)
                        for inventory_config in inventory.get('InventoryConfigurationList', []):
                            services.append({
                                'service_id': 's3_inventory',
                                'resource_id': f"{bucket_name}-{inventory_config.get('Id')}",
                                'resource_name': inventory_config.get('Id'),
                                'region': bucket_region,
                                'service_type': 'Storage',
                                'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per million objects
                                'details': {
                                    'bucket_name': bucket_name,
                                    'inventory_id': inventory_config.get('Id'),
                                    'destination': inventory_config.get('Destination', {}),
                                    'schedule': inventory_config.get('Schedule', {}),
                                    'included_object_versions': inventory_config.get('IncludedObjectVersions'),
                                    'optional_fields': inventory_config.get('OptionalFields', [])
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    except:
                        pass
                    
                    # ========== BUCKET ACCESS POINTS ==========
                    try:
                        access_points = client.list_access_points(Bucket=bucket_name)
                        for ap in access_points.get('AccessPointList', []):
                            services.append({
                                'service_id': 's3_access_points',
                                'resource_id': ap['AccessPointArn'],
                                'resource_name': ap.get('Name'),
                                'region': bucket_region,
                                'service_type': 'Storage',
                                'estimated_monthly_cost': 0.00,
                'count': 1,
                                'details': {
                                    'bucket_name': bucket_name,
                                    'access_point_name': ap.get('Name'),
                                    'access_point_arn': ap.get('AccessPointArn'),
                                    'network_origin': ap.get('NetworkOrigin'),
                                    'vpc_id': ap.get('VpcConfiguration', {}).get('VpcId') if ap.get('VpcConfiguration') else None,
                                    'creation_date': ap.get('CreationDate').isoformat() if ap.get('CreationDate') else None
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    except:
                        pass
                    
            except Exception as e:
                print(f"Error processing bucket {bucket_name}: {str(e)}")
        
        # ========== S3 MULTI-REGION ACCESS POINTS ==========
        try:
            s3control = boto3.client(
                's3control',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name='us-west-2'  # MRAP is global but requires a region
            )
            
            # Get account ID from STS
            sts = boto3.client(
                'sts',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
            account_id = sts.get_caller_identity()['Account']
            
            mraps = s3control.list_multi_region_access_points(AccountId=account_id)
            for mrap in mraps.get('AccessPoints', []):
                services.append({
                    'service_id': 's3_multi_region_access_point',
                    'resource_id': mrap['AccessPointArn'],
                    'resource_name': mrap.get('Name'),
                    'region': 'global',
                    'service_type': 'Storage',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per GB transferred
                    'details': {
                        'name': mrap.get('Name'),
                        'alias': mrap.get('Alias'),
                        'access_point_arn': mrap.get('AccessPointArn'),
                        'status': mrap.get('Status'),
                        'creation_date': mrap.get('CreationDate').isoformat() if mrap.get('CreationDate') else None,
                        'public_access_block': mrap.get('PublicAccessBlock', {}),
                        'regions': mrap.get('Regions', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== S3 STORAGE LENS ==========
        try:
            storage_lens = s3control.list_storage_lens_configurations(AccountId=account_id)
            for lens in storage_lens.get('StorageLensConfigurationList', []):
                services.append({
                    'service_id': 's3_storage_lens',
                    'resource_id': lens['Id'],
                    'resource_name': lens['Id'],
                    'region': 'global',
                    'service_type': 'Storage',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per million objects
                    'details': {
                        'id': lens.get('Id'),
                        'arn': lens.get('StorageLensArn'),
                        'home_region': lens.get('HomeRegion'),
                        'is_enabled': lens.get('IsEnabled'),
                        'storage_lens_configuration': lens
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering S3 services: {str(e)}")
    
    return services