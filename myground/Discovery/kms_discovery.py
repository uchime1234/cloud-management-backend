# discovery/kms_discovery.py
import boto3
from datetime import datetime

from datetime import timezone
# and then using:
timezone.utc

def discover_kms_services(creds, region):
    """Discover KMS keys and related resources"""
    services = []
    try:
        client = boto3.client(
            'kms',
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
        
        # ========== CUSTOMER MASTER KEYS ==========
        # List all keys including AWS managed keys
        keys = client.list_keys()
        for key in keys.get('Keys', []):
            key_id = key['KeyId']
            key_arn = key['KeyArn']
            
            try:
                key_details = client.describe_key(KeyId=key_id)
                metadata = key_details['KeyMetadata']
                
                key_state = metadata.get('KeyState', 'Disabled')
                key_usage = metadata.get('KeyUsage', 'ENCRYPT_DECRYPT')
                key_spec = metadata.get('KeySpec', 'SYMMETRIC_DEFAULT')
                key_origin = metadata.get('Origin', 'AWS_KMS')
                key_manager = metadata.get('KeyManager', 'CUSTOMER')
                creation_date = metadata.get('CreationDate')
                
                # AWS managed keys are free
                if key_manager == 'AWS':
                    monthly_cost = 0.00
                    service_id = 'kms_aws_managed_key'
                else:
                    # Customer managed keys: $1 per key per month
                    monthly_cost = 1.00
                    
                    # Check if key material is imported
                    if key_origin == 'EXTERNAL':
                        service_id = 'kms_cmk_imported'
                        monthly_cost = 1.00
                    else:
                        service_id = 'kms_cmk'
                
                services.append({
                    'service_id': service_id,
                    'resource_id': key_arn,
                    'resource_name': metadata.get('Description', key_id),
                    'region': region,
                    'service_type': 'Security',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'key_id': key_id,
                        'key_arn': key_arn,
                        'description': metadata.get('Description'),
                        'key_state': key_state,
                        'key_usage': key_usage,
                        'key_spec': key_spec,
                        'key_origin': key_origin,
                        'key_manager': key_manager,
                        'creation_date': creation_date.isoformat() if creation_date else None,
                        'enabled': key_state == 'Enabled',
                        'aws_account_id': metadata.get('AWSAccountId'),
                        'multi_region': metadata.get('MultiRegion', False),
                        'deletion_date': metadata.get('DeletionDate').isoformat() if metadata.get('DeletionDate') else None,
                        'valid_to': metadata.get('ValidTo').isoformat() if metadata.get('ValidTo') else None,
                        'encryption_algorithms': metadata.get('EncryptionAlgorithms', []),
                        'signing_algorithms': metadata.get('SigningAlgorithms', []),
                        'pending_deletion_window_in_days': metadata.get('PendingDeletionWindowInDays'),
                        'tags': get_kms_tags(client, key_id)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== KEY ROTATION ==========
                if key_manager == 'CUSTOMER' and key_state == 'Enabled':
                    try:
                        rotation = client.get_key_rotation_status(KeyId=key_id)
                        if rotation.get('KeyRotationEnabled', False):
                            services.append({
                                'service_id': 'kms_rotation',
                                'resource_id': f"{key_arn}/rotation",
                                'resource_name': f"{metadata.get('Description', key_id)} Rotation",
                                'region': region,
                                'service_type': 'Security',
                                'estimated_monthly_cost': 0.00,
                'count': 1,  # Free
                                'details': {
                                    'key_id': key_id,
                                    'key_arn': key_arn,
                                    'key_rotation_enabled': True,
                                    'rotation_period_days': 365
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    except:
                        pass
                
                # ========== KEY ALIASES ==========
                try:
                    aliases = client.list_aliases(KeyId=key_id)
                    for alias in aliases.get('Aliases', []):
                        if 'AliasArn' in alias:
                            services.append({
                                'service_id': 'kms_alias',
                                'resource_id': alias['AliasArn'],
                                'resource_name': alias['AliasName'],
                                'region': region,
                                'service_type': 'Security',
                                'estimated_monthly_cost': 0.00,
                'count': 1,
                                'details': {
                                    'alias_name': alias['AliasName'],
                                    'alias_arn': alias['AliasArn'],
                                    'target_key_id': alias.get('TargetKeyId'),
                                    'creation_date': alias.get('CreationDate').isoformat() if alias.get('CreationDate') else None,
                                    'last_updated_date': alias.get('LastUpdatedDate').isoformat() if alias.get('LastUpdatedDate') else None
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                except:
                    pass
                
                # ========== KEY GRANTS ==========
                try:
                    grants = client.list_grants(KeyId=key_id)
                    for grant in grants.get('Grants', []):
                        services.append({
                            'service_id': 'kms_grant',
                            'resource_id': grant['GrantId'],
                            'resource_name': grant.get('Name', grant['GrantId']),
                            'region': region,
                            'service_type': 'Security',
                            'estimated_monthly_cost': 0.00,
                'count': 1,
                            'details': {
                                'grant_id': grant['GrantId'],
                                'grantee_principal': grant.get('GranteePrincipal'),
                                'retiring_principal': grant.get('RetiringPrincipal'),
                                'issuing_account': grant.get('IssuingAccount'),
                                'operations': grant.get('Operations', []),
                                'constraints': grant.get('Constraints', {}),
                                'creation_date': grant.get('CreationDate').isoformat() if grant.get('CreationDate') else None,
                                'name': grant.get('Name')
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
                    
            except Exception as e:
                print(f"Error describing KMS key {key_id}: {str(e)}")
        
        # ========== CUSTOM KEY STORES ==========
        try:
            custom_stores = client.describe_custom_key_stores()
            for store in custom_stores.get('CustomKeyStores', []):
                store_id = store['CustomKeyStoreId']
                store_name = store['CustomKeyStoreName']
                
                services.append({
                    'service_id': 'kms_custom_key_store',
                    'resource_id': store.get('CustomKeyStoreArn', store_id),
                    'resource_name': store_name,
                    'region': region,
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # CloudHSM pricing applies
                    'details': {
                        'custom_key_store_id': store_id,
                        'custom_key_store_name': store_name,
                        'cloud_hsm_cluster_id': store.get('CloudHsmClusterId'),
                        'trust_anchor_certificate': store.get('TrustAnchorCertificate'),
                        'connection_state': store.get('ConnectionState'),
                        'connection_error_code': store.get('ConnectionErrorCode'),
                        'creation_date': store.get('CreationDate').isoformat() if store.get('CreationDate') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering KMS services in {region}: {str(e)}")
    
    return services

def get_kms_tags(client, key_id):
    """Get tags for KMS key"""
    try:
        response = client.list_resource_tags(KeyId=key_id)
        return response.get('Tags', [])
    except:
        return []