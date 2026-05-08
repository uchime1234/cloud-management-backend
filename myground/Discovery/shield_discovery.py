# discovery/shield_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_shield_services(creds, region):
    """Discover Shield Advanced protections and subscriptions"""
    services = []
    try:
        # Shield is global, but we need to check if it's enabled
        client = boto3.client(
            'shield',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name='us-east-1'  # Shield is global
            config=Config(
            connect_timeout=30,
            read_timeout=30,
            retries={'max_attempts': 3}
        ),
        verify=False 
        )
        
        # ========== SHIELD SUBSCRIPTION ==========
        try:
            subscription = client.describe_subscription()
            if subscription:
                sub_details = subscription.get('Subscription', {})
                
                # Shield Advanced: $3000 per month
                monthly_cost = 3000.00
                
                services.append({
                    'service_id': 'shield_advanced',
                    'resource_id': 'shield-advanced-subscription',
                    'resource_name': 'Shield Advanced Subscription',
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'subscription_id': sub_details.get('SubscriptionId'),
                        'start_time': sub_details.get('StartTime').isoformat() if sub_details.get('StartTime') else None,
                        'end_time': sub_details.get('EndTime').isoformat() if sub_details.get('EndTime') else None,
                        'time_commitment_in_seconds': sub_details.get('TimeCommitmentInSeconds'),
                        'auto_renew': sub_details.get('AutoRenew', 'DISABLED'),
                        'limits': sub_details.get('Limits', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== SHIELD ADVANCED PROTECTIONS ==========
                protections = client.list_protections()
                for protection in protections.get('Protections', []):
                    protection_id = protection['Id']
                    protection_name = protection['Name']
                    resource_arn = protection.get('ResourceArn')
                    
                    services.append({
                        'service_id': 'shield_advanced',
                        'resource_id': protection_id,
                        'resource_name': protection_name,
                        'region': 'global',
                        'service_type': 'Security',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Included in subscription
                        'details': {
                            'protection_id': protection_id,
                            'name': protection_name,
                            'resource_arn': resource_arn,
                            'health_check_ids': protection.get('HealthCheckIds', []),
                            'protection_arn': protection.get('ProtectionArn'),
                            'application_layer_automatic_response': protection.get('ApplicationLayerAutomaticResponseConfiguration', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                
                # ========== SHIELD ADVANCED EMERGENCY CONTACTS ==========
                try:
                    emergency = client.describe_emergency_contact_settings()
                    contacts = emergency.get('EmergencyContactList', [])
                    
                    services.append({
                        'service_id': 'shield_advanced',
                        'resource_id': 'shield-emergency-contacts',
                        'resource_name': 'Emergency Contacts',
                        'region': 'global',
                        'service_type': 'Security',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'contacts': [
                                {
                                    'email': c.get('EmailAddress'),
                                    'phone_number': c.get('PhoneNumber'),
                                    'contact_notes': c.get('ContactNotes')
                                }
                                for c in contacts
                            ]
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                except:
                    pass
        except:
            # Shield Standard (free)
            services.append({
                'service_id': 'shield_standard',
                'resource_id': 'shield-standard',
                'resource_name': 'Shield Standard',
                'region': 'global',
                'service_type': 'Security',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'description': 'Basic DDoS protection for all AWS resources',
                    'enabled': True,
                    'features': ['Network layer DDoS protection', 'Automatic inline attack mitigation']
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== DRT ACCESS ==========
        try:
            drt_access = client.describe_drt_access()
            if drt_access:
                services.append({
                    'service_id': 'shield_advanced',
                    'resource_id': 'shield-drt-access',
                    'resource_name': 'DRT Access',
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'role_arn': drt_access.get('RoleArn'),
                        'log_bucket_list': drt_access.get('LogBucketList', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering Shield services: {str(e)}")
    
    return services