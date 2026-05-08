# discovery/sns_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_sns_services(creds, region):
    """Discover SNS topics and subscriptions"""
    services = []
    try:
        client = boto3.client(
            'sns',
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
        
        # ========== SNS TOPICS ==========
        topics = client.list_topics()
        for topic in topics.get('Topics', []):
            topic_arn = topic['TopicArn']
            topic_name = topic_arn.split(':')[-1]
            
            try:
                # Get topic attributes
                attributes = client.get_topic_attributes(TopicArn=topic_arn)
                attrs = attributes.get('Attributes', {})
                
                # SNS pricing: $0.50 per million publishes
                monthly_publish_cost = 0.50  # Assume 1 million publishes
                
                # Add delivery costs based on protocol
                delivery_costs = 0.00
                
                # Get subscriptions for this topic
                subscriptions = client.list_subscriptions_by_topic(TopicArn=topic_arn)
                subscription_count = len(subscriptions.get('Subscriptions', []))
                
                services.append({
                    'service_id': 'sns_topic',
                    'resource_id': topic_arn,
                    'resource_name': topic_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': round(monthly_publish_cost + delivery_costs, 2),
                'count': 1,
                    'details': {
                        'topic_arn': topic_arn,
                        'topic_name': topic_name,
                        'display_name': attrs.get('DisplayName'),
                        'owner': attrs.get('Owner'),
                        'subscriptions_confirmed': int(attrs.get('SubscriptionsConfirmed', 0)),
                        'subscriptions_deleted': int(attrs.get('SubscriptionsDeleted', 0)),
                        'subscriptions_pending': int(attrs.get('SubscriptionsPending', 0)),
                        'effective_delivery_policy': parse_json(attrs.get('EffectiveDeliveryPolicy')),
                        'policy': parse_json(attrs.get('Policy')),
                        'fifo_topic': attrs.get('FifoTopic') == 'true',
                        'content_based_deduplication': attrs.get('ContentBasedDeduplication') == 'true',
                        'signature_version': attrs.get('SignatureVersion'),
                        'tracing_config': attrs.get('TracingConfig'),
                        'kms_master_key_id': attrs.get('KmsMasterKeyId'),
                        'subscription_count': subscription_count,
                        'tags': get_sns_topic_tags(client, topic_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== SNS SUBSCRIPTIONS ==========
                for sub in subscriptions.get('Subscriptions', []):
                    subscription_arn = sub['SubscriptionArn']
                    if subscription_arn != 'PendingConfirmation':
                        protocol = sub.get('Protocol', 'unknown')
                        endpoint = sub.get('Endpoint', 'unknown')
                        
                        # Delivery cost based on protocol
                        delivery_cost = 0.00
                        service_id = 'sns_http_delivery'  # Default
                        
                        if protocol == 'http' or protocol == 'https':
                            delivery_cost = 0.60  # $0.60 per million deliveries
                            service_id = 'sns_http_delivery'
                        elif protocol == 'email' or protocol == 'email-json':
                            delivery_cost = 2.00  # $2.00 per million deliveries
                            service_id = 'sns_email_delivery'
                        elif protocol == 'sms':
                            delivery_cost = 0.00645 * 1000  # $0.00645 per SMS * 1000 messages
                            service_id = 'sns_sms_us'
                        elif protocol == 'sqs':
                            delivery_cost = 0.00  # Included in SQS pricing
                            service_id = 'sns_sqs_delivery'
                        elif protocol == 'lambda':
                            delivery_cost = 0.00  # Lambda pricing applies
                            service_id = 'sns_lambda_delivery'
                        elif protocol == 'application':
                            delivery_cost = 0.50  # $0.50 per million deliveries
                            service_id = 'sns_mobile_push'
                        
                        monthly_delivery_cost = delivery_cost  # Assume 1 million deliveries
                        
                        services.append({
                            'service_id': service_id,
                            'resource_id': subscription_arn,
                            'resource_name': f"{topic_name}-{protocol}-{endpoint[:20]}",
                            'region': region,
                            'service_type': 'Application Integration',
                            'estimated_monthly_cost': round(monthly_delivery_cost, 2),
                'count': 1,
                            'details': {
                                'subscription_arn': subscription_arn,
                                'topic_arn': topic_arn,
                                'protocol': protocol,
                                'endpoint': endpoint,
                                'owner': sub.get('Owner'),
                                'confirmation_was_authenticated': sub.get('ConfirmationWasAuthenticated'),
                                'filter_policy': sub.get('SubscriptionAttributes', {}).get('FilterPolicy'),
                                'redrive_policy': sub.get('SubscriptionAttributes', {}).get('RedrivePolicy'),
                                'raw_message_delivery': sub.get('SubscriptionAttributes', {}).get('RawMessageDelivery') == 'true'
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                
            except Exception as e:
                print(f"Error processing SNS topic {topic_arn}: {str(e)}")
        
        # ========== SNS PLATFORM APPLICATIONS (MOBILE PUSH) ==========
        try:
            platform_apps = client.list_platform_applications()
            for app in platform_apps.get('PlatformApplications', []):
                app_arn = app['PlatformApplicationArn']
                
                services.append({
                    'service_id': 'sns_mobile_push',
                    'resource_id': app_arn,
                    'resource_name': app_arn.split('/')[-1],
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Pay per message
                    'details': {
                        'platform_application_arn': app_arn,
                        'attributes': app.get('Attributes', {}),
                        'platform': app.get('Platform'),
                        'tags': get_sns_platform_app_tags(client, app_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SMS PREFERENCES ==========
        try:
            sms_prefs = client.get_sms_attributes()
            if sms_prefs:
                services.append({
                    'service_id': 'sns_sms',
                    'resource_id': f"sms-{region}",
                    'resource_name': 'SMS Settings',
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Pay per message
                    'details': {
                        'attributes': sms_prefs.get('attributes', {}),
                        'sms_sandbox': False,  # Would need to check if in sandbox
                        'monthly_spend_limit': sms_prefs.get('attributes', {}).get('MonthlySpendLimit', 1.0)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering SNS services in {region}: {str(e)}")
    
    return services

def get_sns_topic_tags(client, topic_arn):
    """Get tags for SNS topic"""
    try:
        response = client.list_tags_for_resource(ResourceArn=topic_arn)
        return response.get('Tags', [])
    except:
        return []

def get_sns_platform_app_tags(client, app_arn):
    """Get tags for SNS platform application"""
    try:
        response = client.list_tags_for_resource(ResourceArn=app_arn)
        return response.get('Tags', [])
    except:
        return []

def parse_json(json_str):
    """Parse JSON string safely"""
    if not json_str:
        return None
    try:
        import json
        return json.loads(json_str)
    except:
        return json_str