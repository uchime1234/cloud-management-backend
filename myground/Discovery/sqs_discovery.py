# discovery/sqs_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_sqs_services(creds, region):
    """Discover SQS queues and related resources"""
    services = []
    try:
        client = boto3.client(
            'sqs',
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
        
        # ========== SQS QUEUES ==========
        queues = client.list_queues()
        if 'QueueUrls' in queues:
            for queue_url in queues['QueueUrls']:
                try:
                    # Get queue attributes
                    attributes = client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    attrs = attributes.get('Attributes', {})
                    
                    queue_name = queue_url.split('/')[-1]
                    queue_arn = attrs.get('QueueArn')
                    fifo_queue = queue_name.endswith('.fifo')
                    fifo_queue = fifo_queue or attrs.get('FifoQueue') == 'true'
                    
                    # Approximate number of messages
                    approx_messages = int(attrs.get('ApproximateNumberOfMessages', 0))
                    approx_messages_delayed = int(attrs.get('ApproximateNumberOfMessagesDelayed', 0))
                    approx_messages_not_visible = int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0))
                    
                    # SQS pricing: $0.40 per million requests (standard), $0.50 per million (FIFO)
                    # Assume 1 million requests per month
                    if fifo_queue:
                        monthly_cost = 0.50
                        service_id = 'sqs_fifo_request'
                    else:
                        monthly_cost = 0.40
                        service_id = 'sqs_standard_request'
                    
                    # Add KMS cost if enabled
                    kms_key_id = attrs.get('KmsMasterKeyId')
                    if kms_key_id and kms_key_id != 'alias/aws/sqs':
                        # Additional KMS API charges
                        monthly_cost += 0.024  # $0.024 per million requests
                    
                    services.append({
                        'service_id': service_id,
                        'resource_id': queue_arn,
                        'resource_name': queue_name,
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'queue_url': queue_url,
                            'queue_arn': queue_arn,
                            'queue_name': queue_name,
                            'fifo_queue': fifo_queue,
                            'visibility_timeout': attrs.get('VisibilityTimeout'),
                            'message_retention_period': attrs.get('MessageRetentionPeriod'),
                            'maximum_message_size': attrs.get('MaximumMessageSize'),
                            'delay_seconds': attrs.get('DelaySeconds'),
                            'receive_message_wait_time_seconds': attrs.get('ReceiveMessageWaitTimeSeconds'),
                            'redrive_policy': parse_redrive_policy(attrs.get('RedrivePolicy')),
                            'redrive_allow_policy': attrs.get('RedriveAllowPolicy'),
                            'dead_letter_target_arn': parse_redrive_policy_dead_letter_arn(attrs.get('RedrivePolicy')),
                            'content_based_deduplication': attrs.get('ContentBasedDeduplication') == 'true',
                            'deduplication_scope': attrs.get('DeduplicationScope'),
                            'fifo_throughput_limit': attrs.get('FifoThroughputLimit'),
                            'kms_master_key_id': kms_key_id,
                            'kms_data_key_reuse_period_seconds': attrs.get('KmsDataKeyReusePeriodSeconds'),
                            'approximate_number_of_messages': approx_messages,
                            'approximate_number_of_messages_delayed': approx_messages_delayed,
                            'approximate_number_of_messages_not_visible': approx_messages_not_visible,
                            'created_timestamp': attrs.get('CreatedTimestamp'),
                            'last_modified_timestamp': attrs.get('LastModifiedTimestamp'),
                            'sqs_managed_sse_enabled': attrs.get('SqsManagedSseEnabled') == 'true',
                            'tags': get_sqs_tags(client, queue_url)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
                    # ========== SQS DEAD LETTER QUEUE ==========
                    redrive_policy = attrs.get('RedrivePolicy')
                    if redrive_policy:
                        import json
                        try:
                            policy = json.loads(redrive_policy)
                            if 'deadLetterTargetArn' in policy:
                                services.append({
                                    'service_id': 'sqs_dead_letter_queue',
                                    'resource_id': f"{queue_arn}/dlq",
                                    'resource_name': f"{queue_name}-dlq",
                                    'region': region,
                                    'service_type': 'Application Integration',
                                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Costs included in queue
                                    'details': {
                                        'source_queue_arn': queue_arn,
                                        'source_queue_name': queue_name,
                                        'dead_letter_target_arn': policy['deadLetterTargetArn'],
                                        'max_receive_count': policy.get('maxReceiveCount')
                                    },
                                    'discovered_at': datetime.now(timezone.utc).isoformat()
                                })
                        except:
                            pass
                            
                except Exception as e:
                    print(f"Error processing SQS queue {queue_url}: {str(e)}")
        
    except Exception as e:
        print(f"Error discovering SQS services in {region}: {str(e)}")
    
    return services

def get_sqs_tags(client, queue_url):
    """Get tags for SQS queue"""
    try:
        response = client.list_queue_tags(QueueUrl=queue_url)
        return response.get('Tags', {})
    except:
        return {}

def parse_redrive_policy(redrive_policy):
    """Parse redrive policy JSON string"""
    if not redrive_policy:
        return None
    try:
        import json
        return json.loads(redrive_policy)
    except:
        return None

def parse_redrive_policy_dead_letter_arn(redrive_policy):
    """Extract dead letter target ARN from redrive policy"""
    policy = parse_redrive_policy(redrive_policy)
    if policy:
        return policy.get('deadLetterTargetArn')
    return None