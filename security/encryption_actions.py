# security/encryption_actions.py

import boto3
from datetime import datetime
from django.conf import settings
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

def get_credentials(aws_account):
    """Get AWS credentials for the account"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName="EncryptionAction",
            ExternalId=str(aws_account.external_id),
            DurationSeconds=3600
        )
        return response["Credentials"]
    except Exception as e:
        logger.error(f"Error assuming role: {e}")
        return None


def enable_s3_bucket_encryption(aws_account, bucket_name, kms_key_id=None):
    """Enable encryption on an S3 bucket"""
    from .models import EncryptionAction
    
    credentials = get_credentials(aws_account)
    if not credentials:
        return {'success': False, 'error': 'Failed to assume role'}
    
    s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    try:
        # Determine encryption configuration
        if kms_key_id:
            encryption_config = {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': kms_key_id
                        },
                        'BucketKeyEnabled': True
                    }
                ]
            }
        else:
            encryption_config = {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        
        # Apply encryption
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_config
        )
        
        # Also block public access for better security
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        return {
            'success': True,
            'message': f'Successfully enabled encryption on bucket {bucket_name}',
            'encryption_type': 'KMS' if kms_key_id else 'AES-256'
        }
        
    except Exception as e:
        logger.error(f"Error enabling S3 encryption: {e}")
        return {'success': False, 'error': str(e)}


def enable_sqs_queue_encryption(aws_account, queue_url, kms_key_id=None):
    """Enable encryption on an SQS queue"""
    credentials = get_credentials(aws_account)
    if not credentials:
        return {'success': False, 'error': 'Failed to assume role'}
    
    sqs_client = boto3.client(
        'sqs',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=settings.AWS_REGION
    )
    
    try:
        # Get current queue attributes
        attributes = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['All']
        ).get('Attributes', {})
        
        # Prepare new attributes
        if not kms_key_id:
            # Use AWS managed KMS key
            kms_key_id = 'alias/aws/sqs'
        
        new_attributes = {
            'KmsMasterKeyId': kms_key_id,
            'KmsDataKeyReusePeriodSeconds': '300'
        }
        
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes=new_attributes
        )
        
        return {
            'success': True,
            'message': f'Successfully enabled encryption on SQS queue',
            'encryption_type': 'KMS'
        }
        
    except Exception as e:
        logger.error(f"Error enabling SQS encryption: {e}")
        return {'success': False, 'error': str(e)}


def enable_sns_topic_encryption(aws_account, topic_arn, kms_key_id=None):
    """Enable encryption on an SNS topic"""
    credentials = get_credentials(aws_account)
    if not credentials:
        return {'success': False, 'error': 'Failed to assume role'}
    
    sns_client = boto3.client(
        'sns',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=settings.AWS_REGION
    )
    
    try:
        if not kms_key_id:
            kms_key_id = 'alias/aws/sns'
        
        sns_client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName='KmsMasterKeyId',
            AttributeValue=kms_key_id
        )
        
        return {
            'success': True,
            'message': f'Successfully enabled encryption on SNS topic',
            'encryption_type': 'KMS'
        }
        
    except Exception as e:
        logger.error(f"Error enabling SNS encryption: {e}")
        return {'success': False, 'error': str(e)}


def enable_ebs_volume_encryption(aws_account, volume_id, region):
    """Create an encrypted snapshot and volume from unencrypted volume"""
    credentials = get_credentials(aws_account)
    if not credentials:
        return {'success': False, 'error': 'Failed to assume role'}
    
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    try:
        # Create an encrypted snapshot
        snapshot = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f'Encrypted snapshot created for migration - {datetime.now().isoformat()}'
        )
        
        snapshot_id = snapshot['SnapshotId']
        
        # Create encrypted volume from snapshot
        encrypted_volume = ec2_client.create_volume(
            SnapshotId=snapshot_id,
            Encrypted=True,
            AvailabilityZone=snapshot['AvailabilityZone']
        )
        
        return {
            'success': True,
            'requires_manual': True,
            'message': 'Created encrypted snapshot and volume. Manual replacement required.',
            'snapshot_id': snapshot_id,
            'encrypted_volume_id': encrypted_volume['VolumeId'],
            'migration_steps': [
                '1. Stop the EC2 instance',
                f'2. Detach the original volume ({volume_id})',
                f'3. Attach the new encrypted volume ({encrypted_volume["VolumeId"]})',
                '4. Start the EC2 instance',
                '5. Verify data integrity',
                '6. Delete the original volume'
            ]
        }
        
    except Exception as e:
        logger.error(f"Error enabling EBS encryption: {e}")
        return {'success': False, 'error': str(e)}


def enable_default_ebs_encryption(aws_account, region):
    """Enable default EBS encryption for the region"""
    credentials = get_credentials(aws_account)
    if not credentials:
        return {'success': False, 'error': 'Failed to assume role'}
    
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    try:
        ec2_client.enable_ebs_encryption_by_default()
        
        return {
            'success': True,
            'message': f'Enabled default EBS encryption for region {region}',
            'encryption_type': 'EBS Default Encryption'
        }
        
    except Exception as e:
        logger.error(f"Error enabling default EBS encryption: {e}")
        return {'success': False, 'error': str(e)}


def enable_lambda_environment_encryption(aws_account, function_name, region, kms_key_id=None):
    """Enable KMS encryption for Lambda environment variables"""
    credentials = get_credentials(aws_account)
    if not credentials:
        return {'success': False, 'error': 'Failed to assume role'}
    
    lambda_client = boto3.client(
        'lambda',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    try:
        if not kms_key_id:
            kms_key_id = 'alias/aws/lambda'
        
        # Get current function configuration
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        
        # Update with KMS key
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            KMSKeyArn=kms_key_id
        )
        
        return {
            'success': True,
            'message': f'Enabled KMS encryption for Lambda function {function_name}',
            'encryption_type': 'KMS'
        }
        
    except Exception as e:
        logger.error(f"Error enabling Lambda encryption: {e}")
        return {'success': False, 'error': str(e)}


def execute_encryption_action(action_id):
    """Execute a pending encryption action"""
    from .models import EncryptionAction
    
    try:
        action = EncryptionAction.objects.get(id=action_id)
        action.status = 'in_progress'
        action.started_at = timezone.now()
        action.save()
        
        # Get AWS account
        aws_account = action.aws_account
        
        result = None
        
        if action.action_type == 'enable_bucket_encryption':
            result = enable_s3_bucket_encryption(
                aws_account,
                action.resource_id,
                action.action_params.get('kms_key_id')
            )
            
        elif action.action_type == 'enable_queue_encryption':
            # Construct queue URL from resource_id and region
            queue_url = f"https://sqs.{action.region}.amazonaws.com/{action.action_params.get('account_id', '')}/{action.resource_id}"
            result = enable_sqs_queue_encryption(
                aws_account,
                queue_url,
                action.action_params.get('kms_key_id')
            )
            
        elif action.action_type == 'enable_topic_encryption':
            topic_arn = f"arn:aws:sns:{action.region}:{action.action_params.get('account_id', '')}:{action.resource_id}"
            result = enable_sns_topic_encryption(
                aws_account,
                topic_arn,
                action.action_params.get('kms_key_id')
            )
            
        elif action.action_type == 'migrate_encrypted_snapshot':
            result = enable_ebs_volume_encryption(
                aws_account,
                action.resource_id,
                action.region
            )
            
        elif action.action_type == 'enable_default_encryption':
            result = enable_default_ebs_encryption(aws_account, action.region)
            
        elif action.action_type == 'enable_kms':
            result = enable_lambda_environment_encryption(
                aws_account,
                action.resource_id,
                action.region,
                action.action_params.get('kms_key_id')
            )
        
        if result and result.get('success'):
            action.status = 'completed'
            action.status_message = result.get('message', 'Action completed successfully')
            action.result_details = result
            action.requires_migration = result.get('requires_manual', False)
            if result.get('migration_steps'):
                action.migration_workflow = {'steps': result['migration_steps']}
        else:
            action.status = 'failed'
            action.status_message = result.get('error', 'Action failed') if result else 'Unknown error'
            action.error_message = result.get('error', 'Unknown error')
        
        action.completed_at = timezone.now()
        action.save()
        
        return result
        
    except Exception as e:
        logger.error(f"Error executing encryption action: {e}")
        action.status = 'failed'
        action.status_message = str(e)
        action.error_message = str(e)
        action.completed_at = timezone.now()
        action.save()
        return {'success': False, 'error': str(e)}