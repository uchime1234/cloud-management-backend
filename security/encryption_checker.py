# security/encryption_checker.py

import boto3
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def assume_role_for_account(aws_account):
    """Assume role and return credentials"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName="EncryptionChecker",
            ExternalId=str(aws_account.external_id),
            DurationSeconds=3600
        )
        return response["Credentials"]
    except Exception as e:
        logger.error(f"Error assuming role: {e}")
        return None


def check_ec2_volume_encryption(ec2_client, region):
    """Check EC2 EBS volume encryption"""
    findings = []
    try:
        volumes = ec2_client.describe_volumes()
        for volume in volumes.get('Volumes', []):
            volume_id = volume['VolumeId']
            size_gb = volume.get('Size', 0)
            encrypted = volume.get('Encrypted', False)
            kms_key_id = volume.get('KmsKeyId', '')
            
            # Get volume name from tags
            volume_name = volume_id
            for tag in volume.get('Tags', []):
                if tag.get('Key') == 'Name':
                    volume_name = tag.get('Value')
                    break
            
            # Check if attached to production instance
            environment = 'unknown'
            for tag in volume.get('Tags', []):
                if tag.get('Key') == 'Environment' or tag.get('Key') == 'env':
                    environment = tag.get('Value').lower()
                    break
            
            severity = 'HIGH' if not encrypted and environment == 'production' else 'MEDIUM' if not encrypted else 'LOW'
            risk_score = 80 if not encrypted and environment == 'production' else 60 if not encrypted else 10
            
            fix_recommendation = "Enable EBS encryption by default for the region, or create an encrypted snapshot and replace the volume." if not encrypted else "Already encrypted - no action needed."
            
            findings.append({
                'resource_type': 'ec2_volume',
                'resource_id': volume_id,
                'resource_name': volume_name,
                'region': region,
                'is_encrypted': encrypted,
                'encryption_type': 'KMS' if encrypted else 'None',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'environment': environment,
                'size_gb': size_gb,
                'business_risk': f"Unencrypted {'production' if environment == 'production' else ''} volume {volume_name} could expose sensitive data if accessed by unauthorized parties.",
                'fix_recommendation': fix_recommendation,
                'fix_difficulty': 'medium'
            })
    except Exception as e:
        logger.error(f"Error checking EC2 volumes: {e}")
    return findings


def check_ebs_snapshot_encryption(ec2_client, region):
    """Check EBS snapshot encryption"""
    findings = []
    try:
        snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])
        for snapshot in snapshots.get('Snapshots', []):
            snapshot_id = snapshot['SnapshotId']
            volume_size = snapshot.get('VolumeSize', 0)
            encrypted = snapshot.get('Encrypted', False)
            kms_key_id = snapshot.get('KmsKeyId', '')
            start_time = snapshot.get('StartTime')
            
            age_days = (datetime.now(start_time.tzinfo) - start_time).days if start_time else 0
            
            # Older snapshots are less critical
            severity = 'HIGH' if not encrypted and age_days < 30 else 'MEDIUM' if not encrypted else 'LOW'
            risk_score = 70 if not encrypted and age_days < 30 else 50 if not encrypted else 10
            
            findings.append({
                'resource_type': 'ebs_snapshot',
                'resource_id': snapshot_id,
                'resource_name': f"Snapshot {snapshot_id[:8]}",
                'region': region,
                'is_encrypted': encrypted,
                'encryption_type': 'KMS' if encrypted else 'None',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'size_gb': volume_size,
                'business_risk': f"Unencrypted snapshot {'from less than 30 days ago' if age_days < 30 else ''} could expose data if shared.",
                'fix_recommendation': "Create an encrypted copy of the snapshot and delete the unencrypted original." if not encrypted else "Already encrypted.",
                'fix_difficulty': 'easy'
            })
    except Exception as e:
        logger.error(f"Error checking EBS snapshots: {e}")
    return findings


def check_rds_encryption(rds_client, region):
    """Check RDS instance encryption"""
    findings = []
    try:
        instances = rds_client.describe_db_instances()
        for instance in instances.get('DBInstances', []):
            instance_id = instance['DBInstanceIdentifier']
            engine = instance.get('Engine', '')
            storage_encrypted = instance.get('StorageEncrypted', False)
            kms_key_id = instance.get('KmsKeyId', '')
            instance_class = instance.get('DBInstanceClass', '')
            
            # Check if production (based on tags or instance class)
            environment = 'production' if 'prod' in instance_id.lower() else 'unknown'
            
            severity = 'CRITICAL' if not storage_encrypted and environment == 'production' else 'HIGH' if not storage_encrypted else 'LOW'
            risk_score = 95 if not storage_encrypted and environment == 'production' else 75 if not storage_encrypted else 10
            
            findings.append({
                'resource_type': 'rds',
                'resource_id': instance_id,
                'resource_name': instance_id,
                'region': region,
                'is_encrypted': storage_encrypted,
                'encryption_type': 'KMS' if storage_encrypted else 'None',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'environment': environment,
                'business_risk': f"Production database {instance_id} is unencrypted. All data at risk if storage is compromised." if not storage_encrypted and environment == 'production' else f"Database {instance_id} is unencrypted.",
                'fix_recommendation': "Create an encrypted read replica, promote it, and migrate traffic. Or restore from encrypted snapshot." if not storage_encrypted else "Already encrypted.",
                'fix_difficulty': 'hard'
            })
    except Exception as e:
        logger.error(f"Error checking RDS: {e}")
    return findings


def check_s3_encryption(s3_client):
    """Check S3 bucket encryption"""
    findings = []
    try:
        buckets = s3_client.list_buckets()
        for bucket in buckets.get('Buckets', []):
            bucket_name = bucket['Name']
            creation_date = bucket.get('CreationDate')
            
            # Check bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if rules:
                    is_encrypted = True
                    encryption_type = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'KMS')
                    kms_key_id = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID', '')
                else:
                    is_encrypted = False
                    encryption_type = 'None'
                    kms_key_id = ''
            except s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    is_encrypted = False
                    encryption_type = 'None'
                    kms_key_id = ''
                else:
                    raise
            
            # Check bucket for public access (increase severity)
            is_public = False
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        is_public = True
                        break
            except:
                pass
            
            severity = 'CRITICAL' if not is_encrypted and is_public else 'HIGH' if not is_encrypted else 'MEDIUM' if is_public else 'LOW'
            risk_score = 90 if not is_encrypted and is_public else 70 if not is_encrypted else 40 if is_public else 10
            
            findings.append({
                'resource_type': 's3_bucket',
                'resource_id': bucket_name,
                'resource_name': bucket_name,
                'region': 'global',
                'is_encrypted': is_encrypted,
                'encryption_type': encryption_type,
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'size_gb': None,
                'business_risk': f"S3 bucket {bucket_name} is {'publicly accessible and ' if is_public else ''}unencrypted. Data could be exposed or stolen." if not is_encrypted else f"S3 bucket {bucket_name} is public but encrypted.",
                'fix_recommendation': "Enable default encryption on the bucket and block public access." if not is_encrypted else "Block public access to prevent data exposure." if is_public else "Already secure.",
                'fix_difficulty': 'easy'
            })
    except Exception as e:
        logger.error(f"Error checking S3: {e}")
    return findings


def check_dynamodb_encryption(dynamodb_client, region):
    """Check DynamoDB table encryption"""
    findings = []
    try:
        tables = dynamodb_client.list_tables()
        for table_name in tables.get('TableNames', []):
            table_desc = dynamodb_client.describe_table(TableName=table_name)
            table = table_desc.get('Table', {})
            
            # Check encryption
            sse_desc = table.get('SSEDescription', {})
            is_encrypted = sse_desc.get('Status') == 'ENABLED'
            encryption_type = sse_desc.get('SSEType', 'None')
            kms_key_id = sse_desc.get('KMSMasterKeyArn', '')
            
            severity = 'HIGH' if not is_encrypted else 'LOW'
            risk_score = 80 if not is_encrypted else 10
            
            findings.append({
                'resource_type': 'dynamodb_table',
                'resource_id': table_name,
                'resource_name': table_name,
                'region': region,
                'is_encrypted': is_encrypted,
                'encryption_type': encryption_type,
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'size_gb': table.get('TableSizeBytes', 0) / (1024 * 1024 * 1024) if table.get('TableSizeBytes') else 0,
                'business_risk': f"DynamoDB table {table_name} is unencrypted. NoSQL data could be exposed.",
                'fix_recommendation': "Enable default encryption on the table. Note: You may need to recreate the table.",
                'fix_difficulty': 'hard'
            })
    except Exception as e:
        logger.error(f"Error checking DynamoDB: {e}")
    return findings


def check_lambda_encryption(lambda_client, region):
    """Check Lambda function environment variable encryption"""
    findings = []
    try:
        functions = lambda_client.list_functions()
        for function in functions.get('Functions', []):
            function_name = function['FunctionName']
            
            # Check if environment variables exist and are encrypted
            env_vars = function.get('Environment', {}).get('Variables', {})
            is_encrypted = function.get('Environment', {}).get('Error') is None
            
            # Check KMS key
            kms_key_arn = function.get('KMSKeyArn', '')
            
            severity = 'MEDIUM' if not is_encrypted and env_vars else 'LOW'
            risk_score = 60 if not is_encrypted and env_vars else 20
            
            findings.append({
                'resource_type': 'lambda_function',
                'resource_id': function_name,
                'resource_name': function_name,
                'region': region,
                'is_encrypted': is_encrypted,
                'encryption_type': 'KMS' if kms_key_arn else 'None',
                'kms_key_id': kms_key_arn,
                'is_customer_managed_key': bool(kms_key_arn),
                'severity': severity,
                'risk_score': risk_score,
                'business_risk': f"Lambda function {function_name} has unencrypted environment variables that may contain secrets.",
                'fix_recommendation': "Configure a KMS key for environment variable encryption.",
                'fix_difficulty': 'easy'
            })
    except Exception as e:
        logger.error(f"Error checking Lambda: {e}")
    return findings


def check_sqs_encryption(sqs_client, region):
    """Check SQS queue encryption"""
    findings = []
    try:
        queues = sqs_client.list_queues()
        queue_urls = queues.get('QueueUrls', [])
        
        for queue_url in queue_urls:
            queue_name = queue_url.split('/')[-1]
            attributes = sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['All']
            ).get('Attributes', {})
            
            kms_key_id = attributes.get('KmsMasterKeyId', '')
            is_encrypted = bool(kms_key_id)
            
            severity = 'MEDIUM' if not is_encrypted else 'LOW'
            risk_score = 55 if not is_encrypted else 10
            
            findings.append({
                'resource_type': 'sqs_queue',
                'resource_id': queue_name,
                'resource_name': queue_name,
                'region': region,
                'is_encrypted': is_encrypted,
                'encryption_type': 'KMS' if is_encrypted else 'None',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'business_risk': f"SQS queue {queue_name} is unencrypted. Messages could be exposed.",
                'fix_recommendation': "Enable SSE-SQS encryption with a KMS key.",
                'fix_difficulty': 'easy'
            })
    except Exception as e:
        logger.error(f"Error checking SQS: {e}")
    return findings


def check_sns_encryption(sns_client, region):
    """Check SNS topic encryption"""
    findings = []
    try:
        topics = sns_client.list_topics()
        for topic in topics.get('Topics', []):
            topic_arn = topic['TopicArn']
            topic_name = topic_arn.split(':')[-1]
            
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn).get('Attributes', {})
            kms_key_id = attributes.get('KmsMasterKeyId', '')
            is_encrypted = bool(kms_key_id)
            
            severity = 'MEDIUM' if not is_encrypted else 'LOW'
            risk_score = 55 if not is_encrypted else 10
            
            findings.append({
                'resource_type': 'sns_topic',
                'resource_id': topic_name,
                'resource_name': topic_name,
                'region': region,
                'is_encrypted': is_encrypted,
                'encryption_type': 'KMS' if is_encrypted else 'None',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'business_risk': f"SNS topic {topic_name} is unencrypted. Messages could be exposed.",
                'fix_recommendation': "Enable server-side encryption with a KMS key.",
                'fix_difficulty': 'easy'
            })
    except Exception as e:
        logger.error(f"Error checking SNS: {e}")
    return findings


def check_efs_encryption(efs_client, region):
    """Check EFS filesystem encryption"""
    findings = []
    try:
        filesystems = efs_client.describe_file_systems()
        for fs in filesystems.get('FileSystems', []):
            fs_id = fs['FileSystemId']
            fs_name = fs.get('Name', fs_id)
            encrypted = fs.get('Encrypted', False)
            kms_key_id = fs.get('KmsKeyId', '')
            
            severity = 'HIGH' if not encrypted else 'LOW'
            risk_score = 75 if not encrypted else 10
            
            findings.append({
                'resource_type': 'efs_filesystem',
                'resource_id': fs_id,
                'resource_name': fs_name,
                'region': region,
                'is_encrypted': encrypted,
                'encryption_type': 'KMS' if encrypted else 'None',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'size_gb': fs.get('SizeInBytes', {}).get('Value', 0) / (1024 * 1024 * 1024),
                'business_risk': f"EFS filesystem {fs_name} is unencrypted. All files could be exposed.",
                'fix_recommendation': "Create a new encrypted filesystem and migrate data.",
                'fix_difficulty': 'hard'
            })
    except Exception as e:
        logger.error(f"Error checking EFS: {e}")
    return findings


def check_elasticache_encryption(elasticache_client, region):
    """Check ElastiCache cluster encryption"""
    findings = []
    try:
        clusters = elasticache_client.describe_cache_clusters()
        for cluster in clusters.get('CacheClusters', []):
            cluster_id = cluster['CacheClusterId']
            engine = cluster.get('Engine', 'redis')
            
            # Check encryption (Redis only)
            is_encrypted = False
            if engine == 'redis':
                is_encrypted = cluster.get('AtRestEncryptionEnabled', False) or cluster.get('TransitEncryptionEnabled', False)
            
            severity = 'HIGH' if not is_encrypted and engine == 'redis' else 'MEDIUM' if not is_encrypted else 'LOW'
            risk_score = 80 if not is_encrypted and engine == 'redis' else 60 if not is_encrypted else 10
            
            findings.append({
                'resource_type': 'elasticache_cluster',
                'resource_id': cluster_id,
                'resource_name': cluster_id,
                'region': region,
                'is_encrypted': is_encrypted,
                'encryption_type': 'At-rest/In-transit' if is_encrypted else 'None',
                'kms_key_id': '',
                'is_customer_managed_key': False,
                'severity': severity,
                'risk_score': risk_score,
                'business_risk': f"Redis cache cluster {cluster_id} is unencrypted. Cached sensitive data could be exposed.",
                'fix_recommendation': "Create a new cluster with encryption enabled.",
                'fix_difficulty': 'hard'
            })
    except Exception as e:
        logger.error(f"Error checking ElastiCache: {e}")
    return findings


def check_secretsmanager_encryption(secretsmanager_client, region):
    """Check Secrets Manager secret encryption"""
    findings = []
    try:
        secrets = secretsmanager_client.list_secrets()
        for secret in secrets.get('SecretList', []):
            secret_id = secret['Name']
            kms_key_id = secret.get('KmsKeyId', '')
            is_encrypted = True  # Secrets Manager always encrypts
            
            severity = 'LOW'
            risk_score = 5
            
            findings.append({
                'resource_type': 'secretsmanager_secret',
                'resource_id': secret_id,
                'resource_name': secret_id,
                'region': region,
                'is_encrypted': is_encrypted,
                'encryption_type': 'KMS',
                'kms_key_id': kms_key_id,
                'is_customer_managed_key': bool(kms_key_id and 'alias' in kms_key_id.lower()),
                'severity': severity,
                'risk_score': risk_score,
                'business_risk': f"Secret {secret_id} is encrypted by default, but consider using a customer-managed key for compliance.",
                'fix_recommendation': "Use a customer-managed KMS key for regulatory compliance.",
                'fix_difficulty': 'easy'
            })
    except Exception as e:
        logger.error(f"Error checking Secrets Manager: {e}")
    return findings


def scan_encryption_status(aws_account, force_refresh=False):
    """Main function to scan encryption status across all resources"""
    from .models import EncryptionFinding, EncryptionSummary, EncryptionScanCache
    
    # Get or create cache record
    cache, _ = EncryptionScanCache.objects.get_or_create(aws_account=aws_account)
    
    if cache.scan_in_progress and not force_refresh:
        return {'status': 'scan_in_progress', 'message': 'Scan already in progress'}
    
    cache.scan_in_progress = True
    cache.save()
    
    start_time = timezone.now()
    
    try:
        # Assume role
        credentials = assume_role_for_account(aws_account)
        if not credentials:
            cache.scan_in_progress = False
            cache.save()
            return {'error': 'Failed to assume role'}
        
        all_findings = []
        regions = [settings.AWS_REGION, 'us-east-1', 'us-west-2', 'eu-west-1']
        
        # Scan functions by service
        scan_functions = []
        
        # EC2 and EBS (region-specific)
        for region in regions:
            ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('ec2_volumes', lambda: check_ec2_volume_encryption(ec2_client, region)))
            scan_functions.append(('ebs_snapshots', lambda: check_ebs_snapshot_encryption(ec2_client, region)))
            
            # RDS
            rds_client = boto3.client(
                'rds',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('rds', lambda: check_rds_encryption(rds_client, region)))
            
            # DynamoDB
            dynamodb_client = boto3.client(
                'dynamodb',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('dynamodb', lambda: check_dynamodb_encryption(dynamodb_client, region)))
            
            # Lambda
            lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('lambda', lambda: check_lambda_encryption(lambda_client, region)))
            
            # SQS
            sqs_client = boto3.client(
                'sqs',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('sqs', lambda: check_sqs_encryption(sqs_client, region)))
            
            # SNS
            sns_client = boto3.client(
                'sns',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('sns', lambda: check_sns_encryption(sns_client, region)))
            
            # EFS
            efs_client = boto3.client(
                'efs',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('efs', lambda: check_efs_encryption(efs_client, region)))
            
            # ElastiCache
            elasticache_client = boto3.client(
                'elasticache',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('elasticache', lambda: check_elasticache_encryption(elasticache_client, region)))
            
            # Secrets Manager
            secretsmanager_client = boto3.client(
                'secretsmanager',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            scan_functions.append(('secretsmanager', lambda: check_secretsmanager_encryption(secretsmanager_client, region)))
        
        # S3 (global)
        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        all_findings.extend(check_s3_encryption(s3_client))
        
        # Execute scan functions
        for name, func in scan_functions:
            try:
                findings = func()
                all_findings.extend(findings)
                cache.resources_scanned += len(findings)
                cache.save()
            except Exception as e:
                logger.error(f"Error scanning {name}: {e}")
        
        # Delete old findings
        EncryptionFinding.objects.filter(aws_account=aws_account).delete()
        
        # Save new findings
        for finding_data in all_findings:
            EncryptionFinding.objects.create(
                user_id=aws_account.user_id,
                aws_account=aws_account,
                **finding_data
            )
        
        # Calculate summary
        total_resources = len(all_findings)
        encrypted_resources = len([f for f in all_findings if f['is_encrypted']])
        unencrypted_resources = total_resources - encrypted_resources
        encryption_coverage = int((encrypted_resources / total_resources) * 100) if total_resources > 0 else 0
        
        critical_count = len([f for f in all_findings if f['severity'] == 'CRITICAL'])
        high_count = len([f for f in all_findings if f['severity'] == 'HIGH'])
        medium_count = len([f for f in all_findings if f['severity'] == 'MEDIUM'])
        low_count = len([f for f in all_findings if f['severity'] == 'LOW'])
        
        # Resource breakdown by type
        resource_breakdown = {}
        for finding in all_findings:
            rtype = finding['resource_type']
            if rtype not in resource_breakdown:
                resource_breakdown[rtype] = {'total': 0, 'encrypted': 0, 'unencrypted': 0}
            resource_breakdown[rtype]['total'] += 1
            if finding['is_encrypted']:
                resource_breakdown[rtype]['encrypted'] += 1
            else:
                resource_breakdown[rtype]['unencrypted'] += 1
        
        # Recently encrypted (mock - would need historical tracking)
        recently_encrypted = []
        
        # Save summary
        EncryptionSummary.objects.update_or_create(
            aws_account=aws_account,
            defaults={
                'user_id': aws_account.user_id,
                'total_resources': total_resources,
                'encrypted_resources': encrypted_resources,
                'unencrypted_resources': unencrypted_resources,
                'encryption_coverage': encryption_coverage,
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'resource_breakdown': resource_breakdown,
                'total_kms_keys': 0,
                'customer_managed_keys': 0,
                'aws_managed_keys': 0,
                'recently_encrypted': recently_encrypted,
                'last_scan_at': timezone.now()
            }
        )
        
        scan_duration = (timezone.now() - start_time).total_seconds()
        
        cache.last_full_scan = timezone.now()
        cache.scan_in_progress = False
        cache.total_resources = total_resources
        cache.save()
        
        return {
            'success': True,
            'total_resources': total_resources,
            'encrypted_resources': encrypted_resources,
            'unencrypted_resources': unencrypted_resources,
            'encryption_coverage': encryption_coverage,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'scan_duration': scan_duration,
            'cached': False
        }
        
    except Exception as e:
        logger.error(f"Error scanning encryption: {e}")
        cache.scan_in_progress = False
        cache.save()
        return {'error': str(e)}


def get_cached_encryption_summary(aws_account):
    """Get cached encryption summary"""
    from .models import EncryptionSummary
    
    try:
        summary = EncryptionSummary.objects.get(aws_account=aws_account)
        return {
            'success': True,
            'cached': True,
            'summary': {
                'total_resources': summary.total_resources,
                'encrypted_resources': summary.encrypted_resources,
                'unencrypted_resources': summary.unencrypted_resources,
                'encryption_coverage': summary.encryption_coverage,
                'critical_count': summary.critical_count,
                'high_count': summary.high_count,
                'medium_count': summary.medium_count,
                'low_count': summary.low_count,
                'resource_breakdown': summary.resource_breakdown,
                'last_scan_at': summary.last_scan_at.isoformat()
            }
        }
    except EncryptionSummary.DoesNotExist:
        return {'success': False, 'message': 'No scan data available'}


def get_encryption_findings(aws_account, severity_filter=None):
    """Get encryption findings with optional severity filter"""
    from .models import EncryptionFinding
    
    findings = EncryptionFinding.objects.filter(aws_account=aws_account)
    
    if severity_filter and severity_filter != 'all':
        findings = findings.filter(severity=severity_filter)
    
    return {
        'success': True,
        'cached': True,
        'total_findings': findings.count(),
        'findings': [
            {
                'id': f.id,
                'resource_type': f.resource_type,
                'resource_type_display': dict(EncryptionFinding.RESOURCE_TYPES).get(f.resource_type, f.resource_type),
                'resource_id': f.resource_id,
                'resource_name': f.resource_name,
                'region': f.region,
                'is_encrypted': f.is_encrypted,
                'encryption_type': f.encryption_type,
                'kms_key_id': f.kms_key_id,
                'severity': f.severity,
                'risk_score': f.risk_score,
                'business_risk': f.business_risk,
                'fix_recommendation': f.fix_recommendation,
                'fix_difficulty': f.fix_difficulty,
                'detected_at': f.detected_at.isoformat()
            }
            for f in findings
        ]
    }