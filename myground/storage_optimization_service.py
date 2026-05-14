# storage_optimization_service.py
import boto3
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from decimal import Decimal
import logging

from myground.models import (
    AWSAccount,
    StorageOptimizationFinding,
    DuplicateStorageFinding,
    ResourceUsageSnapshot,
    CpuUsageSnapshot,
    StorageOptimizationSummary
)

logger = logging.getLogger(__name__)

def assume_role_for_account(aws_account):
    """Helper to assume role and return credentials"""
    sts = boto3.client(
        'sts',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    response = sts.assume_role(
        RoleArn=aws_account.role_arn,
        RoleSessionName="StorageOptimizationScan",
        ExternalId=str(aws_account.external_id)
    )
    return response["Credentials"]

def save_scan_results_to_db(user, aws_account, scan_results):
    """Save all scan results to database"""
    from .models import (
        StorageOptimizationFinding, DuplicateStorageFinding,
        ResourceUsageSnapshot, CpuUsageSnapshot, StorageOptimizationSummary
    )
    
    with transaction.atomic():
        # Mark old findings as inactive (soft delete)
        StorageOptimizationFinding.objects.filter(
            aws_account=aws_account,
            status='active'
        ).update(status='resolved')
        
        # Save EBS volume findings
        for vol in scan_results.get('ebs_volumes', {}).get('unattached_volumes', []):
            StorageOptimizationFinding.objects.create(
                user=user,
                aws_account=aws_account,
                resource_type='ebs_volume',
                resource_id=vol['volume_id'],
                resource_name=f"EBS Volume {vol['volume_id']}",
                region=vol.get('region', 'unknown'),
                size_gb=vol.get('size_gb', 0),
                estimated_monthly_cost=vol.get('monthly_cost', 0),
                confidence_score=95,
                reason="This EBS volume is not attached to any EC2 instance, meaning it's not being used but still incurring storage costs.",
                recommendation=f"Delete this unattached volume to save ${vol.get('monthly_cost', 0)}/month. First verify you don't need the data, then you can delete it from the EC2 console.",
                severity='high' if vol.get('monthly_cost', 0) > 50 else 'medium',
                status='active',
                metadata={
                    'size_gb': vol.get('size_gb'),
                    'volume_type': vol.get('volume_type'),
                    'scan_timestamp': timezone.now().isoformat()
                }
            )
        
        # Save Elastic IP findings
        for ip in scan_results.get('elastic_ips', {}).get('items', []):
            is_associated = ip.get('is_associated', False)
            if not is_associated:
                StorageOptimizationFinding.objects.create(
                    user=user,
                    aws_account=aws_account,
                    resource_type='elastic_ip',
                    resource_id=ip.get('public_ip', 'unknown'),
                    resource_name=f"Elastic IP {ip.get('public_ip', 'unknown')}",
                    region='global',
                    estimated_monthly_cost=3.65,  # ~$0.005 per hour * 730 hours
                    confidence_score=100,
                    reason="This Elastic IP is allocated but not associated with any resource. AWS charges for unattached Elastic IPs.",
                    recommendation="Release this Elastic IP to stop incurring charges. If you need to keep it, associate it with an EC2 instance or NAT gateway.",
                    severity='medium',
                    status='active',
                    metadata={
                        'allocation_id': ip.get('allocation_id'),
                        'domain': ip.get('domain')
                    }
                )
        
        # Save RDS idle instance findings
        for rds in scan_results.get('idle_rds_instances', {}).get('items', []):
            if rds.get('avg_cpu', 100) < 10:
                StorageOptimizationFinding.objects.create(
                    user=user,
                    aws_account=aws_account,
                    resource_type='rds_instance',
                    resource_id=rds['instance_id'],
                    resource_name=f"RDS {rds['instance_id']}",
                    region=aws_account.account_id[:10],
                    estimated_monthly_cost=rds.get('monthly_cost', 0),
                    confidence_score=85,
                    reason=f"This RDS instance has very low CPU utilization ({rds.get('avg_cpu', 0)}% average over 7 days), suggesting it's underutilized.",
                    recommendation=f"Consider downsizing to a smaller instance class or using Aurora Serverless. Potential savings: ${rds.get('monthly_cost', 0)}/month.",
                    severity='medium' if rds.get('monthly_cost', 0) > 30 else 'low',
                    status='active',
                    metadata={
                        'instance_class': rds.get('instance_class'),
                        'avg_cpu': rds.get('avg_cpu'),
                        'storage_gb': rds.get('storage_gb')
                    }
                )
        
        # Save unused AMI findings
        for ami in scan_results.get('unused_amis', {}).get('items', []):
            StorageOptimizationFinding.objects.create(
                user=user,
                aws_account=aws_account,
                resource_type='unused_ami',
                resource_id=ami['ami_id'],
                resource_name=ami['name'],
                region='global',
                size_gb=ami.get('volume_size_gb', 0),
                estimated_monthly_cost=ami.get('monthly_cost', 0),
                confidence_score=90,
                reason=f"This AMI is {ami.get('age_days', 0)} days old and not used by any running EC2 instance.",
                recommendation=f"Deregister this unused AMI to save ${ami.get('monthly_cost', 0)}/month in EBS snapshot storage costs.",
                severity='low',
                status='active',
                metadata={
                    'age_days': ami.get('age_days'),
                    'volume_size_gb': ami.get('volume_size_gb')
                }
            )
        
        # Save duplicate snapshot findings
        for dup in scan_results.get('duplicate_snapshots', {}).get('items', []):
            DuplicateStorageFinding.objects.create(
                user=user,
                aws_account=aws_account,
                duplicate_type='redundant_backup',
                group_id=dup['volume_id'],
                group_name=f"Snapshots for volume {dup['volume_id']}",
                resources=dup.get('redundant_snapshots', []),
                total_wasted_size_gb=dup.get('total_size_gb', 0),
                estimated_savings=dup.get('monthly_cost', 0),
                reason=f"You have {dup.get('total_snapshots', 0)} snapshots for this volume. Keeping more than 2-3 is usually redundant.",
                recommendation=f"Delete {dup.get('redundant_count', 0)} old snapshots to save ${dup.get('monthly_cost', 0)}/month. Keep only the most recent 2-3 snapshots.",
                status='active'
            )
        
        # Save daily resource usage snapshot
        today = timezone.now().date()
        
        # EBS snapshot
        ResourceUsageSnapshot.objects.update_or_create(
            user=user,
            aws_account=aws_account,
            service_name='ebs',
            region='global',
            snapshot_date=today,
            defaults={
                'usage_value': scan_results.get('ebs_volumes', {}).get('total', 0),
                'unit': 'volumes',
                'metadata': {
                    'unattached': scan_results.get('ebs_volumes', {}).get('unattached', 0),
                    'total_size_gb': sum(v.get('size_gb', 0) for v in scan_results.get('ebs_volumes', {}).get('unattached_volumes', []))
                }
            }
        )
        
        # RDS snapshot
        ResourceUsageSnapshot.objects.update_or_create(
            user=user,
            aws_account=aws_account,
            service_name='rds',
            region='global',
            snapshot_date=today,
            defaults={
                'usage_value': scan_results.get('rds_instances', {}).get('total', 0),
                'unit': 'instances',
                'metadata': {
                    'idle_count': scan_results.get('idle_rds_instances', {}).get('count', 0)
                }
            }
        )
        
        # Snapshot storage snapshot
        ResourceUsageSnapshot.objects.update_or_create(
            user=user,
            aws_account=aws_account,
            service_name='snapshots',
            region='global',
            snapshot_date=today,
            defaults={
                'usage_value': scan_results.get('snapshots', {}).get('total', 0),
                'unit': 'snapshots',
                'metadata': {
                    'old_snapshots': scan_results.get('snapshots', {}).get('old', 0)
                }
            }
        )
        
        # Update summary
        summary, _ = StorageOptimizationSummary.objects.update_or_create(
            user=user,
            aws_account=aws_account,
            defaults={
                'total_idle_resources': scan_results.get('total_findings', 0),
                'total_estimated_waste': scan_results.get('total_potential_savings', 0),
                'duplicate_candidates': scan_results.get('duplicate_snapshots', {}).get('count', 0),
                'duplicate_savings': sum(d.get('monthly_cost', 0) for d in scan_results.get('duplicate_snapshots', {}).get('items', [])),
                'idle_cpu_resources': scan_results.get('idle_rds_instances', {}).get('count', 0),
                'cpu_savings': sum(r.get('monthly_cost', 0) for r in scan_results.get('idle_rds_instances', {}).get('items', [])),
                'summary_data': {
                    'ebs_unattached': scan_results.get('ebs_volumes', {}).get('unattached', 0),
                    'elastic_ips_unused': scan_results.get('elastic_ips', {}).get('unused', 0),
                    'old_snapshots': scan_results.get('snapshots', {}).get('old', 0),
                    'unused_amis': scan_results.get('unused_amis', {}).get('count', 0),
                    'duplicate_groups': scan_results.get('duplicate_snapshots', {}).get('count', 0)
                }
            }
        )
        
        logger.info(f"Saved {StorageOptimizationFinding.objects.filter(aws_account=aws_account, status='active').count()} findings to database")
    
    return True

def get_cached_scan_results(user, aws_account, force_refresh=False):
    """Get cached scan results from database"""
    from .models import StorageOptimizationFinding, DuplicateStorageFinding, StorageOptimizationSummary
    
    # Check if we have recent findings (less than 24 hours old)
    recent_findings = StorageOptimizationFinding.objects.filter(
        aws_account=aws_account,
        status='active',
        detected_at__gte=timezone.now() - timedelta(hours=24)
    )
    
    if recent_findings.exists() and not force_refresh:
        logger.info(f"Using cached findings: {recent_findings.count()} active findings")
        
        # Build response from database
        summary = StorageOptimizationSummary.objects.filter(aws_account=aws_account).first()
        
        return {
            'success': True,
            'cached': True,
            'total_findings': recent_findings.count(),
            'total_potential_savings': float(summary.total_estimated_waste) if summary else 0,
            'ebs_volumes': {
                'total': ResourceUsageSnapshot.objects.filter(
                    aws_account=aws_account,
                    service_name='ebs',
                    snapshot_date=timezone.now().date()
                ).first().usage_value if ResourceUsageSnapshot.objects.filter(aws_account=aws_account, service_name='ebs').exists() else 0,
                'unattached': recent_findings.filter(resource_type='ebs_volume').count(),
                'unattached_volumes': [
                    {
                        'volume_id': f.resource_id,
                        'size_gb': float(f.size_gb) if f.size_gb else 0,
                        'monthly_cost': float(f.estimated_monthly_cost),
                        'region': f.region
                    }
                    for f in recent_findings.filter(resource_type='ebs_volume')
                ],
                'items': []
            },
            'idle_rds_instances': {
                'count': recent_findings.filter(resource_type='rds_instance').count(),
                'items': [
                    {
                        'instance_id': f.resource_id,
                        'instance_class': f.metadata.get('instance_class', 'unknown'),
                        'avg_cpu': f.metadata.get('avg_cpu', 0),
                        'storage_gb': f.metadata.get('storage_gb', 0),
                        'monthly_cost': float(f.estimated_monthly_cost)
                    }
                    for f in recent_findings.filter(resource_type='rds_instance')
                ]
            },
            'elastic_ips': {
                'total': ResourceUsageSnapshot.objects.filter(
                    aws_account=aws_account,
                    service_name='snapshots'
                ).first().usage_value if ResourceUsageSnapshot.objects.filter(aws_account=aws_account, service_name='snapshots').exists() else 0,
                'unused': recent_findings.filter(resource_type='elastic_ip').count(),
                'items': []
            },
            'snapshots': {
                'total': 0,
                'old': recent_findings.filter(resource_type='ebs_snapshot').count(),
                'items': []
            },
            'unused_amis': {
                'count': recent_findings.filter(resource_type='unused_ami').count(),
                'items': [
                    {
                        'ami_id': f.resource_id,
                        'name': f.resource_name,
                        'age_days': f.metadata.get('age_days', 0),
                        'volume_size_gb': float(f.size_gb) if f.size_gb else 0,
                        'monthly_cost': float(f.estimated_monthly_cost)
                    }
                    for f in recent_findings.filter(resource_type='unused_ami')
                ]
            },
            'duplicate_snapshots': {
                'count': DuplicateStorageFinding.objects.filter(aws_account=aws_account, status='active').count(),
                'items': [
                    {
                        'volume_id': d.group_id,
                        'total_snapshots': len(d.resources) + 2,
                        'redundant_count': len(d.resources),
                        'total_size_gb': float(d.total_wasted_size_gb) if d.total_wasted_size_gb else 0,
                        'monthly_cost': float(d.estimated_savings)
                    }
                    for d in DuplicateStorageFinding.objects.filter(aws_account=aws_account, status='active')
                ]
            }
        }
    
    return None

def test_ebs_volumes(role_arn, external_id):
    """List all EBS volumes"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        volumes = ec2.describe_volumes()
        return {
            'success': True,
            'count': len(volumes.get('Volumes', [])),
            'volumes': volumes.get('Volumes', [])
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'volumes': []}

def test_elastic_ips(role_arn, external_id):
    """List all Elastic IPs"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        addresses = ec2.describe_addresses()
        addresses_list = addresses.get('Addresses', [])
        unused_count = sum(1 for addr in addresses_list if not (addr.get('InstanceId') or addr.get('NetworkInterfaceId')))
        
        return {
            'success': True,
            'count': len(addresses_list),
            'unused': unused_count,
            'addresses': addresses_list
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'unused': 0, 'addresses': []}

def test_rds_instances(role_arn, external_id):
    """List all RDS instances"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        rds = boto3.client(
            'rds',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        instances = rds.describe_db_instances()
        return {
            'success': True,
            'count': len(instances.get('DBInstances', [])),
            'instances': instances.get('DBInstances', [])
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'instances': []}

def test_snapshots(role_arn, external_id):
    """List all EBS snapshots"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        snapshots = ec2.describe_snapshots(OwnerIds=['self'])
        snapshots_list = snapshots.get('Snapshots', [])
        
        cutoff_date = timezone.now() - timedelta(days=30)
        old_count = 0
        for snap in snapshots_list:
            start_time = snap.get('StartTime')
            if start_time and start_time.replace(tzinfo=timezone.utc) < cutoff_date:
                old_count += 1
        
        return {
            'success': True,
            'count': len(snapshots_list),
            'old_count': old_count,
            'snapshots': snapshots_list
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'old_count': 0, 'snapshots': []}

def test_unattached_ebs_volumes_only(role_arn, external_id):
    """Find unattached EBS volumes only"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        volumes = ec2.describe_volumes()
        unattached_volumes = []
        
        for vol in volumes.get('Volumes', []):
            attachments = vol.get('Attachments', [])
            is_attached = len(attachments) > 0
            if not is_attached:
                size_gb = vol.get('Size', 0)
                volume_type = vol.get('VolumeType', 'gp2')
                
                # Calculate monthly cost
                if volume_type == 'gp3':
                    price_per_gb = 0.08
                elif volume_type == 'gp2':
                    price_per_gb = 0.10
                else:
                    price_per_gb = 0.10
                
                monthly_cost = size_gb * price_per_gb
                unattached_volumes.append({
                    'volume_id': vol['VolumeId'],
                    'size_gb': size_gb,
                    'volume_type': volume_type,
                    'monthly_cost': round(monthly_cost, 2),
                    'region': vol.get('AvailabilityZone', '')[:-1] if vol.get('AvailabilityZone') else 'us-east-1'
                })
        
        return {
            'success': True,
            'count': len(unattached_volumes),
            'unattached_volumes': unattached_volumes
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'unattached_volumes': []}

def test_duplicate_snapshots(role_arn, external_id):
    """Find duplicate snapshots"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        snapshots = ec2.describe_snapshots(OwnerIds=['self'])
        
        # Group snapshots by volume ID
        snapshots_by_volume = {}
        for snap in snapshots.get('Snapshots', []):
            volume_id = snap.get('VolumeId')
            if volume_id:
                if volume_id not in snapshots_by_volume:
                    snapshots_by_volume[volume_id] = []
                snapshots_by_volume[volume_id].append(snap)
        
        duplicate_groups = []
        for volume_id, vol_snapshots in snapshots_by_volume.items():
            if len(vol_snapshots) > 3:
                # Sort by date (oldest first)
                vol_snapshots.sort(key=lambda x: x.get('StartTime', datetime.min))
                redundant_snapshots = vol_snapshots[:-2]
                total_size = sum(s.get('VolumeSize', 0) for s in redundant_snapshots)
                monthly_cost = total_size * 0.05
                
                duplicate_groups.append({
                    'volume_id': volume_id,
                    'total_snapshots': len(vol_snapshots),
                    'redundant_count': len(redundant_snapshots),
                    'redundant_snapshots': [s['SnapshotId'] for s in redundant_snapshots],
                    'total_size_gb': total_size,
                    'monthly_cost': round(monthly_cost, 2)
                })
        
        return {
            'success': True,
            'count': len(duplicate_groups),
            'duplicate_groups': duplicate_groups
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'duplicate_groups': []}

def test_idle_rds_instances(role_arn, external_id):
    """Find idle RDS instances (low CPU usage)"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        rds = boto3.client(
            'rds',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        cloudwatch = boto3.client(
            'cloudwatch',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        instances = rds.describe_db_instances()
        idle_instances = []
        
        for inst in instances.get('DBInstances', []):
            instance_id = inst['DBInstanceIdentifier']
            instance_state = inst.get('DBInstanceStatus', '')
            
            if instance_state == 'available':
                end_time = timezone.now()
                start_time = end_time - timedelta(days=7)
                
                try:
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    datapoints = metrics.get('Datapoints', [])
                    if datapoints:
                        avg_cpu = sum(dp['Average'] for dp in datapoints) / len(datapoints)
                        if avg_cpu < 10:
                            instance_class = inst.get('DBInstanceClass', 'unknown')
                            allocated_storage = inst.get('AllocatedStorage', 0)
                            storage_cost = allocated_storage * 0.115
                            
                            if 'micro' in instance_class.lower():
                                compute_cost = 12
                            elif 'small' in instance_class.lower():
                                compute_cost = 25
                            else:
                                compute_cost = 50
                            
                            total_cost = storage_cost + compute_cost
                            idle_instances.append({
                                'instance_id': instance_id,
                                'instance_class': instance_class,
                                'avg_cpu': round(avg_cpu, 2),
                                'storage_gb': allocated_storage,
                                'monthly_cost': round(total_cost, 2)
                            })
                except Exception:
                    pass
        
        return {
            'success': True,
            'count': len(idle_instances),
            'idle_instances': idle_instances
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'idle_instances': []}

def test_unused_amis(role_arn, external_id):
    """Find unused AMIs"""
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="StorageScan",
            ExternalId=str(external_id)
        )
        credentials = response["Credentials"]
        
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        # Get all AMIs owned by the account
        images = ec2.describe_images(Owners=['self'])
        
        # Get all running instances
        instances = ec2.describe_instances()
        used_amis = set()
        
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance.get('ImageId'):
                    used_amis.add(instance['ImageId'])
        
        unused_amis = []
        for image in images.get('Images', []):
            image_id = image['ImageId']
            if image_id not in used_amis:
                creation_date = image.get('CreationDate', '')
                if creation_date:
                    try:
                        from dateutil import parser
                        creation_date_parsed = parser.parse(creation_date)
                        age_days = (timezone.now() - creation_date_parsed).days
                        if age_days > 30:
                            volume_size = 0
                            for block in image.get('BlockDeviceMappings', []):
                                if 'Ebs' in block:
                                    volume_size += block['Ebs'].get('VolumeSize', 0)
                            monthly_cost = volume_size * 0.05
                            unused_amis.append({
                                'ami_id': image_id,
                                'name': image.get('Name', 'Unnamed'),
                                'age_days': age_days,
                                'volume_size_gb': volume_size,
                                'monthly_cost': round(monthly_cost, 2)
                            })
                    except Exception:
                        pass
        
        return {
            'success': True,
            'count': len(unused_amis),
            'unused_amis': unused_amis
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'unused_amis': []}


# storage_optimization_service.py - Add these functions

import boto3
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from decimal import Decimal
import logging
import hashlib
import json

from myground.models import (
    AWSAccount,
    StorageOptimizationFinding,
    DuplicateStorageFinding,
    ResourceUsageSnapshot,
    CpuUsageSnapshot,
    StorageOptimizationSummary
)

logger = logging.getLogger(__name__)

def assume_role_for_account(aws_account):
    """Helper to assume role and return credentials"""
    sts = boto3.client(
        'sts',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    response = sts.assume_role(
        RoleArn=aws_account.role_arn,
        RoleSessionName="StorageOptimizationScan",
        ExternalId=str(aws_account.external_id)
    )
    return response["Credentials"]

# storage_optimization_service.py - Fix the get_cached_storage_results function

def get_cached_storage_results(user, aws_account, force_refresh=False):
    """
    Get cached storage results from database
    Only makes AWS API calls if force_refresh=True or no cache exists
    """
    from .models import StorageOptimizationFinding, DuplicateStorageFinding, ResourceUsageSnapshot, StorageOptimizationSummary
    
    # If force_refresh is True, return None to force a fresh scan
    if force_refresh:
        print("🔄 Force refresh requested - skipping storage cache")
        return None
    
    # Check if we have cached results (any age - we keep them until deleted)
    cached_findings = StorageOptimizationFinding.objects.filter(
        aws_account=aws_account,
        status='active'
    )
    
    if cached_findings.exists():
        logger.info(f"📦 Using cached storage findings: {cached_findings.count()} items")
        
        # Get summary from database
        summary = StorageOptimizationSummary.objects.filter(aws_account=aws_account).first()
        
        # Get snapshots
        ebs_snapshot = ResourceUsageSnapshot.objects.filter(
            aws_account=aws_account,
            service_name='ebs'
        ).order_by('-snapshot_date').first()
        
        elastic_ip_snapshot = ResourceUsageSnapshot.objects.filter(
            aws_account=aws_account,
            service_name='elastic_ips'
        ).order_by('-snapshot_date').first()
        
        rds_snapshot = ResourceUsageSnapshot.objects.filter(
            aws_account=aws_account,
            service_name='rds'
        ).order_by('-snapshot_date').first()
        
        snapshots_snapshot = ResourceUsageSnapshot.objects.filter(
            aws_account=aws_account,
            service_name='snapshots'
        ).order_by('-snapshot_date').first()
        
        # Build response from cached data
        return {
            'success': True,
            'cached': True,
            'total_findings': cached_findings.count(),
            'total_potential_savings': float(summary.total_estimated_waste) if summary else 0,
            'ebs_volumes': {
                'total': ebs_snapshot.usage_value if ebs_snapshot else 0,
                'unattached': cached_findings.filter(resource_type='ebs_volume').count(),
                'unattached_volumes': [
                    {
                        'volume_id': f.resource_id,
                        'size_gb': float(f.size_gb) if f.size_gb else 0,
                        'monthly_cost': float(f.estimated_monthly_cost),
                        'region': f.region,
                        'volume_type': f.metadata.get('volume_type', 'gp2') if f.metadata else 'gp2'
                    }
                    for f in cached_findings.filter(resource_type='ebs_volume')
                ],
                'items': []
            },
            'elastic_ips': {
                'total': elastic_ip_snapshot.usage_value if elastic_ip_snapshot else 0,
                'unused': cached_findings.filter(resource_type='elastic_ip').count(),
                'items': [
                    {
                        'public_ip': f.resource_id,
                        'allocation_id': f.metadata.get('allocation_id', '') if f.metadata else '',
                        'domain': f.metadata.get('domain', '') if f.metadata else '',
                        'is_associated': False
                    }
                    for f in cached_findings.filter(resource_type='elastic_ip')
                ]
            },
            'rds_instances': {
                'total': rds_snapshot.usage_value if rds_snapshot else 0,
                'items': []
            },
            'snapshots': {
                'total': snapshots_snapshot.usage_value if snapshots_snapshot else 0,
                'old': cached_findings.filter(resource_type='ebs_snapshot').count(),
                'items': [
                    {
                        'snapshot_id': f.resource_id,
                        'volume_size': float(f.size_gb) if f.size_gb else 0,
                        'age_days': f.metadata.get('age_days', 0) if f.metadata else 0,
                        'monthly_cost': float(f.estimated_monthly_cost)
                    }
                    for f in cached_findings.filter(resource_type='ebs_snapshot')
                ]
            },
            'idle_rds_instances': {
                'count': cached_findings.filter(resource_type='rds_instance').count(),
                'items': [
                    {
                        'instance_id': f.resource_id,
                        'instance_class': f.metadata.get('instance_class', 'unknown') if f.metadata else 'unknown',
                        'avg_cpu': f.metadata.get('avg_cpu', 0) if f.metadata else 0,
                        'storage_gb': f.metadata.get('storage_gb', 0) if f.metadata else 0,
                        'monthly_cost': float(f.estimated_monthly_cost)
                    }
                    for f in cached_findings.filter(resource_type='rds_instance')
                ]
            },
            'unused_amis': {
                'count': cached_findings.filter(resource_type='unused_ami').count(),
                'items': [
                    {
                        'ami_id': f.resource_id,
                        'name': f.resource_name,
                        'age_days': f.metadata.get('age_days', 0) if f.metadata else 0,
                        'volume_size_gb': float(f.size_gb) if f.size_gb else 0,
                        'monthly_cost': float(f.estimated_monthly_cost)
                    }
                    for f in cached_findings.filter(resource_type='unused_ami')
                ]
            },
            'duplicate_snapshots': {
                'count': DuplicateStorageFinding.objects.filter(aws_account=aws_account, status='active').count(),
                'items': [
                    {
                        'volume_id': d.group_id,
                        'total_snapshots': len(d.resources) + 2,
                        'redundant_count': len(d.resources),
                        'total_size_gb': float(d.total_wasted_size_gb) if d.total_wasted_size_gb else 0,
                        'monthly_cost': float(d.estimated_savings)
                    }
                    for d in DuplicateStorageFinding.objects.filter(aws_account=aws_account, status='active')
                ]
            }
        }
    
    return None

# storage_optimization_service.py - Add this function if not present

def clear_all_storage_data(aws_account):
    """
    Clear all storage optimization data from database
    Called when user clicks "Clear Cache" button
    """
    from .models import StorageOptimizationFinding, DuplicateStorageFinding, ResourceUsageSnapshot, StorageOptimizationSummary
    
    with transaction.atomic():
        # Delete all findings
        findings_count = StorageOptimizationFinding.objects.filter(aws_account=aws_account).delete()[0]
        duplicates_count = DuplicateStorageFinding.objects.filter(aws_account=aws_account).delete()[0]
        snapshots_count = ResourceUsageSnapshot.objects.filter(aws_account=aws_account).delete()[0]
        summary_count = StorageOptimizationSummary.objects.filter(aws_account=aws_account).delete()[0]
        
        logger.info(f"🗑️ Cleared storage data: {findings_count} findings, {duplicates_count} duplicates, {snapshots_count} snapshots")
        
        return {
            'findings_deleted': findings_count,
            'duplicates_deleted': duplicates_count,
            'snapshots_deleted': snapshots_count,
            'total_deleted': findings_count + duplicates_count + snapshots_count + summary_count
        }

# storage_optimization_service.py - Make sure this function is complete

def save_scan_results_to_db(user, aws_account, scan_results):
    """Save all scan results to database (overwrites existing)"""
    from .models import (
        StorageOptimizationFinding, DuplicateStorageFinding,
        ResourceUsageSnapshot, CpuUsageSnapshot, StorageOptimizationSummary
    )
    
    with transaction.atomic():
        # Delete OLD data first (complete refresh)
        StorageOptimizationFinding.objects.filter(aws_account=aws_account).delete()
        DuplicateStorageFinding.objects.filter(aws_account=aws_account).delete()
        ResourceUsageSnapshot.objects.filter(aws_account=aws_account).delete()
        CpuUsageSnapshot.objects.filter(aws_account=aws_account).delete()
        StorageOptimizationSummary.objects.filter(aws_account=aws_account).delete()
        
        # Save EBS volume findings
        for vol in scan_results.get('ebs_volumes', {}).get('unattached_volumes', []):
            StorageOptimizationFinding.objects.create(
                user=user,
                aws_account=aws_account,
                resource_type='ebs_volume',
                resource_id=vol['volume_id'],
                resource_name=f"EBS Volume {vol['volume_id']}",
                region=vol.get('region', 'unknown'),
                size_gb=vol.get('size_gb', 0),
                estimated_monthly_cost=vol.get('monthly_cost', 0),
                confidence_score=95,
                reason="This EBS volume is not attached to any EC2 instance, meaning it's not being used but still incurring storage costs.",
                recommendation=f"Delete this unattached volume to save ${vol.get('monthly_cost', 0)}/month.",
                severity='high' if vol.get('monthly_cost', 0) > 50 else 'medium',
                status='active',
                metadata={
                    'size_gb': vol.get('size_gb'),
                    'volume_type': vol.get('volume_type'),
                    'scan_timestamp': timezone.now().isoformat()
                }
            )
        
        # Save Elastic IP findings
        for ip in scan_results.get('elastic_ips', {}).get('items', []):
            if not ip.get('is_associated', False):
                StorageOptimizationFinding.objects.create(
                    user=user,
                    aws_account=aws_account,
                    resource_type='elastic_ip',
                    resource_id=ip.get('public_ip', 'unknown'),
                    resource_name=f"Elastic IP {ip.get('public_ip', 'unknown')}",
                    region='global',
                    estimated_monthly_cost=3.65,
                    confidence_score=100,
                    reason="This Elastic IP is allocated but not associated with any resource. AWS charges for unattached Elastic IPs.",
                    recommendation="Release this Elastic IP to stop incurring charges.",
                    severity='medium',
                    status='active',
                    metadata={
                        'allocation_id': ip.get('allocation_id'),
                        'domain': ip.get('domain')
                    }
                )
        
        # Save idle RDS findings
        for rds in scan_results.get('idle_rds_instances', {}).get('items', []):
            StorageOptimizationFinding.objects.create(
                user=user,
                aws_account=aws_account,
                resource_type='rds_instance',
                resource_id=rds['instance_id'],
                resource_name=f"RDS {rds['instance_id']}",
                region=aws_account.account_id[:10],
                estimated_monthly_cost=rds.get('monthly_cost', 0),
                confidence_score=85,
                reason=f"This RDS instance has very low CPU utilization ({rds.get('avg_cpu', 0)}% average over 7 days).",
                recommendation=f"Consider downsizing or stopping this instance. Potential savings: ${rds.get('monthly_cost', 0)}/month.",
                severity='medium' if rds.get('monthly_cost', 0) > 30 else 'low',
                status='active',
                metadata={
                    'instance_class': rds.get('instance_class'),
                    'avg_cpu': rds.get('avg_cpu'),
                    'storage_gb': rds.get('storage_gb')
                }
            )
        
        # Save old snapshot findings
        for snap in scan_results.get('snapshots', {}).get('items', []):
            if snap.get('age_days', 0) > 30:
                StorageOptimizationFinding.objects.create(
                    user=user,
                    aws_account=aws_account,
                    resource_type='ebs_snapshot',
                    resource_id=snap['snapshot_id'],
                    resource_name=f"Snapshot {snap['snapshot_id'][:20]}",
                    region='global',
                    size_gb=snap.get('volume_size', 0),
                    estimated_monthly_cost=snap.get('monthly_cost', 0),
                    confidence_score=90,
                    reason=f"This snapshot is {snap.get('age_days', 0)} days old.",
                    recommendation=f"Delete this old snapshot to save ${snap.get('monthly_cost', 0)}/month.",
                    severity='low',
                    status='active',
                    metadata={
                        'age_days': snap.get('age_days'),
                        'volume_size': snap.get('volume_size')
                    }
                )
        
        # Save unused AMI findings
        for ami in scan_results.get('unused_amis', {}).get('items', []):
            StorageOptimizationFinding.objects.create(
                user=user,
                aws_account=aws_account,
                resource_type='unused_ami',
                resource_id=ami['ami_id'],
                resource_name=ami['name'],
                region='global',
                size_gb=ami.get('volume_size_gb', 0),
                estimated_monthly_cost=ami.get('monthly_cost', 0),
                confidence_score=90,
                reason=f"This AMI is {ami.get('age_days', 0)} days old and not used.",
                recommendation=f"Deregister this unused AMI to save ${ami.get('monthly_cost', 0)}/month.",
                severity='low',
                status='active',
                metadata={
                    'age_days': ami.get('age_days'),
                    'volume_size_gb': ami.get('volume_size_gb')
                }
            )
        
        # Save duplicate snapshot findings
        for dup in scan_results.get('duplicate_snapshots', {}).get('items', []):
            DuplicateStorageFinding.objects.create(
                user=user,
                aws_account=aws_account,
                duplicate_type='redundant_backup',
                group_id=dup['volume_id'],
                group_name=f"Snapshots for volume {dup['volume_id']}",
                resources=dup.get('redundant_snapshots', []),
                total_wasted_size_gb=dup.get('total_size_gb', 0),
                estimated_savings=dup.get('monthly_cost', 0),
                reason=f"You have {dup.get('total_snapshots', 0)} snapshots for this volume.",
                recommendation=f"Delete {dup.get('redundant_count', 0)} old snapshots to save ${dup.get('monthly_cost', 0)}/month.",
                status='active'
            )
        
        # Update summary
        total_savings = sum(float(f.estimated_monthly_cost) for f in StorageOptimizationFinding.objects.filter(aws_account=aws_account))
        
        StorageOptimizationSummary.objects.create(
            user=user,
            aws_account=aws_account,
            total_idle_resources=StorageOptimizationFinding.objects.filter(aws_account=aws_account).count(),
            total_estimated_waste=total_savings,
            duplicate_candidates=DuplicateStorageFinding.objects.filter(aws_account=aws_account).count(),
            duplicate_savings=sum(float(d.estimated_savings) for d in DuplicateStorageFinding.objects.filter(aws_account=aws_account)),
            idle_cpu_resources=StorageOptimizationFinding.objects.filter(aws_account=aws_account, resource_type='rds_instance').count(),
            cpu_savings=sum(float(f.estimated_monthly_cost) for f in StorageOptimizationFinding.objects.filter(aws_account=aws_account, resource_type='rds_instance')),
            summary_data={
                'ebs_unattached': StorageOptimizationFinding.objects.filter(aws_account=aws_account, resource_type='ebs_volume').count(),
                'elastic_ips_unused': StorageOptimizationFinding.objects.filter(aws_account=aws_account, resource_type='elastic_ip').count(),
                'old_snapshots': StorageOptimizationFinding.objects.filter(aws_account=aws_account, resource_type='ebs_snapshot').count(),
                'unused_amis': StorageOptimizationFinding.objects.filter(aws_account=aws_account, resource_type='unused_ami').count(),
                'duplicate_groups': DuplicateStorageFinding.objects.filter(aws_account=aws_account).count()
            }
        )
        
        logger.info(f"💾 Saved {StorageOptimizationFinding.objects.filter(aws_account=aws_account).count()} storage findings to database")
        return True