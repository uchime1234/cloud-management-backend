# discovery/ec2_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_ec2_services(creds, region):
    """Discover all EC2-related services and components"""
    services = []
    try:
        client = boto3.client(
            'ec2',
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
        
        # ========== EC2 INSTANCES ==========
        instances = client.describe_instances()
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_type = instance.get('InstanceType', 'unknown')
                state = instance.get('State', {}).get('Name', 'unknown')
                
                # Estimate cost based on instance type (simplified pricing)
                hourly_rates = {
                    't2.nano': 0.0058, 't2.micro': 0.0116, 't2.small': 0.023,
                    't2.medium': 0.0464, 't2.large': 0.0928, 't2.xlarge': 0.1856,
                    't2.2xlarge': 0.3712,
                    't3.nano': 0.0052, 't3.micro': 0.0104, 't3.small': 0.0208,
                    't3.medium': 0.0416, 't3.large': 0.0832, 't3.xlarge': 0.1664,
                    't3.2xlarge': 0.3328,
                    'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
                    'm5.4xlarge': 0.768, 'm5.8xlarge': 1.536, 'm5.12xlarge': 2.304,
                    'm5.16xlarge': 3.072, 'm5.24xlarge': 4.608,
                    'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
                    'c5.4xlarge': 0.68, 'c5.9xlarge': 1.53, 'c5.12xlarge': 2.04,
                    'c5.18xlarge': 3.06, 'c5.24xlarge': 4.08,
                    'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
                    'r5.4xlarge': 1.008, 'r5.8xlarge': 2.016, 'r5.12xlarge': 3.024,
                    'r5.16xlarge': 4.032, 'r5.24xlarge': 6.048
                }
                
                hourly_rate = hourly_rates.get(instance_type, 0.05)  # Default to $0.05
                monthly_cost = hourly_rate * 730 if state == 'running' else 0
                
                # Add Windows license cost if applicable
                if instance.get('Platform') == 'windows':
                    monthly_cost += 0.04 * 730  # Additional $0.04/hour for Windows
                
                services.append({
                    'service_id': 'ec2_instance',
                    'resource_id': instance['InstanceId'],
                    'resource_name': next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId']),
                    'region': region,
                    'service_type': 'Compute',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance_type,
                        'state': state,
                        'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                        'vpc_id': instance.get('VpcId'),
                        'subnet_id': instance.get('SubnetId'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'platform': instance.get('Platform', 'linux'),
                        'architecture': instance.get('Architecture'),
                        'root_device_type': instance.get('RootDeviceType'),
                        'root_device_name': instance.get('RootDeviceName'),
                        'ebs_optimized': instance.get('EbsOptimized', False),
                        'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                        'tags': instance.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
        # ========== EBS VOLUMES ==========
        volumes = client.describe_volumes()
        for volume in volumes.get('Volumes', []):
            volume_type = volume.get('VolumeType', 'gp2')
            size_gb = volume.get('Size', 0)
            iops = volume.get('Iops', 0)
            
            # Pricing per GB-month
            pricing = {
                'gp3': {'per_gb': 0.08, 'per_iops': 0.00004 * 730},
                'gp2': {'per_gb': 0.10, 'per_iops': 0},
                'io1': {'per_gb': 0.125, 'per_iops': 0.065},
                'io2': {'per_gb': 0.125, 'per_iops': 0.065},
                'st1': {'per_gb': 0.045, 'per_iops': 0},
                'sc1': {'per_gb': 0.025, 'per_iops': 0},
                'standard': {'per_gb': 0.05, 'per_iops': 0}
            }
            
            volume_pricing = pricing.get(volume_type, pricing['gp2'])
            monthly_cost = volume_pricing['per_gb'] * size_gb
            
            if volume_pricing['per_iops'] > 0 and iops > 0:
                if volume_type in ['io1', 'io2']:
                    monthly_cost += volume_pricing['per_iops'] * iops
                elif volume_type == 'gp3':
                    # First 3000 IOPS free for gp3
                    paid_iops = max(0, iops - 3000)
                    monthly_cost += volume_pricing['per_iops'] * paid_iops * 730
            
            services.append({
                'service_id': f"ebs_volume_{volume_type}",
                'resource_id': volume['VolumeId'],
                'resource_name': volume['VolumeId'],
                'region': region,
                'service_type': 'Storage',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'volume_id': volume['VolumeId'],
                    'volume_type': volume_type,
                    'size_gb': size_gb,
                    'iops': iops,
                    'throughput': volume.get('Throughput'),
                    'state': volume.get('State'),
                    'availability_zone': volume.get('AvailabilityZone'),
                    'encrypted': volume.get('Encrypted', False),
                    'kms_key_id': volume.get('KmsKeyId'),
                    'attachments': volume.get('Attachments', []),
                    'snapshot_id': volume.get('SnapshotId'),
                    'creation_time': volume.get('CreateTime').isoformat() if volume.get('CreateTime') else None,
                    'tags': volume.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== EBS SNAPSHOTS ==========
        snapshots = client.describe_snapshots(OwnerIds=['self'])
        for snapshot in snapshots.get('Snapshots', []):
            size_gb = snapshot.get('VolumeSize', 0)
            monthly_cost = 0.05 * size_gb  # $0.05 per GB-month
            
            services.append({
                'service_id': 'ebs_snapshot',
                'resource_id': snapshot['SnapshotId'],
                'resource_name': snapshot['SnapshotId'],
                'region': region,
                'service_type': 'Storage',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'snapshot_id': snapshot['SnapshotId'],
                    'volume_id': snapshot.get('VolumeId'),
                    'volume_size_gb': size_gb,
                    'state': snapshot.get('State'),
                    'description': snapshot.get('Description'),
                    'encrypted': snapshot.get('Encrypted', False),
                    'kms_key_id': snapshot.get('KmsKeyId'),
                    'owner_id': snapshot.get('OwnerId'),
                    'progress': snapshot.get('Progress'),
                    'start_time': snapshot.get('StartTime').isoformat() if snapshot.get('StartTime') else None,
                    'tags': snapshot.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== AMIs ==========
        images = client.describe_images(Owners=['self'])
        for image in images.get('Images', []):
            size_gb = sum(block_device.get('Ebs', {}).get('VolumeSize', 0) 
                         for block_device in image.get('BlockDeviceMappings', []))
            monthly_cost = 0.05 * size_gb  # $0.05 per GB-month
            
            services.append({
                'service_id': 'ami_storage',
                'resource_id': image['ImageId'],
                'resource_name': image.get('Name', image['ImageId']),
                'region': region,
                'service_type': 'Compute',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'image_id': image['ImageId'],
                    'name': image.get('Name'),
                    'description': image.get('Description'),
                    'state': image.get('State'),
                    'architecture': image.get('Architecture'),
                    'platform': image.get('Platform', 'linux'),
                    'creation_date': image.get('CreationDate'),
                    'owner_id': image.get('OwnerId'),
                    'root_device_type': image.get('RootDeviceType'),
                    'virtualization_type': image.get('VirtualizationType'),
                    'tags': image.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== DEDICATED HOSTS ==========
        hosts = client.describe_hosts()
        for host in hosts.get('Hosts', []):
            host_type = host.get('HostProperties', {}).get('InstanceType', 'unknown')
            
            # Pricing for dedicated hosts (simplified)
            host_pricing = {
                'a1': 0.55, 'c5': 1.18, 'm5': 1.30, 'r5': 1.58
            }
            hourly_rate = host_pricing.get(host_type.split('.')[0], 1.00)
            monthly_cost = hourly_rate * 730
            
            services.append({
                'service_id': 'dedicated_host',
                'resource_id': host['HostId'],
                'resource_name': host['HostId'],
                'region': region,
                'service_type': 'Compute',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'host_id': host['HostId'],
                    'host_properties': host.get('HostProperties', {}),
                    'state': host.get('State'),
                    'availability_zone': host.get('AvailabilityZone'),
                    'instances': host.get('Instances', []),
                    'auto_placement': host.get('AutoPlacement'),
                    'host_recovery': host.get('HostRecovery'),
                    'tags': host.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== PLACEMENT GROUPS ==========
        placement_groups = client.describe_placement_groups()
        for pg in placement_groups.get('PlacementGroups', []):
            services.append({
                'service_id': 'placement_group',
                'resource_id': pg['GroupName'],
                'resource_name': pg['GroupName'],
                'region': region,
                'service_type': 'Compute',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'group_name': pg.get('GroupName'),
                    'strategy': pg.get('Strategy'),
                    'state': pg.get('State'),
                    'tags': pg.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== CAPACITY RESERVATIONS ==========
        capacity_reservations = client.describe_capacity_reservations()
        for cr in capacity_reservations.get('CapacityReservations', []):
            services.append({
                'service_id': 'capacity_reservation',
                'resource_id': cr['CapacityReservationId'],
                'resource_name': cr['CapacityReservationId'],
                'region': region,
                'service_type': 'Compute',
                'estimated_monthly_cost': 0.00,
                'count': 1,  # Instance pricing applies
                'details': {
                    'capacity_reservation_id': cr['CapacityReservationId'],
                    'instance_type': cr.get('InstanceType'),
                    'availability_zone': cr.get('AvailabilityZone'),
                    'instance_count': cr.get('TotalInstanceCount'),
                    'available_instance_count': cr.get('AvailableInstanceCount'),
                    'state': cr.get('State'),
                    'tenancy': cr.get('Tenancy'),
                    'tags': cr.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== LAUNCH TEMPLATES ==========
        launch_templates = client.describe_launch_templates()
        for lt in launch_templates.get('LaunchTemplates', []):
            services.append({
                'service_id': 'ec2_launch_template',
                'resource_id': lt['LaunchTemplateId'],
                'resource_name': lt['LaunchTemplateName'],
                'region': region,
                'service_type': 'Compute',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'launch_template_id': lt['LaunchTemplateId'],
                    'launch_template_name': lt['LaunchTemplateName'],
                    'created_by': lt.get('CreatedBy'),
                    'create_time': lt.get('CreateTime').isoformat() if lt.get('CreateTime') else None,
                    'default_version_number': lt.get('DefaultVersionNumber'),
                    'latest_version_number': lt.get('LatestVersionNumber'),
                    'tags': lt.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
    except Exception as e:
        print(f"Error discovering EC2 services in {region}: {str(e)}")
    
    return services