# low_level_tracker.py
import boto3
from datetime import datetime
from django.utils import timezone
from botocore.exceptions import ClientError

from .models import AWSAccount, LowLevelServiceSnapshot, LowLevelServiceResource, LowLevelServiceDefinition, LowLevelServiceCategory, LowLevelServiceCostHistory
from django.core.cache import cache
import concurrent.futures
import time
from botocore.config import Config
import urllib3
from decimal import Decimal

# Disable warnings (development only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# COMPLETE LOW-LEVEL SERVICE CATEGORIES & PRICING
# ============================================================
# EVERY AWS SERVICE WITH ALL LOW-LEVEL COMPONENTS
# ============================================================

LOW_LEVEL_SERVICES = {
    # ========== NETWORKING & CONTENT DELIVERY ==========
    'vpc': {
        'name': 'Virtual Private Cloud',
        'low_level_services': [
            {
                'id': 'internet_gateway',
                'name': 'Internet Gateway',
                'description': 'VPC internet connectivity',
                'price_per_hour': 0.00,
                'unit': 'per gateway'
            },
            {
                'id': 'nat_gateway',
                'name': 'NAT Gateway',
                'description': 'Outbound internet for private subnets',
                'price_per_hour': 0.045,
                'price_per_gb': 0.045,
                'unit': 'per gateway + data processed'
            },
            {
                'id': 'vpc_endpoint',
                'name': 'VPC Endpoints',
                'description': 'Private AWS service access',
                'price_per_hour': 0.01,
                'price_per_gb': 0.01,
                'unit': 'per endpoint-hour + data processed'
            },
            {
                'id': 'vpc_peering',
                'name': 'VPC Peering',
                'description': 'Cross-VPC connectivity',
                'price_per_gb': 0.01,
                'unit': 'per GB transferred'
            },
            {
                'id': 'transit_gateway',
                'name': 'Transit Gateway',
                'description': 'Hub-and-spoke networking',
                'price_per_hour': 0.05,
                'price_per_gb': 0.02,
                'unit': 'per gateway-hour + data processed'
            },
            {
                'id': 'transit_gateway_attachment',
                'name': 'Transit Gateway Attachment',
                'description': 'Network attachments to Transit Gateway',
                'price_per_hour': 0.05,
                'unit': 'per attachment-hour'
            },
            {
                'id': 'vpn_connection',
                'name': 'VPN Connections',
                'description': 'Site-to-site VPN',
                'price_per_hour': 0.05,
                'price_per_gb': 0.09,
                'unit': 'per connection-hour + data processed'
            },
            {
                'id': 'elastic_ip',
                'name': 'Elastic IP Address',
                'description': 'Static public IPv4',
                'price_per_hour': 0.005,
                'unit': 'per address-hour (unattached)'
            },
            {
                'id': 'flow_logs',
                'name': 'VPC Flow Logs',
                'description': 'IP traffic logs',
                'price_per_gb': 0.50,
                'unit': 'per GB ingested'
            }
        ]
    },
    
    'ec2': {
        'name': 'Elastic Compute Cloud',
        'low_level_services': [
            {
                'id': 'ebs_volume_gp3',
                'name': 'EBS General Purpose SSD (gp3)',
                'description': 'Block storage',
                'price_per_gb_month': 0.08,
                'unit': 'per GB-month'
            },
            {
                'id': 'ebs_volume_gp2',
                'name': 'EBS General Purpose SSD (gp2)',
                'description': 'Block storage',
                'price_per_gb_month': 0.10,
                'unit': 'per GB-month'
            },
            {
                'id': 'ebs_volume_io1',
                'name': 'EBS Provisioned IOPS SSD (io1)',
                'description': 'High-performance block storage',
                'price_per_gb_month': 0.125,
                'unit': 'per GB-month + IOPS-month'
            },
            {
                'id': 'ebs_snapshot',
                'name': 'EBS Snapshots',
                'description': 'Point-in-time backups',
                'price_per_gb_month': 0.05,
                'unit': 'per GB-month'
            },
            {
                'id': 'ec2_spot_instance',
                'name': 'Spot Instance',
                'description': 'Spare capacity compute',
                'price_per_hour': 0.00,
                'unit': 'discounted variable pricing'
            }
        ]
    },
    
    's3': {
        'name': 'Simple Storage Service',
        'low_level_services': [
            {
                'id': 's3_standard_storage',
                'name': 'S3 Standard',
                'description': 'Frequently accessed data',
                'price_per_gb_month': 0.023,
                'unit': 'per GB-month'
            },
            {
                'id': 's3_standard_ia',
                'name': 'S3 Standard-IA',
                'description': 'Infrequent access',
                'price_per_gb_month': 0.0125,
                'unit': 'per GB-month + retrieval'
            },
            {
                'id': 's3_glacier_deep_archive',
                'name': 'S3 Glacier Deep Archive',
                'description': 'Long-term archive, hours',
                'price_per_gb_month': 0.00099,
                'unit': 'per GB-month + retrieval'
            },
            {
                'id': 's3_put_requests',
                'name': 'PUT/COPY/POST/LIST Requests',
                'description': 'Write operations',
                'price_per_thousand': 0.005,
                'unit': 'per 1,000 requests'
            },
            {
                'id': 's3_get_requests',
                'name': 'GET/SELECT Requests',
                'description': 'Read operations',
                'price_per_thousand': 0.0004,
                'unit': 'per 1,000 requests'
            }
        ]
    },
    
    'rds': {
        'name': 'Relational Database Service',
        'low_level_services': [
            {
                'id': 'rds_db_instance',
                'name': 'DB Instance',
                'description': 'Database compute',
                'price_per_hour': 0.00,
                'unit': 'varies by instance type'
            },
            {
                'id': 'rds_storage_gp2',
                'name': 'General Purpose SSD (gp2)',
                'description': 'Database storage',
                'price_per_gb_month': 0.115,
                'unit': 'per GB-month'
            },
            {
                'id': 'rds_backup',
                'name': 'Automated Backups',
                'description': 'Database backups',
                'price_per_gb_month': 0.095,
                'unit': 'per GB-month'
            },
            {
                'id': 'rds_performance_insights',
                'name': 'Performance Insights',
                'description': 'Database monitoring',
                'price_per_hour': 0.10,
                'unit': 'per instance-hour'
            }
        ]
    },
    
    'lambda': {
        'name': 'Lambda',
        'low_level_services': [
            {
                'id': 'lambda_execution',
                'name': 'Execution Time',
                'description': 'Compute duration',
                'price_per_gb_second': 0.0000166667,
                'unit': 'per GB-second'
            },
            {
                'id': 'lambda_requests',
                'name': 'Requests',
                'description': 'Invocation count',
                'price_per_million': 0.20,
                'unit': 'per million requests'
            }
        ]
    },
    
    'dynamodb': {
        'name': 'DynamoDB',
        'low_level_services': [
            {
                'id': 'dynamodb_wcu',
                'name': 'Write Capacity Unit',
                'description': 'Provisioned writes',
                'price_per_wcu_hour': 0.00065,
                'unit': 'per WCU-hour'
            },
            {
                'id': 'dynamodb_rcu',
                'name': 'Read Capacity Unit',
                'description': 'Provisioned reads',
                'price_per_rcu_hour': 0.00013,
                'unit': 'per RCU-hour'
            },
            {
                'id': 'dynamodb_storage',
                'name': 'Data Storage',
                'description': 'Table data',
                'price_per_gb_month': 0.25,
                'unit': 'per GB-month'
            }
        ]
    },
    
    'elb': {
        'name': 'Elastic Load Balancing',
        'low_level_services': [
            {
                'id': 'application_load_balancer',
                'name': 'Application Load Balancer',
                'description': 'Layer 7 load balancing',
                'price_per_hour': 0.0225,
                'unit': 'per ALB-hour'
            },
            {
                'id': 'network_load_balancer',
                'name': 'Network Load Balancer',
                'description': 'Layer 4 load balancing',
                'price_per_hour': 0.0225,
                'unit': 'per NLB-hour'
            }
        ]
    },
    
    'cloudfront': {
        'name': 'CloudFront',
        'low_level_services': [
            {
                'id': 'distribution',
                'name': 'Distribution',
                'description': 'CDN configuration',
                'price_per_hour': 0.00,
                'unit': 'free'
            },
            {
                'id': 'data_transfer_out',
                'name': 'Data Transfer Out',
                'description': 'Content delivery to internet',
                'price_per_gb': 0.085,
                'unit': 'per GB'
            },
            {
                'id': 'http_requests',
                'name': 'HTTP/HTTPS Requests',
                'description': 'Content requests',
                'price_per_10k': 0.0075,
                'unit': 'per 10,000 requests'
            }
        ]
    },
    
    'route53': {
        'name': 'Route 53',
        'low_level_services': [
            {
                'id': 'hosted_zone',
                'name': 'Hosted Zone',
                'description': 'DNS namespace management',
                'price_per_month': 0.50,
                'unit': 'per zone-month'
            },
            {
                'id': 'dns_query',
                'name': 'DNS Queries',
                'description': 'DNS resolution requests',
                'price_per_million': 0.40,
                'unit': 'per million queries'
            },
            {
                'id': 'health_check',
                'name': 'Basic Health Check',
                'description': 'Endpoint monitoring',
                'price_per_month': 0.50,
                'unit': 'per check-month'
            }
        ]
    }
}


# ============================================================
# DISCOVERY FUNCTIONS FOR ALL SERVICES
# ============================================================

# Simplified discovery functions (placeholders - implement as needed)
def discover_vpc_services(creds, region):
    """Discover VPC-related services"""
    services = []
    try:
        ec2 = boto3.client('ec2', 
                          aws_access_key_id=creds['AccessKeyId'],
                          aws_secret_access_key=creds['SecretAccessKey'],
                          aws_session_token=creds['SessionToken'],
                          region_name=region,
                          verify=False)
        
        # Discover NAT Gateways
        try:
            nat_gateways = ec2.describe_nat_gateways()
            for nat in nat_gateways.get('NatGateways', []):
                if nat['State'] == 'available':
                    services.append({
                        'service_id': 'nat_gateway',
                        'resource_id': nat['NatGatewayId'],
                        'resource_name': f"NAT Gateway {nat['NatGatewayId'][:8]}",
                        'region': region,
                        'count': 1,
                        'estimated_monthly_cost': 0.045 * 730,  # $0.045 per hour * 730 hours/month
                        'details': {
                            'vpc_id': nat.get('VpcId'),
                            'subnet_id': nat.get('SubnetId'),
                            'state': nat.get('State')
                        }
                    })
        except Exception as e:
            print(f"Error discovering NAT Gateways: {e}")
        
        # Discover VPC Endpoints
        try:
            vpc_endpoints = ec2.describe_vpc_endpoints()
            for endpoint in vpc_endpoints.get('VpcEndpoints', []):
                if endpoint['State'] == 'available':
                    services.append({
                        'service_id': 'vpc_endpoint',
                        'resource_id': endpoint['VpcEndpointId'],
                        'resource_name': f"VPC Endpoint {endpoint['VpcEndpointId'][:8]}",
                        'region': region,
                        'count': 1,
                        'estimated_monthly_cost': 0.01 * 730,  # $0.01 per hour
                        'details': {
                            'vpc_id': endpoint.get('VpcId'),
                            'service_name': endpoint.get('ServiceName'),
                            'vpc_endpoint_type': endpoint.get('VpcEndpointType')
                        }
                    })
        except Exception as e:
            print(f"Error discovering VPC Endpoints: {e}")
        
        # Discover Elastic IPs (unattached)
        try:
            addresses = ec2.describe_addresses()
            for addr in addresses.get('Addresses', []):
                if 'InstanceId' not in addr and 'NetworkInterfaceId' not in addr:
                    services.append({
                        'service_id': 'elastic_ip',
                        'resource_id': addr['AllocationId'],
                        'resource_name': f"Elastic IP {addr.get('PublicIp', 'unknown')}",
                        'region': region,
                        'count': 1,
                        'estimated_monthly_cost': 0.005 * 730,  # $0.005 per hour
                        'details': {
                            'public_ip': addr.get('PublicIp'),
                            'domain': addr.get('Domain')
                        }
                    })
        except Exception as e:
            print(f"Error discovering Elastic IPs: {e}")
            
    except Exception as e:
        print(f"Error in VPC discovery: {e}")
    
    return services


def discover_ec2_services(creds, region):
    """Discover EC2-related services"""
    services = []
    try:
        ec2 = boto3.client('ec2',
                          aws_access_key_id=creds['AccessKeyId'],
                          aws_secret_access_key=creds['SecretAccessKey'],
                          aws_session_token=creds['SessionToken'],
                          region_name=region,
                          verify=False)
        
        # Discover EC2 Instances
        try:
            instances = ec2.describe_instances()
            instance_count = 0
            running_count = 0
            stopped_count = 0
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_count += 1
                    if instance['State']['Name'] == 'running':
                        running_count += 1
                    elif instance['State']['Name'] == 'stopped':
                        stopped_count += 1
                    
                    # Estimate cost based on instance type (simplified)
                    # You would need a pricing API for accurate estimates
                    estimated_cost = 0.05 * 730  # Placeholder: $0.05 per hour
                    
                    services.append({
                        'service_id': 'ec2_instance',
                        'resource_id': instance['InstanceId'],
                        'resource_name': next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId']),
                        'region': region,
                        'count': 1,
                        'estimated_monthly_cost': estimated_cost,
                        'details': {
                            'instance_type': instance.get('InstanceType'),
                            'state': instance['State']['Name'],
                            'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None
                        }
                    })
            
            # Add EC2 summary as a service
            if instance_count > 0:
                services.append({
                    'service_id': 'ec2_summary',
                    'resource_id': f'ec2_summary_{region}',
                    'resource_name': f'EC2 Instances Summary',
                    'region': region,
                    'count': instance_count,
                    'estimated_monthly_cost': 0,
                    'details': {
                        'total_instances': instance_count,
                        'running': running_count,
                        'stopped': stopped_count
                    }
                })
                
        except Exception as e:
            print(f"Error discovering EC2 instances: {e}")
        
        # Discover EBS Volumes
        try:
            volumes = ec2.describe_volumes()
            for volume in volumes.get('Volumes', []):
                size_gb = volume.get('Size', 0)
                estimated_cost = size_gb * 0.10  # $0.10 per GB-month for gp2
                
                services.append({
                    'service_id': 'ebs_volume_gp2',
                    'resource_id': volume['VolumeId'],
                    'resource_name': f"EBS Volume {volume['VolumeId'][:8]}",
                    'region': region,
                    'count': 1,
                    'estimated_monthly_cost': estimated_cost,
                    'details': {
                        'size_gb': size_gb,
                        'volume_type': volume.get('VolumeType'),
                        'state': volume.get('State'),
                        'attached_to': volume.get('Attachments', [{}])[0].get('InstanceId') if volume.get('Attachments') else None
                    }
                })
        except Exception as e:
            print(f"Error discovering EBS volumes: {e}")
            
    except Exception as e:
        print(f"Error in EC2 discovery: {e}")
    
    return services


def discover_s3_services(creds, region):
    """Discover S3-related services"""
    services = []
    try:
        s3 = boto3.client('s3',
                         aws_access_key_id=creds['AccessKeyId'],
                         aws_secret_access_key=creds['SecretAccessKey'],
                         aws_session_token=creds['SessionToken'],
                         verify=False)
        
        # S3 is a global service, but we'll discover from us-east-1
        if region == 'us-east-1':
            try:
                buckets = s3.list_buckets()
                for bucket in buckets.get('Buckets', []):
                    services.append({
                        'service_id': 's3_standard_storage',
                        'resource_id': bucket['Name'],
                        'resource_name': bucket['Name'],
                        'region': 'global',
                        'count': 1,
                        'estimated_monthly_cost': 0,  # Would need to get bucket size
                        'details': {
                            'creation_date': bucket.get('CreationDate', '').isoformat() if bucket.get('CreationDate') else None
                        }
                    })
            except Exception as e:
                print(f"Error discovering S3 buckets: {e}")
                
    except Exception as e:
        print(f"Error in S3 discovery: {e}")
    
    return services


def discover_rds_services(creds, region):
    """Discover RDS-related services"""
    services = []
    try:
        rds = boto3.client('rds',
                          aws_access_key_id=creds['AccessKeyId'],
                          aws_secret_access_key=creds['SecretAccessKey'],
                          aws_session_token=creds['SessionToken'],
                          region_name=region,
                          verify=False)
        
        try:
            instances = rds.describe_db_instances()
            for instance in instances.get('DBInstances', []):
                # Estimate cost based on instance class (simplified)
                estimated_cost = 0.10 * 730  # Placeholder
                
                services.append({
                    'service_id': 'rds_db_instance',
                    'resource_id': instance['DBInstanceIdentifier'],
                    'resource_name': instance['DBInstanceIdentifier'],
                    'region': region,
                    'count': 1,
                    'estimated_monthly_cost': estimated_cost,
                    'details': {
                        'engine': instance.get('Engine'),
                        'instance_class': instance.get('DBInstanceClass'),
                        'storage_gb': instance.get('AllocatedStorage'),
                        'status': instance.get('DBInstanceStatus'),
                        'multi_az': instance.get('MultiAZ', False)
                    }
                })
        except Exception as e:
            print(f"Error discovering RDS instances: {e}")
            
    except Exception as e:
        print(f"Error in RDS discovery: {e}")
    
    return services


def discover_dynamodb_services(creds, region):
    """Discover DynamoDB-related services"""
    services = []
    try:
        dynamodb = boto3.client('dynamodb',
                               aws_access_key_id=creds['AccessKeyId'],
                               aws_secret_access_key=creds['SecretAccessKey'],
                               aws_session_token=creds['SessionToken'],
                               region_name=region,
                               verify=False)
        
        try:
            tables = dynamodb.list_tables()
            for table_name in tables.get('TableNames', []):
                table_desc = dynamodb.describe_table(TableName=table_name)
                table = table_desc.get('Table', {})
                
                # Estimate cost based on read/write capacity
                read_capacity = table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0)
                write_capacity = table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0)
                estimated_cost = (read_capacity * 0.00013 * 730) + (write_capacity * 0.00065 * 730)
                
                services.append({
                    'service_id': 'dynamodb_storage',
                    'resource_id': table_name,
                    'resource_name': table_name,
                    'region': region,
                    'count': 1,
                    'estimated_monthly_cost': estimated_cost,
                    'details': {
                        'item_count': table.get('ItemCount', 0),
                        'size_bytes': table.get('TableSizeBytes', 0),
                        'read_capacity': read_capacity,
                        'write_capacity': write_capacity,
                        'status': table.get('TableStatus')
                    }
                })
        except Exception as e:
            print(f"Error discovering DynamoDB tables: {e}")
            
    except Exception as e:
        print(f"Error in DynamoDB discovery: {e}")
    
    return services


def discover_lambda_services(creds, region):
    """Discover Lambda-related services"""
    services = []
    try:
        lambda_client = boto3.client('lambda',
                                    aws_access_key_id=creds['AccessKeyId'],
                                    aws_secret_access_key=creds['SecretAccessKey'],
                                    aws_session_token=creds['SessionToken'],
                                    region_name=region,
                                    verify=False)
        
        try:
            functions = lambda_client.list_functions()
            for function in functions.get('Functions', []):
                # Estimate cost based on memory and timeout (simplified)
                memory_mb = function.get('MemorySize', 128)
                estimated_cost = (memory_mb / 1024) * 0.0000166667 * 1000000  # Placeholder
                
                services.append({
                    'service_id': 'lambda_execution',
                    'resource_id': function['FunctionName'],
                    'resource_name': function['FunctionName'],
                    'region': region,
                    'count': 1,
                    'estimated_monthly_cost': estimated_cost,
                    'details': {
                        'runtime': function.get('Runtime'),
                        'memory_mb': memory_mb,
                        'timeout': function.get('Timeout'),
                        'last_modified': function.get('LastModified')
                    }
                })
        except Exception as e:
            print(f"Error discovering Lambda functions: {e}")
            
    except Exception as e:
        print(f"Error in Lambda discovery: {e}")
    
    return services


def discover_ecs_services(creds, region):
    """Discover ECS-related services"""
    services = []
    try:
        ecs = boto3.client('ecs',
                          aws_access_key_id=creds['AccessKeyId'],
                          aws_secret_access_key=creds['SecretAccessKey'],
                          aws_session_token=creds['SessionToken'],
                          region_name=region,
                          verify=False)
        
        try:
            clusters = ecs.list_clusters()
            for cluster_arn in clusters.get('clusterArns', []):
                cluster_desc = ecs.describe_clusters(clusters=[cluster_arn])
                for cluster in cluster_desc.get('clusters', []):
                    services.append({
                        'service_id': 'ecs_cluster',
                        'resource_id': cluster['clusterArn'].split('/')[-1],
                        'resource_name': cluster['clusterName'],
                        'region': region,
                        'count': 1,
                        'estimated_monthly_cost': 0,  # ECS cluster itself is free
                        'details': {
                            'status': cluster.get('status'),
                            'registered_container_instances_count': cluster.get('registeredContainerInstancesCount', 0),
                            'running_tasks_count': cluster.get('runningTasksCount', 0)
                        }
                    })
        except Exception as e:
            print(f"Error discovering ECS clusters: {e}")
            
    except Exception as e:
        print(f"Error in ECS discovery: {e}")
    
    return services


def discover_eks_services(creds, region):
    """Discover EKS-related services"""
    services = []
    try:
        eks = boto3.client('eks',
                          aws_access_key_id=creds['AccessKeyId'],
                          aws_secret_access_key=creds['SecretAccessKey'],
                          aws_session_token=creds['SessionToken'],
                          region_name=region,
                          verify=False)
        
        try:
            clusters = eks.list_clusters()
            for cluster_name in clusters.get('clusters', []):
                cluster_desc = eks.describe_cluster(name=cluster_name)
                cluster = cluster_desc.get('cluster', {})
                
                services.append({
                    'service_id': 'eks_control_plane',
                    'resource_id': cluster_name,
                    'resource_name': cluster_name,
                    'region': region,
                    'count': 1,
                    'estimated_monthly_cost': 0.10 * 730,  # $0.10 per hour
                    'details': {
                        'status': cluster.get('status'),
                        'version': cluster.get('version'),
                        'endpoint': cluster.get('endpoint'),
                        'created_at': cluster.get('createdAt', '').isoformat() if cluster.get('createdAt') else None
                    }
                })
        except Exception as e:
            print(f"Error discovering EKS clusters: {e}")
            
    except Exception as e:
        print(f"Error in EKS discovery: {e}")
    
    return services


def discover_route53_services(creds):
    """Discover Route53-related services (global)"""
    services = []
    try:
        route53 = boto3.client('route53',
                              aws_access_key_id=creds['AccessKeyId'],
                              aws_secret_access_key=creds['SecretAccessKey'],
                              aws_session_token=creds['SessionToken'],
                              verify=False)
        
        try:
            hosted_zones = route53.list_hosted_zones()
            for zone in hosted_zones.get('HostedZones', []):
                services.append({
                    'service_id': 'hosted_zone',
                    'resource_id': zone['Id'].split('/')[-1],
                    'resource_name': zone['Name'],
                    'region': 'global',
                    'count': 1,
                    'estimated_monthly_cost': 0.50,  # $0.50 per month
                    'details': {
                        'resource_record_set_count': zone.get('ResourceRecordSetCount', 0),
                        'is_private': zone.get('Config', {}).get('PrivateZone', False)
                    }
                })
        except Exception as e:
            print(f"Error discovering Route53 hosted zones: {e}")
            
    except Exception as e:
        print(f"Error in Route53 discovery: {e}")
    
    return services


def discover_cloudfront_distributions(creds):
    """Discover CloudFront distributions (global)"""
    services = []
    try:
        cloudfront = boto3.client('cloudfront',
                                  aws_access_key_id=creds['AccessKeyId'],
                                  aws_secret_access_key=creds['SecretAccessKey'],
                                  aws_session_token=creds['SessionToken'],
                                  verify=False)
        
        try:
            distributions = cloudfront.list_distributions()
            for distribution in distributions.get('DistributionList', {}).get('Items', []):
                services.append({
                    'service_id': 'distribution',
                    'resource_id': distribution['Id'],
                    'resource_name': distribution['DomainName'],
                    'region': 'global',
                    'count': 1,
                    'estimated_monthly_cost': 0,  # Distribution is free, pay for usage
                    'details': {
                        'status': distribution.get('Status'),
                        'domain_name': distribution.get('DomainName'),
                        'comment': distribution.get('Comment', ''),
                        'enabled': distribution.get('Enabled', False)
                    }
                })
        except Exception as e:
            print(f"Error discovering CloudFront distributions: {e}")
            
    except Exception as e:
        print(f"Error in CloudFront discovery: {e}")
    
    return services


def discover_waf_services(creds, region):
    """Discover WAF-related services"""
    services = []
    try:
        wafv2 = boto3.client('wafv2',
                            aws_access_key_id=creds['AccessKeyId'],
                            aws_secret_access_key=creds['SecretAccessKey'],
                            aws_session_token=creds['SessionToken'],
                            region_name=region,
                            verify=False)
        
        try:
            web_acls = wafv2.list_web_acls(Scope='REGIONAL')
            for acl in web_acls.get('WebACLs', []):
                services.append({
                    'service_id': 'waf_acl',
                    'resource_id': acl['Id'],
                    'resource_name': acl['Name'],
                    'region': region,
                    'count': 1,
                    'estimated_monthly_cost': 5.00,  # $5 per month for Web ACL
                    'details': {
                        'description': acl.get('Description', ''),
                        'lock_token': acl.get('LockToken')
                    }
                })
        except Exception as e:
            print(f"Error discovering WAF Web ACLs: {e}")
            
    except Exception as e:
        print(f"Error in WAF discovery: {e}")
    
    return services


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def assume_role_for_account(account):
    """Assume role for AWS account using platform credentials"""
    try:
        from django.conf import settings
        
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
            config=Config(
                retries={'max_attempts': 3},
                connect_timeout=30,
                read_timeout=30
            ),
            verify=False
        )
        
        print(f"🔍 Assuming role: {account.role_arn}")
        print(f"🔍 External ID: {account.external_id}")
        
        response = sts.assume_role(
            RoleArn=account.role_arn,
            RoleSessionName=f"LowLevelDiscovery_{account.id}",
            ExternalId=str(account.external_id),
            DurationSeconds=3600
        )
        
        creds = response["Credentials"]
        
        print(f"✅ Successfully assumed role for account {account.account_id}")
        return creds
        
    except Exception as e:
        print(f"❌ Error assuming role: {e}")
        import traceback
        traceback.print_exc()
        return None


def discover_region_services(creds, region):
    """Discover all low-level services in a specific region"""
    services = []
    
    # Execute all region-based discovery functions
    discovery_functions = [
        discover_vpc_services,
        discover_ec2_services,
        discover_s3_services,
        discover_rds_services,
        discover_dynamodb_services,
        discover_lambda_services,
        discover_ecs_services,
        discover_eks_services,
        discover_waf_services,
    ]
    
    for func in discovery_functions:
        try:
            result = func(creds, region)
            if result:
                services.extend(result)
        except Exception as e:
            print(f"Error in {func.__name__}: {e}")
    
    return services


def discover_global_services(creds):
    """Discover global AWS services"""
    services = []
    
    # Execute global discovery functions
    global_functions = [
        discover_route53_services,
        discover_cloudfront_distributions,
    ]
    
    for func in global_functions:
        try:
            result = func(creds)
            if result:
                services.extend(result)
        except Exception as e:
            print(f"Error in {func.__name__}: {e}")
    
    return services


def save_snapshot_to_database(account, services_data, scan_duration):
    """Save the discovered services to the database"""
    from django.db import transaction
    from decimal import Decimal
    
    with transaction.atomic():
        # Create snapshot
        snapshot = LowLevelServiceSnapshot.objects.create(
            account=account,
            total_services=services_data['summary']['total_services'],
            estimated_monthly_cost=Decimal(str(services_data['summary']['estimated_monthly_cost'])),
            unique_service_types=services_data['summary']['unique_service_types'],
            unique_services_discovered=services_data['summary']['unique_services_discovered'],
            regions_scanned=services_data['summary']['regions_scanned'],
            snapshot_data=services_data,
            scan_duration_seconds=scan_duration,
            expires_at=timezone.now() + timezone.timedelta(hours=24)
        )
        
        # Mark old resources as inactive
        LowLevelServiceResource.objects.filter(
            account=account,
            is_active=True
        ).update(is_active=False)
        
        # Save all resources
        for service_id, category_data in services_data['services_by_category'].items():
            # Get or create category
            category_name = category_data.get('category', 'Other')
            category, _ = LowLevelServiceCategory.objects.get_or_create(
                key=category_name.lower().replace(' ', '_'),
                defaults={'name': category_name}
            )
            
            # Get or create service definition
            service_info = category_data.get('service_info')
            if service_info:
                service_def, _ = LowLevelServiceDefinition.objects.get_or_create(
                    service_id=service_id,
                    defaults={
                        'name': service_info.get('name', service_id),
                        'description': service_info.get('description', ''),
                        'category': category,
                        'unit': service_info.get('unit', ''),
                        'price_per_hour': Decimal(str(service_info.get('price_per_hour', 0))) if service_info.get('price_per_hour') else None,
                        'price_per_gb': Decimal(str(service_info.get('price_per_gb', 0))) if service_info.get('price_per_gb') else None,
                        'price_per_gb_month': Decimal(str(service_info.get('price_per_gb_month', 0))) if service_info.get('price_per_gb_month') else None,
                        'price_per_million': Decimal(str(service_info.get('price_per_million', 0))) if service_info.get('price_per_million') else None,
                        'price_per_month': Decimal(str(service_info.get('price_per_month', 0))) if service_info.get('price_per_month') else None,
                    }
                )
            else:
                # Create a generic service definition
                service_def, _ = LowLevelServiceDefinition.objects.get_or_create(
                    service_id=service_id,
                    defaults={
                        'name': service_id.replace('_', ' ').title(),
                        'description': f'AWS {service_id.replace("_", " ").title()} service',
                        'category': category,
                        'unit': 'per resource'
                    }
                )
            
            # Save each resource
            for resource in category_data.get('resources', []):
                LowLevelServiceResource.objects.update_or_create(
                    account=account,
                    service_definition=service_def,
                    resource_id=resource.get('resource_id', 'unknown'),
                    region=resource.get('region', 'unknown'),
                    defaults={
                        'resource_name': resource.get('resource_name', ''),
                        'count': resource.get('count', 1),
                        'estimated_monthly_cost': Decimal(str(resource.get('estimated_monthly_cost', 0))),
                        'details': resource.get('details', {}),
                        'discovered_at': snapshot.created_at,
                        'is_active': True
                    }
                )
            
            # Save cost history
            today = timezone.now().date()
            LowLevelServiceCostHistory.objects.update_or_create(
                account=account,
                service_definition=service_def,
                date=today,
                defaults={
                    'monthly_cost': Decimal(str(category_data.get('total_monthly_cost', 0))),
                    'resource_count': category_data.get('total_count', 0),
                    'region_breakdown': {
                        r.get('region', 'unknown'): float(r.get('estimated_monthly_cost', 0))
                        for r in category_data.get('resources', [])
                    }
                }
            )
        
        print(f"✅ Saved snapshot to database: {snapshot}")
        return snapshot

# low_level_tracker.py - Fix the attribute name in discover_low_level_services

def discover_low_level_services(account_id, use_cache=True):
    """Discover ALL low-level AWS services and save to database"""
    try:
        start_time = time.time()
        # Get account from database
        account = AWSAccount.objects.get(id=account_id)
        # Check if we have a recent snapshot (less than 24 hours old)
        if use_cache:
            recent_snapshot = LowLevelServiceSnapshot.objects.filter(
                account=account,
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).first()
            if recent_snapshot:
                print(f"📦 Using recent database snapshot from {recent_snapshot.created_at}")
                return recent_snapshot.snapshot_data
        
        # Assume role
        creds = assume_role_for_account(account)
        if not creds:
            return {
                'error': 'Failed to assume role',
                'services': [],
                'summary': {'total_services': 0, 'estimated_monthly_cost': 0}
            }
        
        # Regions to scan
        regions_to_check = ['us-east-1', 'us-west-2']
        all_services = []
        
        # Parallel discovery with timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as thread_executor:
            futures = {
                thread_executor.submit(discover_region_services, creds, region): region
                for region in regions_to_check
            }
            for future in concurrent.futures.as_completed(futures, timeout=60):
                region = futures[future]
                try:
                    region_services = future.result(timeout=30)
                    if region_services:
                        all_services.extend(region_services)
                        print(f"✅ Discovered {len(region_services)} services in {region}")
                except Exception as e:
                    print(f"❌ Error discovering services in {region}: {e}")
        
        # Add global services
        global_services = discover_global_services(creds)
        all_services.extend(global_services)
        
        # Calculate summary
        total_monthly_cost = sum(service.get('estimated_monthly_cost', 0) for service in all_services)
        
        # Group by service category
        grouped_services = {}
        for service in all_services:
            service_id = service['service_id']
            if service_id not in grouped_services:
                # Find service info from LOW_LEVEL_SERVICES
                service_info = None
                category_name = "Other"
                for category_key, category in LOW_LEVEL_SERVICES.items():
                    for low_service in category['low_level_services']:
                        if low_service['id'] == service_id:
                            service_info = low_service
                            category_name = category['name']
                            break
                    if service_info:
                        break
                grouped_services[service_id] = {
                    'service_info': service_info,
                    'category': category_name,
                    'resources': [],
                    'total_count': 0,
                    'total_monthly_cost': 0
                }
            grouped_services[service_id]['resources'].append(service)
            grouped_services[service_id]['total_count'] += 1
            grouped_services[service_id]['total_monthly_cost'] += service.get('estimated_monthly_cost', 0)
        
        scan_duration = round(time.time() - start_time, 2)
        result = {
            'services_by_category': grouped_services,
            'all_resources': all_services,
            'summary': {
                'total_services': len(all_services),
                'estimated_monthly_cost': round(total_monthly_cost, 2),
                'unique_service_types': len(grouped_services),
                'unique_services_discovered': len(set(s['service_id'] for s in all_services)),
                'regions_scanned': regions_to_check,
                'timestamp': datetime.now(timezone.UTC).isoformat(),
                'scan_duration': scan_duration
            },
            'source': 'aws_api',
            'cached': False
        }
        
        # Save to database
        save_snapshot_to_database(account, result, scan_duration)
        return result
        
    except AWSAccount.DoesNotExist:
        return {
            'error': f"Account {account_id} not found",
            'services': [],
            'summary': {'total_services': 0, 'estimated_monthly_cost': 0}
        }
    except Exception as e:
        print(f"Error discovering low-level services: {e}")
        import traceback
        traceback.print_exc()
        return {
            'error': str(e),
            'services': [],
            'summary': {'total_services': 0, 'estimated_monthly_cost': 0}
        }