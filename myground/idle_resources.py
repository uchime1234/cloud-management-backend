# idle_ec2_checker.py
# Run this in Django shell: python manage.py shell < idle_ec2_checker.py
# Or copy/paste into Django shell

import boto3
from datetime import datetime, timedelta
from django.conf import settings
import json
from decimal import Decimal

# Add this helper function at the top of your idle_resources.py

def check_idle_ec2_instances(role_arn=None, external_id=None, region='us-east-1'):
    """
    Comprehensive EC2 idle instance checker
    Checks CPU, Network, Disk I/O, Load Balancer, and Auto Scaling
    """
    
    print("=" * 80)
    print("🔍 EC2 IDLE INSTANCE DETECTION TOOL")
    print("=" * 80)
    
    # If role_arn provided, assume role first
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="IdleEC2Checker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            ec2 = boto3.client(
                'ec2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            elbv2 = boto3.client(
                'elbv2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            autoscaling = boto3.client(
                'autoscaling',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return None
    else:
        # Use direct credentials
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        elbv2 = boto3.client('elbv2', region_name=region)
        autoscaling = boto3.client('autoscaling', region_name=region)
    
    # Get all running instances
    print(f"\n📊 Fetching EC2 instances in {region}...")
    try:
        instances_response = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
    except Exception as e:
        print(f"❌ Failed to describe instances: {e}")
        return None
    
    instances = []
    for reservation in instances_response['Reservations']:
        for instance in reservation['Instances']:
            instances.append(instance)
    
    print(f"✅ Found {len(instances)} running EC2 instances")
    
    if not instances:
        print("No running instances to check")
        return []
    
    # Get CloudWatch metrics for the last 14 days
    end_time = datetime.utcnow()
    start_time_14d = end_time - timedelta(days=14)
    start_time_7d = end_time - timedelta(days=7)
    
    idle_instances = []
    
    for instance in instances:
        instance_id = instance['InstanceId']
        instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'Unnamed')
        instance_type = instance['InstanceType']
        
        print(f"\n{'─' * 60}")
        print(f"🔍 Checking Instance: {instance_id} ({instance_name})")
        print(f"   Type: {instance_type}")
        
        # 1. Check CPU Utilization (7 days)
        cpu_metrics = []
        try:
            cpu_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_7d,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average']
            )
            cpu_datapoints = cpu_response.get('Datapoints', [])
            if cpu_datapoints:
                cpu_metrics = [dp['Average'] for dp in cpu_datapoints]
                avg_cpu = sum(cpu_metrics) / len(cpu_metrics)
                max_cpu = max(cpu_metrics)
                min_cpu = min(cpu_metrics)
                print(f"   📊 CPU - Avg: {avg_cpu:.2f}% | Max: {max_cpu:.2f}% | Min: {min_cpu:.2f}%")
            else:
                avg_cpu = 0
                print(f"   📊 CPU - No data available")
        except Exception as e:
            print(f"   ❌ CPU check failed: {e}")
            avg_cpu = 100  # Assume not idle if we can't check
        
        # 2. Check Network In/Out (14 days)
        try:
            network_in_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='NetworkIn',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d,
                EndTime=end_time,
                Period=86400,  # Daily
                Statistics=['Sum']
            )
            network_in = sum(dp['Sum'] for dp in network_in_response.get('Datapoints', [])) / (1024 * 1024)  # Convert to MB
            
            network_out_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='NetworkOut',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            network_out = sum(dp['Sum'] for dp in network_out_response.get('Datapoints', [])) / (1024 * 1024)
            
            print(f"   🌐 Network - In: {network_in:.2f} MB | Out: {network_out:.2f} MB (14 days)")
        except Exception as e:
            print(f"   ❌ Network check failed: {e}")
            network_in = network_out = 0
        
        # 3. Check Disk Read/Write (14 days)
        try:
            disk_read_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='DiskReadBytes',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            disk_read = sum(dp['Sum'] for dp in disk_read_response.get('Datapoints', [])) / (1024 * 1024)
            
            disk_write_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='DiskWriteBytes',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            disk_write = sum(dp['Sum'] for dp in disk_write_response.get('Datapoints', [])) / (1024 * 1024)
            
            print(f"   💾 Disk - Read: {disk_read:.2f} MB | Write: {disk_write:.2f} MB (14 days)")
        except Exception as e:
            print(f"   ❌ Disk check failed: {e}")
            disk_read = disk_write = 0
        
        # 4. Check Load Balancer Attachment
        connected_to_lb = False
        try:
            # Check if instance is registered with any target group
            target_groups = elbv2.describe_target_groups()['TargetGroups']
            for tg in target_groups:
                try:
                    targets = elbv2.describe_target_health(
                        TargetGroupArn=tg['TargetGroupArn'],
                        Targets=[{'Id': instance_id}]
                    )
                    if targets['TargetHealthDescriptions']:
                        connected_to_lb = True
                        break
                except:
                    pass
            print(f"   🔗 Load Balancer: {'Connected' if connected_to_lb else 'Not connected'}")
        except Exception as e:
            print(f"   ❌ Load balancer check failed: {e}")
        
        # 5. Check Auto Scaling Activity
        in_autoscaling = False
        try:
            autoscale_groups = autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']
            for asg in autoscale_groups:
                for instance_in_asg in asg.get('Instances', []):
                    if instance_in_asg['InstanceId'] == instance_id:
                        in_autoscaling = True
                        break
            print(f"   🔄 Auto Scaling: {'In group' if in_autoscaling else 'Not in group'}")
        except Exception as e:
            print(f"   ❌ Auto Scaling check failed: {e}")
        
        # 6. Check Status
        status_healthy = True
        try:
            status_response = ec2.describe_instance_status(InstanceIds=[instance_id])
            if status_response['InstanceStatuses']:
                status = status_response['InstanceStatuses'][0]
                status_healthy = (
                    status['InstanceStatus']['Status'] == 'ok' and
                    status['SystemStatus']['Status'] == 'ok'
                )
            print(f"   ✅ Status: {'Healthy' if status_healthy else 'Unhealthy'}")
        except Exception as e:
            print(f"   ❌ Status check failed: {e}")
        
        # Determine if idle
        is_idle = False
        idle_reasons = []
        
        # CPU idle (<5% average over 7 days)
        if avg_cpu < 5:
            idle_reasons.append(f"CPU utilization extremely low ({avg_cpu:.2f}% avg)")
        
        # Network idle (less than 10MB over 14 days)
        if network_in < 10 and network_out < 10:
            idle_reasons.append(f"Network activity minimal ({network_in + network_out:.2f} MB total)")
        
        # Disk idle (less than 50MB over 14 days)
        if disk_read < 50 and disk_write < 50:
            idle_reasons.append(f"Disk I/O minimal ({disk_read + disk_write:.2f} MB total)")
        
        # Not connected to load balancer AND not in auto scaling
        if not connected_to_lb and not in_autoscaling:
            idle_reasons.append("Not connected to Load Balancer or Auto Scaling")
        
        # Status is healthy (running but doing nothing)
        if status_healthy and len(idle_reasons) >= 2:
            is_idle = True
        
        # Calculate potential savings
        # Approximate hourly cost based on instance type
        hourly_cost = 0
        instance_pricing = {
            't2.micro': 0.0116, 't2.small': 0.023, 't2.medium': 0.0464,
            't3.micro': 0.0104, 't3.small': 0.0208, 't3.medium': 0.0416,
            't4g.micro': 0.0084, 't4g.small': 0.0168, 't4g.medium': 0.0336,
            'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
            'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
            'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
        }
        hourly_cost = instance_pricing.get(instance_type, 0.05)
        monthly_cost = hourly_cost * 730
        yearly_cost = monthly_cost * 12
        
        result = {
            'instance_id': instance_id,
            'instance_name': instance_name,
            'instance_type': instance_type,
            'is_idle': is_idle,
            'idle_reasons': idle_reasons,
            'metrics': {
                'avg_cpu': round(avg_cpu, 2),
                'network_in_mb': round(network_in, 2),
                'network_out_mb': round(network_out, 2),
                'disk_read_mb': round(disk_read, 2),
                'disk_write_mb': round(disk_write, 2),
                'connected_to_lb': connected_to_lb,
                'in_autoscaling': in_autoscaling,
                'status_healthy': status_healthy
            },
            'estimated_monthly_cost': round(monthly_cost, 2),
            'estimated_yearly_cost': round(yearly_cost, 2)
        }
        
        if is_idle:
            print(f"\n   ⚠️  IDLE DETECTED!")
            print(f"   Reasons: {', '.join(idle_reasons)}")
            print(f"   💰 Wasting: ${monthly_cost:.2f}/month (${yearly_cost:.2f}/year)")
            idle_instances.append(result)
        else:
            print(f"\n   ✅ Instance appears ACTIVE")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE INSTANCE SUMMARY")
    print("=" * 80)
    
    if idle_instances:
        print(f"\n⚠️  Found {len(idle_instances)} idle EC2 instance(s):\n")
        total_waste = 0
        for i, instance in enumerate(idle_instances, 1):
            print(f"{i}. {instance['instance_id']} ({instance['instance_name']})")
            print(f"   Type: {instance['instance_type']}")
            print(f"   Reasons: {', '.join(instance['idle_reasons'])}")
            print(f"   Monthly Waste: ${instance['estimated_monthly_cost']}")
            print(f"   Yearly Waste: ${instance['estimated_yearly_cost']}")
            print()
            total_waste += instance['estimated_monthly_cost']
        
        print(f"💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_waste:.2f}")
        print(f"💰 TOTAL POTENTIAL YEARLY SAVINGS: ${total_waste * 12:.2f}")
        print("\n💡 Recommendation: Consider stopping, terminating, or downsizing these instances")
    else:
        print("\n✅ No idle EC2 instances found! All instances appear active.")
    
    return idle_instances



def check_idle_auto_scaling_groups(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle/over-provisioned Auto Scaling Groups
    """
    
    print("=" * 80)
    print("⚡ AUTO SCALING GROUP IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="ASGIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            autoscaling = boto3.client(
                'autoscaling',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            ec2 = boto3.client(
                'ec2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        # Use direct credentials
        autoscaling = boto3.client('autoscaling', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        ec2 = boto3.client('ec2', region_name=region)
    
    # Get all Auto Scaling Groups
    print(f"\n📊 Fetching Auto Scaling Groups in {region}...")
    try:
        asgs = autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']
    except Exception as e:
        print(f"❌ Failed to describe ASGs: {e}")
        return []
    
    print(f"✅ Found {len(asgs)} Auto Scaling Groups")
    
    if not asgs:
        print("No ASGs to check")
        return []
    
    # Time range for metrics (last 7 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    idle_asgs = []
    
    # Instance pricing (approximate hourly rates)
    instance_pricing = {
        't2.micro': 0.0116, 't2.small': 0.023, 't2.medium': 0.0464,
        't3.micro': 0.0104, 't3.small': 0.0208, 't3.medium': 0.0416,
        't4g.micro': 0.0084, 't4g.small': 0.0168, 't4g.medium': 0.0336,
        'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
        'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
        'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
    }
    
    for asg in asgs:
        asg_name = asg['AutoScalingGroupName']
        min_size = asg['MinSize']
        max_size = asg['MaxSize']
        desired_capacity = asg['DesiredCapacity']
        current_instances = len(asg.get('Instances', []))
        
        print(f"\n{'─' * 60}")
        print(f"🔍 Checking ASG: {asg_name}")
        print(f"   Min Size: {min_size} | Max Size: {max_size} | Desired: {desired_capacity} | Current: {current_instances}")
        
        # 1. Check if desired capacity is > 0 and instances are running
        if desired_capacity == 0:
            print(f"   ⚠️  Desired capacity is 0 - ASG is effectively idle")
            is_idle = True
            reasons = ["Desired capacity set to 0 - no instances running"]
            estimated_monthly_cost = 0
        else:
            is_idle = False
            reasons = []
            
            # 2. Check CPU utilization of instances in ASG
            instance_ids = [inst['InstanceId'] for inst in asg.get('Instances', [])]
            avg_cpu_all = 0
            
            if instance_ids:
                cpu_utilizations = []
                for instance_id in instance_ids[:3]:  # Check max 3 instances per ASG
                    try:
                        cpu_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Average']
                        )
                        datapoints = cpu_response.get('Datapoints', [])
                        if datapoints:
                            avg_cpu = sum(dp['Average'] for dp in datapoints) / len(datapoints)
                            cpu_utilizations.append(avg_cpu)
                    except Exception as e:
                        print(f"   ❌ CPU check failed for {instance_id}: {e}")
                
                if cpu_utilizations:
                    avg_cpu_all = sum(cpu_utilizations) / len(cpu_utilizations)
                    print(f"   📊 Avg CPU across instances: {avg_cpu_all:.2f}%")
                    
                    if avg_cpu_all < 10:
                        reasons.append(f"Low CPU utilization ({avg_cpu_all:.2f}% avg over 7 days)")
            
            # 3. Check for scaling activities in last 7 days
            try:
                scaling_activities = autoscaling.describe_scaling_activities(
                    AutoScalingGroupName=asg_name,
                    MaxRecords=10
                )['Activities']
                
                recent_activities = [act for act in scaling_activities 
                                   if act['StartTime'] > start_time]
                
                print(f"   📈 Scaling activities (7 days): {len(recent_activities)}")
                
                if len(recent_activities) == 0:
                    reasons.append("No scaling activities in the past 7 days")
                else:
                    # Check if activities were just scale downs or no real changes
                    no_real_change = all(
                        'launch' not in act['Description'].lower() 
                        and 'terminate' not in act['Description'].lower()
                        for act in recent_activities
                    )
                    if no_real_change:
                        reasons.append("Scaling activities detected but no actual instance changes")
                        
            except Exception as e:
                print(f"   ❌ Scaling activities check failed: {e}")
            
            # 4. Check if min size is too high for workload
            if min_size > desired_capacity:
                reasons.append(f"Min size ({min_size}) higher than desired capacity ({desired_capacity})")
            
            if min_size > 1 and desired_capacity <= min_size:
                reasons.append(f"Min size set to {min_size} but workload may only need 1 instance")
            
            # 5. Check if ASG has been at min size for extended period
            if desired_capacity == min_size and min_size > 0:
                reasons.append(f"ASG stuck at minimum size ({min_size}) with no scaling up")
            
            # 6. Check if current instances less than desired (wasting capacity)
            if current_instances < desired_capacity:
                reasons.append(f"Only {current_instances}/{desired_capacity} instances running")
            
            # Determine if idle based on reasons
            if len(reasons) >= 2:
                is_idle = True
            
            # Calculate estimated monthly cost
            estimated_monthly_cost = 0
            if instance_ids:
                for instance_id in instance_ids[:1]:
                    try:
                        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
                        instance_type = instance_info['Reservations'][0]['Instances'][0]['InstanceType']
                        hourly_rate = instance_pricing.get(instance_type, 0.05)
                        estimated_monthly_cost = hourly_rate * 730 * desired_capacity
                    except Exception as e:
                        print(f"   ❌ Cost calculation failed: {e}")
                        estimated_monthly_cost = desired_capacity * 10  # Default estimate
        
        result = {
            'asg_name': asg_name,
            'min_size': min_size,
            'max_size': max_size,
            'desired_capacity': desired_capacity,
            'current_instances': current_instances,
            'is_idle': is_idle,
            'idle_reasons': reasons,
            'avg_cpu': round(avg_cpu_all, 2) if 'avg_cpu_all' in locals() else 0,
            'estimated_monthly_cost': round(estimated_monthly_cost, 2),
            'estimated_yearly_cost': round(estimated_monthly_cost * 12, 2)
        }
        
        if is_idle:
            print(f"\n   ⚠️  IDLE ASG DETECTED!")
            print(f"   Reasons: {', '.join(reasons)}")
            print(f"   💰 Wasting: ${estimated_monthly_cost:.2f}/month (${estimated_monthly_cost * 12:.2f}/year)")
            idle_asgs.append(result)
        else:
            print(f"\n   ✅ ASG appears ACTIVE")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE AUTO SCALING GROUP SUMMARY")
    print("=" * 80)
    
    if idle_asgs:
        print(f"\n⚠️  Found {len(idle_asgs)} idle/over-provisioned Auto Scaling Group(s):\n")
        total_waste = 0
        for i, asg in enumerate(idle_asgs, 1):
            print(f"{i}. {asg['asg_name']}")
            print(f"   Desired: {asg['desired_capacity']} instances | Current: {asg['current_instances']}")
            print(f"   Min: {asg['min_size']} | Max: {asg['max_size']}")
            print(f"   CPU Avg: {asg['avg_cpu']}%")
            print(f"   Reasons: {', '.join(asg['idle_reasons'])}")
            print(f"   Monthly Waste: ${asg['estimated_monthly_cost']}")
            print(f"   Yearly Waste: ${asg['estimated_yearly_cost']}")
            print()
            total_waste += asg['estimated_monthly_cost']
        
        print(f"💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_waste:.2f}")
        print(f"💰 TOTAL POTENTIAL YEARLY SAVINGS: ${total_waste * 12:.2f}")
        print("\n💡 Recommendations:")
        print("   • Reduce min_size and desired_capacity")
        print("   • Implement better scaling policies")
        print("   • Consider using smaller instance types")
        print("   • Set up scheduled scaling for predictable workloads")
    else:
        print("\n✅ No idle Auto Scaling Groups found!")
    
    return idle_asgs

# idle_resources_checker.py
# Run in Django shell: python manage.py shell

import boto3
from datetime import datetime, timedelta
from django.conf import settings

def check_idle_load_balancers(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle Load Balancers (ALB/NLB/ELB) with no traffic
    """
    
    print("=" * 80)
    print("🌐 LOAD BALANCER IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="LBIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            elbv2 = boto3.client(
                'elbv2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        elbv2 = boto3.client('elbv2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    # Get all load balancers
    print(f"\n📊 Fetching Load Balancers in {region}...")
    try:
        lbs = elbv2.describe_load_balancers()['LoadBalancers']
    except Exception as e:
        print(f"❌ Failed to describe LBs: {e}")
        return []
    
    print(f"✅ Found {len(lbs)} Load Balancers")
    
    if not lbs:
        print("No LBs to check")
        return []
    
    # Time range for metrics (last 7 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    idle_lbs = []
    
    # Load Balancer pricing (approximate)
    lb_pricing = {
        'application': 0.0225,  # per hour
        'network': 0.0225,
        'gateway': 0.0225,
        'classic': 0.025
    }
    
    for lb in lbs:
        lb_name = lb['LoadBalancerName']
        lb_type = lb['Type']
        lb_scheme = lb['Scheme']
        lb_state = lb['State']['Code']
        
        print(f"\n{'─' * 60}")
        print(f"🔍 Checking LB: {lb_name}")
        print(f"   Type: {lb_type} | Scheme: {lb_scheme} | State: {lb_state}")
        
        if lb_state != 'active':
            print(f"   ⚠️  LB is {lb_state} - not active")
            continue
        
        # Get target groups for this LB
        try:
            target_groups = elbv2.describe_target_groups(
                LoadBalancerArn=lb['LoadBalancerArn']
            )['TargetGroups']
        except Exception as e:
            print(f"   ❌ Failed to get target groups: {e}")
            target_groups = []
        
        # Check request count
        try:
            request_count = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApplicationELB',
                MetricName='RequestCount',
                Dimensions=[{'Name': 'LoadBalancer', 'Value': lb['LoadBalancerArn']}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            total_requests = sum(dp['Sum'] for dp in request_count.get('Datapoints', []))
            print(f"   📊 Total Requests (7 days): {int(total_requests)}")
        except Exception as e:
            print(f"   ❌ Request count check failed: {e}")
            total_requests = 0
        
        # Check processed bytes
        try:
            processed_bytes = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApplicationELB',
                MetricName='ProcessedBytes',
                Dimensions=[{'Name': 'LoadBalancer', 'Value': lb['LoadBalancerArn']}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            total_bytes = sum(dp['Sum'] for dp in processed_bytes.get('Datapoints', []))
            total_gb = total_bytes / (1024 * 1024 * 1024)
            print(f"   📊 Processed Data (7 days): {total_gb:.2f} GB")
        except Exception as e:
            print(f"   ❌ Processed bytes check failed: {e}")
            total_gb = 0
        
        # Check target group health
        healthy_targets = 0
        total_targets = 0
        for tg in target_groups:
            try:
                health = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                for target in health['TargetHealthDescriptions']:
                    total_targets += 1
                    if target['TargetHealth']['State'] == 'healthy':
                        healthy_targets += 1
            except Exception as e:
                print(f"   ❌ Health check failed for {tg['TargetGroupName']}: {e}")
        
        print(f"   🎯 Target Health: {healthy_targets}/{total_targets} healthy")
        
        # Determine if idle
        is_idle = False
        reasons = []
        
        if total_requests == 0:
            reasons.append("Zero requests in past 7 days")
        
        if total_gb < 0.001:  # Less than 1 MB
            reasons.append(f"No data processed ({total_gb:.4f} GB)")
        
        if healthy_targets == 0 and total_targets > 0:
            reasons.append("No healthy targets available")
        elif healthy_targets == 0 and total_targets == 0:
            reasons.append("No targets registered")
        
        if len(reasons) >= 2:
            is_idle = True
        
        # Calculate monthly cost
        hourly_rate = lb_pricing.get(lb_type, 0.0225)
        monthly_cost = hourly_rate * 730
        
        result = {
            'lb_name': lb_name,
            'lb_type': lb_type,
            'lb_scheme': lb_scheme,
            'lb_state': lb_state,
            'total_requests': int(total_requests),
            'processed_gb': round(total_gb, 2),
            'healthy_targets': healthy_targets,
            'total_targets': total_targets,
            'is_idle': is_idle,
            'idle_reasons': reasons,
            'estimated_monthly_cost': round(monthly_cost, 2),
            'estimated_yearly_cost': round(monthly_cost * 12, 2)
        }
        
        if is_idle:
            print(f"\n   ⚠️  IDLE LOAD BALANCER DETECTED!")
            print(f"   Reasons: {', '.join(reasons)}")
            print(f"   💰 Wasting: ${monthly_cost:.2f}/month (${monthly_cost * 12:.2f}/year)")
            idle_lbs.append(result)
        else:
            print(f"\n   ✅ Load Balancer appears ACTIVE")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE LOAD BALANCER SUMMARY")
    print("=" * 80)
    
    if idle_lbs:
        print(f"\n⚠️  Found {len(idle_lbs)} idle Load Balancer(s):\n")
        total_waste = 0
        for i, lb in enumerate(idle_lbs, 1):
            print(f"{i}. {lb['lb_name']} ({lb['lb_type']})")
            print(f"   Requests: {lb['total_requests']} | Data: {lb['processed_gb']} GB")
            print(f"   Targets: {lb['healthy_targets']}/{lb['total_targets']} healthy")
            print(f"   Reasons: {', '.join(lb['idle_reasons'])}")
            print(f"   Monthly Waste: ${lb['estimated_monthly_cost']}")
            print(f"   Yearly Waste: ${lb['estimated_yearly_cost']}")
            print()
            total_waste += lb['estimated_monthly_cost']
        
        print(f"💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_waste:.2f}")
        print(f"💰 TOTAL POTENTIAL YEARLY SAVINGS: ${total_waste * 12:.2f}")
    else:
        print("\n✅ No idle Load Balancers found!")
    
    return idle_lbs


def check_idle_lambda_functions(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle Lambda functions with no invocations
    """
    
    print("\n" + "=" * 80)
    print("📡 LAMBDA FUNCTION IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="LambdaIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        lambda_client = boto3.client('lambda', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    # Get all Lambda functions
    print(f"\n📊 Fetching Lambda functions in {region}...")
    try:
        functions = []
        next_marker = None
        while True:
            if next_marker:
                response = lambda_client.list_functions(Marker=next_marker)
            else:
                response = lambda_client.list_functions()
            
            functions.extend(response['Functions'])
            next_marker = response.get('NextMarker')
            if not next_marker:
                break
    except Exception as e:
        print(f"❌ Failed to list functions: {e}")
        return []
    
    print(f"✅ Found {len(functions)} Lambda functions")
    
    if not functions:
        print("No Lambda functions to check")
        return []
    
    # Time ranges
    end_time = datetime.utcnow()
    start_time_7d = end_time - timedelta(days=7)
    start_time_30d = end_time - timedelta(days=30)
    
    idle_functions = []
    
    for func in functions:
        func_name = func['FunctionName']
        runtime = func.get('Runtime', 'Unknown')
        memory = func.get('MemorySize', 128)
        last_modified = func.get('LastModified', 'Unknown')
        
        print(f"\n{'─' * 60}")
        print(f"🔍 Checking Lambda: {func_name}")
        print(f"   Runtime: {runtime} | Memory: {memory}MB | Modified: {last_modified[:10]}")
        
        # Check invocations (last 30 days)
        try:
            invocations_30d = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Invocations',
                Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                StartTime=start_time_30d,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            total_invocations_30d = sum(dp['Sum'] for dp in invocations_30d.get('Datapoints', []))
            print(f"   📊 Invocations (30 days): {int(total_invocations_30d)}")
        except Exception as e:
            print(f"   ❌ Invocations check failed: {e}")
            total_invocations_30d = 0
        
        # Check invocations (last 7 days)
        try:
            invocations_7d = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Invocations',
                Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                StartTime=start_time_7d,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            total_invocations_7d = sum(dp['Sum'] for dp in invocations_7d.get('Datapoints', []))
            print(f"   📊 Invocations (7 days): {int(total_invocations_7d)}")
        except Exception as e:
            print(f"   ❌ Invocations check failed: {e}")
            total_invocations_7d = 0
        
        # Check duration (if any invocations exist)
        avg_duration = 0
        if total_invocations_7d > 0:
            try:
                duration = cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Duration',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time_7d,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Average']
                )
                if duration.get('Datapoints'):
                    avg_duration = sum(dp['Average'] for dp in duration['Datapoints']) / len(duration['Datapoints'])
                print(f"   ⏱️  Avg Duration: {avg_duration:.2f} ms")
            except Exception as e:
                print(f"   ❌ Duration check failed: {e}")
        
        # Determine if idle
        is_idle = False
        reasons = []
        
        if total_invocations_30d == 0:
            reasons.append("No invocations in past 30 days")
        elif total_invocations_7d == 0 and total_invocations_30d > 0:
            reasons.append(f"No invocations in past 7 days (but had {int(total_invocations_30d)} in 30 days)")
        
        if total_invocations_7d < 10 and total_invocations_7d > 0:
            reasons.append(f"Very low usage ({int(total_invocations_7d)} invocations in 7 days)")
        
        # Check function age (if older than 90 days with no usage)
        try:
            from dateutil import parser
            modified_date = parser.parse(last_modified)
            age_days = (datetime.now(modified_date.tzinfo) - modified_date).days
            if age_days > 90 and total_invocations_30d == 0:
                reasons.append(f"Function {age_days} days old with no recent usage")
        except:
            pass
        
        if len(reasons) >= 1:
            is_idle = True
        
        # Calculate monthly cost (based on memory and potential usage)
        # Free tier: 1 million requests per month
        estimated_monthly_cost = 0
        if total_invocations_30d > 0:
            # Very rough estimate
            estimated_monthly_cost = round((total_invocations_30d / 1000000) * 0.20, 2)
        
        result = {
            'function_name': func_name,
            'runtime': runtime,
            'memory_mb': memory,
            'last_modified': last_modified,
            'invocations_30d': int(total_invocations_30d),
            'invocations_7d': int(total_invocations_7d),
            'avg_duration_ms': round(avg_duration, 2),
            'is_idle': is_idle,
            'idle_reasons': reasons,
            'estimated_monthly_cost': estimated_monthly_cost,
            'estimated_yearly_cost': round(estimated_monthly_cost * 12, 2)
        }
        
        if is_idle:
            print(f"\n   ⚠️  IDLE LAMBDA FUNCTION DETECTED!")
            print(f"   Reasons: {', '.join(reasons)}")
            if estimated_monthly_cost > 0:
                print(f"   💰 Estimated monthly cost: ${estimated_monthly_cost}")
            idle_functions.append(result)
        else:
            print(f"\n   ✅ Lambda function appears ACTIVE")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📡 IDLE LAMBDA FUNCTION SUMMARY")
    print("=" * 80)
    
    if idle_functions:
        print(f"\n⚠️  Found {len(idle_functions)} idle Lambda function(s):\n")
        for i, func in enumerate(idle_functions, 1):
            print(f"{i}. {func['function_name']}")
            print(f"   Invocations: {func['invocations_30d']} (30d) | {func['invocations_7d']} (7d)")
            print(f"   Memory: {func['memory_mb']}MB | Runtime: {func['runtime']}")
            print(f"   Reasons: {', '.join(func['idle_reasons'])}")
            if func['estimated_monthly_cost'] > 0:
                print(f"   Monthly Cost: ${func['estimated_monthly_cost']}")
            print()
    else:
        print("\n✅ No idle Lambda functions found!")
    
    return idle_functions

# idle_resources_checker.py
# Run in Django shell: python manage.py shell

import boto3
from datetime import datetime, timedelta
from django.conf import settings

def check_idle_ecs_services(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle ECS/Fargate services with low/no usage
    """
    
    print("=" * 80)
    print("🔁 ECS/FARGATE SERVICE IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="ECSIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            ecs = boto3.client(
                'ecs',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        ecs = boto3.client('ecs', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    # Get all ECS clusters
    print(f"\n📊 Fetching ECS clusters in {region}...")
    try:
        clusters = ecs.list_clusters()['clusterArns']
    except Exception as e:
        print(f"❌ Failed to list clusters: {e}")
        return []
    
    if not clusters:
        print("No ECS clusters found")
        return []
    
    print(f"✅ Found {len(clusters)} ECS clusters")
    
    idle_services = []
    
    # Time range for metrics (last 7 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    # Pricing for Fargate (per vCPU per hour)
    fargate_vcpu_price = 0.04048  # $0.04048 per vCPU per hour
    fargate_memory_price = 0.004445  # $0.004445 per GB per hour
    
    for cluster_arn in clusters:
        cluster_name = cluster_arn.split('/')[-1]
        
        try:
            # Get services in cluster
            services = ecs.list_services(cluster=cluster_name)['serviceArns']
            
            for service_arn in services[:10]:  # Limit to 10 per cluster
                service_name = service_arn.split('/')[-1]
                
                try:
                    # Describe service
                    service_desc = ecs.describe_services(
                        cluster=cluster_name,
                        services=[service_name]
                    )['services'][0]
                    
                    # Get task definition
                    task_def = ecs.describe_task_definition(
                        taskDefinition=service_desc['taskDefinition']
                    )['taskDefinition']
                    
                    # Get CPU and memory
                    cpu = task_def.get('cpu', '256')
                    memory = task_def.get('memory', '512')
                    
                    # Parse CPU (convert from string to number)
                    if isinstance(cpu, str):
                        if 'cpu' in cpu.lower():
                            cpu = 256
                        else:
                            cpu = int(cpu)
                    
                    # Get running tasks count
                    running_tasks = service_desc.get('runningCount', 0)
                    desired_tasks = service_desc.get('desiredCount', 0)
                    
                    print(f"\n{'─' * 60}")
                    print(f"🔍 Checking ECS Service: {service_name}")
                    print(f"   Cluster: {cluster_name}")
                    print(f"   CPU: {cpu} | Memory: {memory} MB")
                    print(f"   Tasks: {running_tasks}/{desired_tasks} running")
                    
                    # Check CPU utilization (CloudWatch)
                    cpu_util = 0
                    try:
                        cpu_metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/ECS',
                            MetricName='CPUUtilization',
                            Dimensions=[
                                {'Name': 'ClusterName', 'Value': cluster_name},
                                {'Name': 'ServiceName', 'Value': service_name}
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Average']
                        )
                        if cpu_metrics.get('Datapoints'):
                            cpu_util = sum(dp['Average'] for dp in cpu_metrics['Datapoints']) / len(cpu_metrics['Datapoints'])
                        print(f"   📊 Avg CPU: {cpu_util:.2f}%")
                    except:
                        print(f"   📊 Avg CPU: No data")
                    
                    # Check memory utilization
                    memory_util = 0
                    try:
                        memory_metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/ECS',
                            MetricName='MemoryUtilization',
                            Dimensions=[
                                {'Name': 'ClusterName', 'Value': cluster_name},
                                {'Name': 'ServiceName', 'Value': service_name}
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Average']
                        )
                        if memory_metrics.get('Datapoints'):
                            memory_util = sum(dp['Average'] for dp in memory_metrics['Datapoints']) / len(memory_metrics['Datapoints'])
                        print(f"   📊 Avg Memory: {memory_util:.2f}%")
                    except:
                        print(f"   📊 Avg Memory: No data")
                    
                    # Determine if idle
                    is_idle = False
                    reasons = []
                    
                    if running_tasks == 0:
                        reasons.append(f"No running tasks (0/{desired_tasks})")
                    elif cpu_util < 5:
                        reasons.append(f"Low CPU utilization ({cpu_util:.2f}% avg)")
                    
                    if memory_util < 10:
                        reasons.append(f"Low memory utilization ({memory_util:.2f}% avg)")
                    
                    if desired_tasks > 0 and running_tasks == 0:
                        reasons.append("Service running but no tasks")
                    
                    if len(reasons) >= 2:
                        is_idle = True
                    
                    # Calculate monthly cost (approximate)
                    vcpu_hours = (int(cpu) / 1024) * 730 * running_tasks
                    memory_gb_hours = (int(memory) / 1024) * 730 * running_tasks
                    
                    monthly_cost = (vcpu_hours * fargate_vcpu_price) + (memory_gb_hours * fargate_memory_price)
                    
                    result = {
                        'service_name': service_name,
                        'cluster_name': cluster_name,
                        'cpu': int(cpu),
                        'memory_mb': int(memory),
                        'running_tasks': running_tasks,
                        'desired_tasks': desired_tasks,
                        'cpu_utilization': round(cpu_util, 2),
                        'memory_utilization': round(memory_util, 2),
                        'is_idle': is_idle,
                        'idle_reasons': reasons,
                        'estimated_monthly_cost': round(monthly_cost, 2)
                    }
                    
                    if is_idle:
                        print(f"\n   ⚠️  IDLE ECS SERVICE DETECTED!")
                        print(f"   Reasons: {', '.join(reasons)}")
                        print(f"   💰 Monthly cost: ${monthly_cost:.2f}")
                        idle_services.append(result)
                    else:
                        print(f"\n   ✅ ECS Service appears ACTIVE")
                        
                except Exception as e:
                    print(f"   ❌ Error checking service {service_name}: {e}")
                    
        except Exception as e:
            print(f"❌ Error processing cluster {cluster_name}: {e}")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE ECS/FARGATE SERVICES SUMMARY")
    print("=" * 80)
    
    if idle_services:
        print(f"\n⚠️  Found {len(idle_services)} idle ECS service(s):\n")
        total_waste = 0
        for i, service in enumerate(idle_services, 1):
            print(f"{i}. {service['service_name']} (Cluster: {service['cluster_name']})")
            print(f"   CPU: {service['cpu']} | Memory: {service['memory_mb']}MB")
            print(f"   Tasks: {service['running_tasks']}/{service['desired_tasks']}")
            print(f"   CPU Util: {service['cpu_utilization']}% | Memory Util: {service['memory_utilization']}%")
            print(f"   Reasons: {', '.join(service['idle_reasons'])}")
            print(f"   Monthly Cost: ${service['estimated_monthly_cost']}")
            print()
            total_waste += service['estimated_monthly_cost']
        
        print(f"💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_waste:.2f}")
    else:
        print("\n✅ No idle ECS services found!")
    
    return idle_services


def check_idle_nat_gateways(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle NAT Gateways with no traffic
    """
    
    print("\n" + "=" * 80)
    print("🔥 NAT GATEWAY IDLE DETECTION (Silent Money Burner)")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NATIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            ec2 = boto3.client(
                'ec2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    # Get all NAT Gateways
    print(f"\n📊 Fetching NAT Gateways in {region}...")
    try:
        nat_gateways = ec2.describe_nat_gateways()['NatGateways']
    except Exception as e:
        print(f"❌ Failed to describe NAT Gateways: {e}")
        return []
    
    # Filter to only active ones in this region
    nat_gateways = [ng for ng in nat_gateways if ng['State'] == 'available' and ng['VpcId']]
    print(f"✅ Found {len(nat_gateways)} active NAT Gateways")
    
    if not nat_gateways:
        print("No NAT Gateways to check")
        return []
    
    # Time range for metrics (last 7 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    idle_nats = []
    
    for nat in nat_gateways:
        nat_id = nat['NatGatewayId']
        vpc_id = nat['VpcId']
        subnet_id = nat['SubnetId']
        
        print(f"\n{'─' * 60}")
        print(f"🔍 Checking NAT Gateway: {nat_id}")
        print(f"   VPC: {vpc_id} | Subnet: {subnet_id}")
        
        # Check bytes processed
        try:
            bytes_processed = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway',
                MetricName='BytesOutToDestination',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            total_bytes = sum(dp['Sum'] for dp in bytes_processed.get('Datapoints', []))
            total_gb = total_bytes / (1024 * 1024 * 1024)
            print(f"   📊 Data processed (7 days): {total_gb:.2f} GB")
        except:
            print(f"   📊 Data processed: No data")
            total_gb = 0
        
        # Check packets processed
        try:
            packets = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway',
                MetricName='PacketsOutToDestination',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            total_packets = sum(dp['Sum'] for dp in packets.get('Datapoints', []))
            print(f"   📊 Packets processed (7 days): {int(total_packets)}")
        except:
            print(f"   📊 Packets processed: No data")
            total_packets = 0
        
        # Check active connections
        try:
            connections = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway',
                MetricName='ActiveConnectionCount',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average']
            )
            avg_connections = 0
            if connections.get('Datapoints'):
                avg_connections = sum(dp['Average'] for dp in connections['Datapoints']) / len(connections['Datapoints'])
            print(f"   📊 Avg Active Connections: {avg_connections:.2f}")
        except:
            print(f"   📊 Avg Active Connections: No data")
            avg_connections = 0
        
        # Determine if idle
        is_idle = False
        reasons = []
        
        if total_gb < 0.1:  # Less than 100 MB
            reasons.append(f"Minimal data processed ({total_gb:.2f} GB)")
        
        if total_packets < 1000:
            reasons.append(f"Very low packet count ({int(total_packets)})")
        
        if avg_connections < 1:
            reasons.append("No active connections")
        
        if len(reasons) >= 2:
            is_idle = True
        
        # NAT Gateway costs $0.045 per hour
        monthly_cost = 0.045 * 730
        yearly_cost = monthly_cost * 12
        
        result = {
            'nat_gateway_id': nat_id,
            'vpc_id': vpc_id,
            'subnet_id': subnet_id,
            'data_processed_gb': round(total_gb, 2),
            'packets_processed': int(total_packets),
            'avg_connections': round(avg_connections, 2),
            'is_idle': is_idle,
            'idle_reasons': reasons,
            'estimated_monthly_cost': round(monthly_cost, 2),
            'estimated_yearly_cost': round(yearly_cost, 2)
        }
        
        if is_idle:
            print(f"\n   ⚠️  IDLE NAT GATEWAY DETECTED!")
            print(f"   Reasons: {', '.join(reasons)}")
            print(f"   💰 Wasting: ${monthly_cost:.2f}/month (${yearly_cost:.2f}/year)")
            idle_nats.append(result)
        else:
            print(f"\n   ✅ NAT Gateway appears ACTIVE")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE NAT GATEWAY SUMMARY")
    print("=" * 80)
    
    if idle_nats:
        print(f"\n⚠️  Found {len(idle_nats)} idle NAT Gateway(s):\n")
        total_waste = 0
        for i, nat in enumerate(idle_nats, 1):
            print(f"{i}. {nat['nat_gateway_id']}")
            print(f"   VPC: {nat['vpc_id']}")
            print(f"   Data: {nat['data_processed_gb']} GB | Packets: {nat['packets_processed']}")
            print(f"   Connections: {nat['avg_connections']}")
            print(f"   Reasons: {', '.join(nat['idle_reasons'])}")
            print(f"   Monthly Waste: ${nat['estimated_monthly_cost']}")
            print(f"   Yearly Waste: ${nat['estimated_yearly_cost']}")
            print()
            total_waste += nat['estimated_monthly_cost']
        
        print(f"💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_waste:.2f}")
        print(f"💰 TOTAL POTENTIAL YEARLY SAVINGS: ${total_waste * 12:.2f}")
        print("\n💡 Recommendation: Consider deleting idle NAT Gateways")
    else:
        print("\n✅ No idle NAT Gateways found!")
    
    return idle_nats


def check_idle_vpc_endpoints(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle VPC Endpoints with no traffic
    """
    
    print("\n" + "=" * 80)
    print("🔗 VPC ENDPOINT IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="VPCEndpointChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            ec2 = boto3.client(
                'ec2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    # Get all VPC Endpoints
    print(f"\n📊 Fetching VPC Endpoints in {region}...")
    try:
        endpoints = ec2.describe_vpc_endpoints()['VpcEndpoints']
    except Exception as e:
        print(f"❌ Failed to describe VPC Endpoints: {e}")
        return []
    
    # Filter to available endpoints
    endpoints = [ep for ep in endpoints if ep['State'] == 'available']
    print(f"✅ Found {len(endpoints)} VPC Endpoints")
    
    if not endpoints:
        print("No VPC Endpoints to check")
        return []
    
    # Time range for metrics (last 7 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    idle_endpoints = []
    
    for endpoint in endpoints:
        endpoint_id = endpoint['VpcEndpointId']
        service_name = endpoint['ServiceName']
        vpc_id = endpoint['VpcId']
        endpoint_type = endpoint['VpcEndpointType']
        
        print(f"\n{'─' * 60}")
        print(f"🔍 Checking VPC Endpoint: {endpoint_id}")
        print(f"   Service: {service_name}")
        print(f"   Type: {endpoint_type} | VPC: {vpc_id}")
        
        # Check requests through endpoint
        try:
            if 'interface' in endpoint_type.lower():
                # For interface endpoints
                requests = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='PacketsIn',
                    Dimensions=[{'Name': 'VpcEndpointId', 'Value': endpoint_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                total_requests = sum(dp['Sum'] for dp in requests.get('Datapoints', []))
                print(f"   📊 Packets (7 days): {int(total_requests)}")
            else:
                # For gateway endpoints (S3, DynamoDB)
                total_requests = 0
                print(f"   📊 Gateway endpoint - check via VPC Flow Logs")
        except:
            total_requests = 0
            print(f"   📊 No metric data available")
        
        # Determine if idle
        is_idle = False
        reasons = []
        
        if total_requests == 0:
            reasons.append("No traffic through endpoint in past 7 days")
        
        # Check endpoint age if possible
        created_date = endpoint.get('CreationTimestamp')
        if created_date:
            age_days = (datetime.now(created_date.tzinfo) - created_date).days
            if age_days > 30 and total_requests == 0:
                reasons.append(f"Endpoint {age_days} days old with no traffic")
        
        if len(reasons) >= 1:
            is_idle = True
        
        # VPC Endpoint costs (approximately)
        monthly_cost = 0.01 * 730  # $0.01 per hour
        if 'gateway' in endpoint_type.lower():
            monthly_cost = 0  # Gateway endpoints are free
        
        result = {
            'endpoint_id': endpoint_id,
            'service_name': service_name,
            'endpoint_type': endpoint_type,
            'vpc_id': vpc_id,
            'total_packets': int(total_requests),
            'is_idle': is_idle,
            'idle_reasons': reasons,
            'estimated_monthly_cost': round(monthly_cost, 2),
            'estimated_yearly_cost': round(monthly_cost * 12, 2)
        }
        
        if is_idle and endpoint_type != 'gateway':
            print(f"\n   ⚠️  IDLE VPC ENDPOINT DETECTED!")
            print(f"   Reasons: {', '.join(reasons)}")
            print(f"   💰 Wasting: ${monthly_cost:.2f}/month")
            idle_endpoints.append(result)
        else:
            print(f"\n   ✅ VPC Endpoint appears ACTIVE or free")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE VPC ENDPOINT SUMMARY")
    print("=" * 80)
    
    if idle_endpoints:
        print(f"\n⚠️  Found {len(idle_endpoints)} idle VPC Endpoint(s):\n")
        total_waste = 0
        for i, ep in enumerate(idle_endpoints, 1):
            print(f"{i}. {ep['endpoint_id']}")
            print(f"   Service: {ep['service_name']}")
            print(f"   Type: {ep['endpoint_type']}")
            print(f"   Packets: {ep['total_packets']}")
            print(f"   Reasons: {', '.join(ep['idle_reasons'])}")
            print(f"   Monthly Waste: ${ep['estimated_monthly_cost']}")
            print()
            total_waste += ep['estimated_monthly_cost']
        
        print(f"💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_waste:.2f}")
    else:
        print("\n✅ No idle VPC Endpoints found!")
    
    return idle_endpoints

# api_gateway_cloudwatch_checker.py
# Run in Django shell: python manage.py shell

import boto3
from datetime import datetime, timedelta
from django.conf import settings

def check_idle_api_gateways(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle/underutilized API Gateway APIs
    Checks: REST APIs, HTTP APIs, WebSocket APIs
    Metrics: Request count, data transferred, latency
    """
    
    print("=" * 80)
    print("🌐 API GATEWAY IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="APIGWIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            apigw = boto3.client(
                'apigateway',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            apigwv2 = boto3.client(
                'apigatewayv2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return []
    else:
        apigw = boto3.client('apigateway', region_name=region)
        apigwv2 = boto3.client('apigatewayv2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    idle_apis = []
    
    # Time range for metrics (last 30 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30)
    start_time_7d = end_time - timedelta(days=7)
    
    # ============================================================
    # 1. Check REST APIs (API Gateway v1)
    # ============================================================
    print(f"\n📊 Fetching REST APIs in {region}...")
    try:
        rest_apis = apigw.get_rest_apis()['items']
        print(f"✅ Found {len(rest_apis)} REST APIs")
        
        for api in rest_apis:
            api_id = api['id']
            api_name = api.get('name', 'Unnamed')
            created_date = api.get('createdDate')
            
            print(f"\n{'─' * 60}")
            print(f"🔍 Checking REST API: {api_name} ({api_id})")
            
            # Get API stages to check deployments
            try:
                stages = apigw.get_stages(restApiId=api_id)['item']
                active_stages = [s for s in stages if s.get('deploymentId')]
                print(f"   Stages: {len(active_stages)} active")
            except:
                active_stages = []
            
            # Check request count (last 30 days)
            total_requests = 0
            try:
                metrics = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Count',
                    Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                total_requests = sum(dp['Sum'] for dp in metrics.get('Datapoints', []))
                print(f"   📊 Total Requests (30 days): {int(total_requests)}")
            except Exception as e:
                print(f"   📊 Request count: No data available")
            
            # Check requests in last 7 days
            requests_7d = 0
            try:
                metrics_7d = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Count',
                    Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                    StartTime=start_time_7d,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                requests_7d = sum(dp['Sum'] for dp in metrics_7d.get('Datapoints', []))
                print(f"   📊 Total Requests (7 days): {int(requests_7d)}")
            except:
                pass
            
            # Check data transfer (response bytes)
            data_transfer_gb = 0
            try:
                latency_metrics = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Latency',
                    Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Average']
                )
            except:
                pass
            
            # Determine if idle
            is_idle = False
            reasons = []
            
            if total_requests == 0:
                reasons.append("Zero API requests in past 30 days")
            elif total_requests < 1000:
                reasons.append(f"Very low usage ({int(total_requests)} requests in 30 days)")
            
            if requests_7d == 0 and total_requests > 0:
                reasons.append("No requests in past 7 days")
            
            if len(active_stages) == 0:
                reasons.append("No active deployment stages")
            
            if len(reasons) >= 1:
                is_idle = True
            
            # Calculate potential cost (simplified)
            # REST API: $3.50 per million requests + data transfer
            monthly_cost = 0
            if total_requests > 0:
                monthly_cost = (total_requests / 1000000) * 3.50
            
            result = {
                'api_id': api_id,
                'api_name': api_name,
                'api_type': 'REST',
                'total_requests_30d': int(total_requests),
                'requests_7d': int(requests_7d),
                'active_stages': len(active_stages),
                'is_idle': is_idle,
                'idle_reasons': reasons,
                'estimated_monthly_cost': round(monthly_cost, 2),
                'created_date': str(created_date) if created_date else 'Unknown'
            }
            
            if is_idle:
                print(f"\n   ⚠️  IDLE REST API DETECTED!")
                print(f"   Reasons: {', '.join(reasons)}")
                print(f"   💰 Monthly cost (if used): ${monthly_cost:.2f}")
                idle_apis.append(result)
            else:
                print(f"\n   ✅ REST API appears ACTIVE")
                
    except Exception as e:
        print(f"❌ Error checking REST APIs: {e}")
    
    # ============================================================
    # 2. Check HTTP/WebSocket APIs (API Gateway v2)
    # ============================================================
    print(f"\n📊 Fetching HTTP/WebSocket APIs in {region}...")
    try:
        http_apis = apigwv2.get_apis()['Items']
        print(f"✅ Found {len(http_apis)} HTTP/WebSocket APIs")
        
        for api in http_apis:
            api_id = api['ApiId']
            api_name = api.get('Name', 'Unnamed')
            api_type = api.get('ProtocolType', 'HTTP')
            
            print(f"\n{'─' * 60}")
            print(f"🔍 Checking {api_type} API: {api_name} ({api_id})")
            
            # Check request count
            total_requests = 0
            try:
                # For HTTP APIs
                metrics = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Count',
                    Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                total_requests = sum(dp['Sum'] for dp in metrics.get('Datapoints', []))
                print(f"   📊 Total Requests (30 days): {int(total_requests)}")
            except:
                # Try different namespace for HTTP APIs
                try:
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ApiGateway',
                        MetricName='Count',
                        Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum']
                    )
                    total_requests = sum(dp['Sum'] for dp in metrics.get('Datapoints', []))
                    print(f"   📊 Total Requests (30 days): {int(total_requests)}")
                except:
                    print(f"   📊 Request count: No data available")
            
            # Check requests in last 7 days
            requests_7d = 0
            try:
                metrics_7d = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Count',
                    Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                    StartTime=start_time_7d,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                requests_7d = sum(dp['Sum'] for dp in metrics_7d.get('Datapoints', []))
                print(f"   📊 Total Requests (7 days): {int(requests_7d)}")
            except:
                pass
            
            # For WebSocket APIs, check connection count
            avg_connections = 0
            if api_type == 'WEBSOCKET':
                try:
                    conn_metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ApiGateway',
                        MetricName='ConnectionCount',
                        Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                        StartTime=start_time_7d,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    if conn_metrics.get('Datapoints'):
                        avg_connections = sum(dp['Average'] for dp in conn_metrics['Datapoints']) / len(conn_metrics['Datapoints'])
                    print(f"   🔌 Avg Connections: {avg_connections:.2f}")
                except:
                    pass
            
            # Determine if idle
            is_idle = False
            reasons = []
            
            if total_requests == 0:
                reasons.append("Zero API requests in past 30 days")
            elif total_requests < 1000:
                reasons.append(f"Very low usage ({int(total_requests)} requests in 30 days)")
            
            if requests_7d == 0 and total_requests > 0:
                reasons.append("No requests in past 7 days")
            
            if api_type == 'WEBSOCKET' and avg_connections == 0:
                reasons.append("No active WebSocket connections")
            
            if len(reasons) >= 1:
                is_idle = True
            
            # Calculate potential cost
            # HTTP API: $1.00 per million requests
            monthly_cost = 0
            if total_requests > 0:
                monthly_cost = (total_requests / 1000000) * 1.00
            
            result = {
                'api_id': api_id,
                'api_name': api_name,
                'api_type': api_type,
                'total_requests_30d': int(total_requests),
                'requests_7d': int(requests_7d),
                'avg_connections': round(avg_connections, 2),
                'is_idle': is_idle,
                'idle_reasons': reasons,
                'estimated_monthly_cost': round(monthly_cost, 2)
            }
            
            if is_idle:
                print(f"\n   ⚠️  IDLE {api_type} API DETECTED!")
                print(f"   Reasons: {', '.join(reasons)}")
                print(f"   💰 Monthly cost (if used): ${monthly_cost:.2f}")
                idle_apis.append(result)
            else:
                print(f"\n   ✅ {api_type} API appears ACTIVE")
                
    except Exception as e:
        print(f"❌ Error checking HTTP/WebSocket APIs: {e}")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 IDLE API GATEWAY SUMMARY")
    print("=" * 80)
    
    if idle_apis:
        print(f"\n⚠️  Found {len(idle_apis)} idle/underutilized API(s):\n")
        for i, api in enumerate(idle_apis, 1):
            print(f"{i}. {api['api_name']} ({api['api_id']}) - {api['api_type']}")
            print(f"   Requests: {api['total_requests_30d']} (30d) | {api['requests_7d']} (7d)")
            print(f"   Reasons: {', '.join(api['idle_reasons'])}")
            if api['estimated_monthly_cost'] > 0:
                print(f"   Monthly Cost: ${api['estimated_monthly_cost']}")
            print()
    else:
        print("\n✅ No idle API Gateway APIs found!")
    
    return idle_apis


def check_idle_cloudwatch_resources(role_arn=None, external_id=None, region='us-east-1'):
    """
    Check for idle/underutilized CloudWatch resources
    Checks: Log groups, Metrics, Alarms, Dashboards
    """
    
    print("\n" + "=" * 80)
    print("📊 CLOUDWATCH IDLE DETECTION")
    print("=" * 80)
    
    # Assume role if provided
    if role_arn and external_id:
        print(f"\n📡 Assuming IAM Role: {role_arn}")
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="CWIdleChecker",
                ExternalId=str(external_id)
            )
            credentials = response["Credentials"]
            
            logs = boto3.client(
                'logs',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            cloudwatch = boto3.client(
                'cloudwatch',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            return {}
    else:
        logs = boto3.client('logs', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    idle_resources = {
        'log_groups': [],
        'alarms': [],
        'dashboards': [],
        'metrics': []
    }
    
    # Time range for metrics (last 30 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30)
    
    # ============================================================
    # 1. Check CloudWatch Log Groups
    # ============================================================
    print(f"\n📊 Fetching CloudWatch Log Groups in {region}...")
    try:
        log_groups = []
        next_token = None
        while True:
            if next_token:
                response = logs.describe_log_groups(nextToken=next_token)
            else:
                response = logs.describe_log_groups()
            
            log_groups.extend(response['logGroups'])
            next_token = response.get('nextToken')
            if not next_token:
                break
        
        print(f"✅ Found {len(log_groups)} Log Groups")
        
        for lg in log_groups:
            log_group_name = lg['logGroupName']
            stored_bytes = lg.get('storedBytes', 0)
            stored_gb = stored_bytes / (1024 * 1024 * 1024)
            retention_days = lg.get('retentionInDays', 0)
            
            # Get log events in last 30 days
            try:
                # Check if any log streams exist
                streams = logs.describe_log_streams(
                    logGroupName=log_group_name,
                    limit=1
                )
                
                if streams['logStreams']:
                    # Get latest event time
                    latest_stream = streams['logStreams'][0]
                    if 'lastIngestionTime' in latest_stream:
                        last_ingestion = datetime.fromtimestamp(latest_stream['lastIngestionTime'] / 1000)
                        days_since_last = (datetime.now() - last_ingestion).days
                    else:
                        days_since_last = 999
                else:
                    days_since_last = 999
                    
            except Exception as e:
                days_since_last = 999
            
            print(f"\n{'─' * 60}")
            print(f"🔍 Checking Log Group: {log_group_name}")
            print(f"   Storage: {stored_gb:.2f} GB | Retention: {retention_days} days")
            print(f"   Days since last log: {days_since_last}")
            
            is_idle = False
            reasons = []
            
            if stored_bytes == 0 or stored_gb < 0.001:
                reasons.append("No logs stored (empty log group)")
            elif stored_gb < 0.01:
                reasons.append(f"Minimal logs stored ({stored_gb:.4f} GB)")
            
            if days_since_last > 30:
                reasons.append(f"No logs ingested in {days_since_last} days")
            
            if retention_days == 0:
                reasons.append("No retention policy set (logs stored indefinitely)")
            
            if len(reasons) >= 2:
                is_idle = True
            
            # Calculate monthly cost
            monthly_cost = stored_gb * 0.50  # $0.50 per GB ingested (approximate)
            
            result = {
                'log_group_name': log_group_name,
                'stored_gb': round(stored_gb, 2),
                'retention_days': retention_days,
                'days_since_last_log': days_since_last,
                'is_idle': is_idle,
                'idle_reasons': reasons,
                'estimated_monthly_cost': round(monthly_cost, 2)
            }
            
            if is_idle:
                print(f"\n   ⚠️  IDLE LOG GROUP DETECTED!")
                print(f"   Reasons: {', '.join(reasons)}")
                idle_resources['log_groups'].append(result)
            else:
                print(f"\n   ✅ Log Group appears ACTIVE")
                
    except Exception as e:
        print(f"❌ Error checking log groups: {e}")
    
    # ============================================================
    # 2. Check CloudWatch Alarms
    # ============================================================
    print(f"\n📊 Fetching CloudWatch Alarms in {region}...")
    try:
        alarms = cloudwatch.describe_alarms()['MetricAlarms']
        print(f"✅ Found {len(alarms)} Alarms")
        
        for alarm in alarms:
            alarm_name = alarm['AlarmName']
            state = alarm['StateValue']
            actions_enabled = alarm.get('ActionsEnabled', False)
            
            print(f"\n{'─' * 60}")
            print(f"🔍 Checking Alarm: {alarm_name}")
            print(f"   State: {state} | Actions Enabled: {actions_enabled}")
            
            is_idle = False
            reasons = []
            
            if state == 'INSUFFICIENT_DATA':
                reasons.append("Alarm has insufficient data (never triggered)")
            
            if not actions_enabled:
                reasons.append("Alarm actions disabled (no notifications)")
            
            if state == 'OK' and not actions_enabled:
                reasons.append("Alarm in OK state with no actions")
            
            if len(reasons) >= 1:
                is_idle = True
            
            result = {
                'alarm_name': alarm_name,
                'state': state,
                'actions_enabled': actions_enabled,
                'is_idle': is_idle,
                'idle_reasons': reasons,
                'estimated_monthly_cost': 0.10  # $0.10 per alarm-month
            }
            
            if is_idle:
                print(f"\n   ⚠️  IDLE ALARM DETECTED!")
                print(f"   Reasons: {', '.join(reasons)}")
                idle_resources['alarms'].append(result)
            else:
                print(f"\n   ✅ Alarm appears ACTIVE")
                
    except Exception as e:
        print(f"❌ Error checking alarms: {e}")
    
    # ============================================================
    # 3. Check CloudWatch Dashboards
    # ============================================================
    print(f"\n📊 Fetching CloudWatch Dashboards in {region}...")
    try:
        dashboards = cloudwatch.list_dashboards()['DashboardEntries']
        print(f"✅ Found {len(dashboards)} Dashboards")
        
        for dashboard in dashboards:
            dashboard_name = dashboard['DashboardName']
            last_modified = dashboard.get('LastModified')
            
            if last_modified:
                days_since_modified = (datetime.now(last_modified.tzinfo) - last_modified).days
            else:
                days_since_modified = 999
            
            print(f"\n{'─' * 60}")
            print(f"🔍 Checking Dashboard: {dashboard_name}")
            print(f"   Last modified: {days_since_modified} days ago")
            
            is_idle = False
            reasons = []
            
            if days_since_modified > 90:
                reasons.append(f"Dashboard not modified in {days_since_modified} days")
            
            if len(reasons) >= 1:
                is_idle = True
            
            result = {
                'dashboard_name': dashboard_name,
                'days_since_modified': days_since_modified,
                'is_idle': is_idle,
                'idle_reasons': reasons,
                'estimated_monthly_cost': 0  # Dashboards are free
            }
            
            if is_idle:
                print(f"\n   ⚠️  IDLE DASHBOARD DETECTED!")
                print(f"   Reasons: {', '.join(reasons)}")
                idle_resources['dashboards'].append(result)
            else:
                print(f"\n   ✅ Dashboard appears ACTIVE")
                
    except Exception as e:
        print(f"❌ Error checking dashboards: {e}")
    
    # ============================================================
    # 4. Check Custom Metrics
    # ============================================================
    print(f"\n📊 Fetching Custom Metrics in {region}...")
    try:
        # Get custom metrics (non-AWS namespaces)
        metrics = cloudwatch.list_metrics()['Metrics']
        
        # Filter for custom metrics (not starting with AWS/)
        custom_metrics = [m for m in metrics if not m['Namespace'].startswith('AWS/')]
        print(f"✅ Found {len(custom_metrics)} Custom Metrics")
        
        # Check if custom metrics are being used
        active_custom_metrics = []
        idle_custom_metrics = []
        
        for metric in custom_metrics[:50]:  # Limit to 50 for performance
            namespace = metric['Namespace']
            metric_name = metric['MetricName']
            
            try:
                # Check if metric has any data points in last 30 days
                stats = cloudwatch.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    Dimensions=metric.get('Dimensions', []),
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Average']
                )
                
                if stats.get('Datapoints'):
                    active_custom_metrics.append(f"{namespace}/{metric_name}")
                else:
                    idle_custom_metrics.append({
                        'namespace': namespace,
                        'metric_name': metric_name,
                        'is_idle': True,
                        'idle_reasons': ['No data points in past 30 days'],
                        'estimated_monthly_cost': 0.30  # $0.30 per custom metric
                    })
            except:
                idle_custom_metrics.append({
                    'namespace': namespace,
                    'metric_name': metric_name,
                    'is_idle': True,
                    'idle_reasons': ['Unable to query metric data'],
                    'estimated_monthly_cost': 0.30
                })
        
        print(f"   Active custom metrics: {len(active_custom_metrics)}")
        print(f"   Idle custom metrics: {len(idle_custom_metrics)}")
        
        idle_resources['metrics'] = idle_custom_metrics
        
    except Exception as e:
        print(f"❌ Error checking custom metrics: {e}")
    
    # Print summary
    print("\n" + "=" * 80)
    print("📊 CLOUDWATCH IDLE RESOURCES SUMMARY")
    print("=" * 80)
    
    if idle_resources['log_groups']:
        print(f"\n⚠️  Idle Log Groups: {len(idle_resources['log_groups'])}")
        total_waste = sum(lg['estimated_monthly_cost'] for lg in idle_resources['log_groups'])
        for lg in idle_resources['log_groups'][:5]:
            print(f"   • {lg['log_group_name']}: {', '.join(lg['idle_reasons'][:2])}")
        if total_waste > 0:
            print(f"   💰 Monthly waste: ${total_waste:.2f}")
    
    if idle_resources['alarms']:
        print(f"\n⚠️  Idle Alarms: {len(idle_resources['alarms'])}")
        for alarm in idle_resources['alarms'][:5]:
            print(f"   • {alarm['alarm_name']}: {', '.join(alarm['idle_reasons'])}")
    
    if idle_resources['dashboards']:
        print(f"\n⚠️  Idle Dashboards: {len(idle_resources['dashboards'])}")
        for dash in idle_resources['dashboards'][:5]:
            print(f"   • {dash['dashboard_name']}: {', '.join(dash['idle_reasons'])}")
    
    if idle_resources['metrics']:
        print(f"\n⚠️  Idle Custom Metrics: {len(idle_resources['metrics'])}")
        for metric in idle_resources['metrics'][:5]:
            print(f"   • {metric['namespace']}/{metric['metric_name']}")
    
    if not any(idle_resources.values()):
        print("\n✅ No idle CloudWatch resources found!")
    
    return idle_resources

# idle_resources_db.py

import logging
from django.utils import timezone
from django.db import transaction
from decimal import Decimal

logger = logging.getLogger(__name__)


def get_cached_idle_results(user, aws_account, force_refresh=False):
    """
    Get cached idle resources from database
    Only makes AWS API calls if force_refresh=True or no cache exists
    """
    from .models import (
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway, IdleCloudWatchLogGroup,
        IdleCloudWatchAlarm, IdleCloudWatchDashboard, IdleCloudWatchMetric
    )
    
    # Check if we have cached results
    cached_ec2 = IdleEC2Instance.objects.filter(aws_account=aws_account, is_resolved=False)
    
    if not force_refresh and cached_ec2.exists():
        logger.info(f"📦 Using cached idle resources: {cached_ec2.count()} EC2 instances")
        
        # Build response from cached data
        return {
            'success': True,
            'cached': True,
            'total_findings': _count_total_findings(aws_account),
            'total_savings': float(_calculate_total_savings(aws_account)),
            'ec2_instances': _get_cached_ec2_instances(aws_account),
            'auto_scaling_groups': _get_cached_auto_scaling_groups(aws_account),
            'load_balancers': _get_cached_load_balancers(aws_account),
            'lambda_functions': _get_cached_lambda_functions(aws_account),
            'ecs_services': _get_cached_ecs_services(aws_account),
            'nat_gateways': _get_cached_nat_gateways(aws_account),
            'vpc_endpoints': _get_cached_vpc_endpoints(aws_account),
            'api_gateways': _get_cached_api_gateways(aws_account),
            'cloudwatch': _get_cached_cloudwatch_resources(aws_account)
        }
    
    return None


def _count_total_findings(aws_account):
    """Helper to count total findings"""
    from .models import (
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway
    )
    
    return (
        IdleEC2Instance.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleAutoScalingGroup.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleLoadBalancer.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleLambdaFunction.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleECSService.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleNATGateway.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleVPCEndpoint.objects.filter(aws_account=aws_account, is_resolved=False).count() +
        IdleAPIGateway.objects.filter(aws_account=aws_account, is_resolved=False).count()
    )


def _calculate_total_savings(aws_account):
    """Helper to calculate total savings"""
    from .models import (
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway, IdleCloudWatchLogGroup,
        IdleCloudWatchAlarm, IdleCloudWatchMetric
    )
    
    total = 0
    total += sum(i.monthly_cost for i in IdleEC2Instance.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(a.monthly_cost for a in IdleAutoScalingGroup.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(l.monthly_cost for l in IdleLoadBalancer.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(f.monthly_cost for f in IdleLambdaFunction.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(s.monthly_cost for s in IdleECSService.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(n.monthly_cost for n in IdleNATGateway.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(v.monthly_cost for v in IdleVPCEndpoint.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(a.monthly_cost for a in IdleAPIGateway.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(l.monthly_cost for l in IdleCloudWatchLogGroup.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(a.monthly_cost for a in IdleCloudWatchAlarm.objects.filter(aws_account=aws_account, is_resolved=False))
    total += sum(m.monthly_cost for m in IdleCloudWatchMetric.objects.filter(aws_account=aws_account, is_resolved=False))
    
    return total


def _get_cached_ec2_instances(aws_account):
    """Get cached EC2 instances"""
    from .models import IdleEC2Instance
    
    instances = IdleEC2Instance.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': instances.count(),
        'savings': sum(float(i.monthly_cost) for i in instances),
        'items': [
            {
                'instance_id': i.instance_id,
                'instance_name': i.instance_name,
                'instance_type': i.instance_type,
                'cpu_avg': float(i.cpu_avg),
                'monthly_cost': float(i.monthly_cost),
                'reasons': i.reasons
            }
            for i in instances
        ]
    }


def _get_cached_auto_scaling_groups(aws_account):
    """Get cached Auto Scaling Groups"""
    from .models import IdleAutoScalingGroup
    
    asgs = IdleAutoScalingGroup.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': asgs.count(),
        'savings': sum(float(a.monthly_cost) for a in asgs),
        'items': [
            {
                'asg_name': a.asg_name,
                'min_size': a.min_size,
                'max_size': a.max_size,
                'desired_capacity': a.desired_capacity,
                'current_instances': a.current_instances,
                'avg_cpu': float(a.avg_cpu),
                'monthly_cost': float(a.monthly_cost),
                'reasons': a.reasons
            }
            for a in asgs
        ]
    }


def _get_cached_load_balancers(aws_account):
    """Get cached Load Balancers"""
    from .models import IdleLoadBalancer
    
    lbs = IdleLoadBalancer.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': lbs.count(),
        'savings': sum(float(l.monthly_cost) for l in lbs),
        'items': [
            {
                'lb_name': l.lb_name,
                'lb_type': l.lb_type,
                'lb_scheme': l.lb_scheme,
                'total_requests': l.total_requests,
                'processed_gb': float(l.processed_gb),
                'healthy_targets': l.healthy_targets,
                'total_targets': l.total_targets,
                'monthly_cost': float(l.monthly_cost),
                'reasons': l.reasons
            }
            for l in lbs
        ]
    }


def _get_cached_lambda_functions(aws_account):
    """Get cached Lambda functions"""
    from .models import IdleLambdaFunction
    
    funcs = IdleLambdaFunction.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': funcs.count(),
        'savings': sum(float(f.monthly_cost) for f in funcs),
        'items': [
            {
                'function_name': f.function_name,
                'runtime': f.runtime,
                'memory_mb': f.memory_mb,
                'invocations_30d': f.invocations_30d,
                'invocations_7d': f.invocations_7d,
                'avg_duration_ms': float(f.avg_duration_ms),
                'monthly_cost': float(f.monthly_cost),
                'reasons': f.reasons
            }
            for f in funcs
        ]
    }


def _get_cached_ecs_services(aws_account):
    """Get cached ECS services"""
    from .models import IdleECSService
    
    services = IdleECSService.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': services.count(),
        'savings': sum(float(s.monthly_cost) for s in services),
        'items': [
            {
                'service_name': s.service_name,
                'cluster_name': s.cluster_name,
                'cpu': s.cpu,
                'memory_mb': s.memory_mb,
                'running_tasks': s.running_tasks,
                'desired_tasks': s.desired_tasks,
                'cpu_utilization': float(s.cpu_utilization),
                'memory_utilization': float(s.memory_utilization),
                'monthly_cost': float(s.monthly_cost),
                'reasons': s.reasons
            }
            for s in services
        ]
    }


def _get_cached_nat_gateways(aws_account):
    """Get cached NAT Gateways"""
    from .models import IdleNATGateway
    
    nats = IdleNATGateway.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': nats.count(),
        'savings': sum(float(n.monthly_cost) for n in nats),
        'items': [
            {
                'nat_gateway_id': n.nat_gateway_id,
                'vpc_id': n.vpc_id,
                'data_processed_gb': float(n.data_processed_gb),
                'packets_processed': n.packets_processed,
                'avg_connections': float(n.avg_connections),
                'monthly_cost': float(n.monthly_cost),
                'reasons': n.reasons
            }
            for n in nats
        ]
    }


def _get_cached_vpc_endpoints(aws_account):
    """Get cached VPC Endpoints"""
    from .models import IdleVPCEndpoint
    
    endpoints = IdleVPCEndpoint.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': endpoints.count(),
        'savings': sum(float(e.monthly_cost) for e in endpoints),
        'items': [
            {
                'endpoint_id': e.endpoint_id,
                'service_name': e.service_name,
                'endpoint_type': e.endpoint_type,
                'total_packets': e.total_packets,
                'monthly_cost': float(e.monthly_cost),
                'reasons': e.reasons
            }
            for e in endpoints
        ]
    }


def _get_cached_api_gateways(aws_account):
    """Get cached API Gateways"""
    from .models import IdleAPIGateway
    
    apis = IdleAPIGateway.objects.filter(aws_account=aws_account, is_resolved=False)
    return {
        'count': apis.count(),
        'savings': sum(float(a.monthly_cost) for a in apis),
        'items': [
            {
                'api_id': a.api_id,
                'api_name': a.api_name,
                'api_type': a.api_type,
                'total_requests_30d': a.total_requests_30d,
                'requests_7d': a.requests_7d,
                'monthly_cost': float(a.monthly_cost),
                'reasons': a.reasons
            }
            for a in apis
        ]
    }


def _get_cached_cloudwatch_resources(aws_account):
    """Get cached CloudWatch resources"""
    from .models import (
        IdleCloudWatchLogGroup, IdleCloudWatchAlarm,
        IdleCloudWatchDashboard, IdleCloudWatchMetric
    )
    
    log_groups = IdleCloudWatchLogGroup.objects.filter(aws_account=aws_account, is_resolved=False)
    alarms = IdleCloudWatchAlarm.objects.filter(aws_account=aws_account, is_resolved=False)
    dashboards = IdleCloudWatchDashboard.objects.filter(aws_account=aws_account, is_resolved=False)
    metrics = IdleCloudWatchMetric.objects.filter(aws_account=aws_account, is_resolved=False)
    
    return {
        'log_groups': {
            'count': log_groups.count(),
            'savings': sum(float(l.monthly_cost) for l in log_groups),
            'items': [
                {
                    'log_group_name': l.log_group_name,
                    'stored_gb': float(l.stored_gb),
                    'retention_days': l.retention_days,
                    'days_since_last_log': l.days_since_last_log,
                    'monthly_cost': float(l.monthly_cost),
                    'reasons': l.reasons
                }
                for l in log_groups
            ]
        },
        'alarms': {
            'count': alarms.count(),
            'savings': sum(float(a.monthly_cost) for a in alarms),
            'items': [
                {
                    'alarm_name': a.alarm_name,
                    'state': a.state,
                    'actions_enabled': a.actions_enabled,
                    'monthly_cost': float(a.monthly_cost),
                    'reasons': a.reasons
                }
                for a in alarms
            ]
        },
        'dashboards': {
            'count': dashboards.count(),
            'items': [
                {
                    'dashboard_name': d.dashboard_name,
                    'days_since_modified': d.days_since_modified,
                    'reasons': d.reasons
                }
                for d in dashboards
            ]
        },
        'metrics': {
            'count': metrics.count(),
            'savings': sum(float(m.monthly_cost) for m in metrics),
            'items': [
                {
                    'namespace': m.namespace,
                    'metric_name': m.metric_name,
                    'monthly_cost': float(m.monthly_cost),
                    'reasons': m.reasons
                }
                for m in metrics
            ]
        }
    }


def clear_all_idle_data(aws_account):
    """
    Clear all idle resources data from database
    """
    from .models import (
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway, IdleCloudWatchLogGroup,
        IdleCloudWatchAlarm, IdleCloudWatchDashboard, IdleCloudWatchMetric
    )
    
    with transaction.atomic():
        ec2_count = IdleEC2Instance.objects.filter(aws_account=aws_account).delete()[0]
        asg_count = IdleAutoScalingGroup.objects.filter(aws_account=aws_account).delete()[0]
        lb_count = IdleLoadBalancer.objects.filter(aws_account=aws_account).delete()[0]
        lambda_count = IdleLambdaFunction.objects.filter(aws_account=aws_account).delete()[0]
        ecs_count = IdleECSService.objects.filter(aws_account=aws_account).delete()[0]
        nat_count = IdleNATGateway.objects.filter(aws_account=aws_account).delete()[0]
        vpce_count = IdleVPCEndpoint.objects.filter(aws_account=aws_account).delete()[0]
        api_count = IdleAPIGateway.objects.filter(aws_account=aws_account).delete()[0]
        log_count = IdleCloudWatchLogGroup.objects.filter(aws_account=aws_account).delete()[0]
        alarm_count = IdleCloudWatchAlarm.objects.filter(aws_account=aws_account).delete()[0]
        dashboard_count = IdleCloudWatchDashboard.objects.filter(aws_account=aws_account).delete()[0]
        metric_count = IdleCloudWatchMetric.objects.filter(aws_account=aws_account).delete()[0]
        
        total = (ec2_count + asg_count + lb_count + lambda_count + ecs_count + 
                nat_count + vpce_count + api_count + log_count + alarm_count + 
                dashboard_count + metric_count)
        
        logger.info(f"🗑️ Cleared {total} idle resource records")
        
        return total