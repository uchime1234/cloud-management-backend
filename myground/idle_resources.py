# myground/idle_resources.py
"""
Idle Resources Detection — production grade

Every detector:
  - accepts `aws_account` so it can record permission errors
  - returns a structured dict:
        {
            'detector': '<id>',
            'success': bool,          # did the scan itself succeed
            'scanned': bool,          # did we actually get to look
            'items': [...],
            'errors': [...],          # list of {code, message, permission}
            'total_savings': float,
            'count': int,
        }
  - never raises — always returns a result dict so a single detector
    failure does not crash the whole scan.
"""

import boto3
from datetime import datetime, timedelta
from decimal import Decimal
import logging

from django.conf import settings
from botocore.exceptions import ClientError

from .idle_error_handler import handle_aws_error, clear_detector_errors

logger = logging.getLogger(__name__)


# ============================================================
# HELPER: build an STS-assumed set of boto3 clients
# ============================================================

def _assume_and_clients(role_arn, external_id, region, services, aws_account=None, detector=None):
    """
    Assume role and return a dict of {service_name: boto3_client}.
    On failure, records the error and returns None.
    """
    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
        )
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"IdleScan_{detector or 'generic'}",
            ExternalId=str(external_id),
        )
        creds = response["Credentials"]

        clients = {}
        for svc in services:
            clients[svc] = boto3.client(
                svc,
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region,
            )
        return clients

    except ClientError as e:
        if aws_account and detector:
            handle_aws_error(aws_account, detector, e)
        logger.error(f"Assume role failed for {detector}: {e}")
        return None
    except Exception as e:
        logger.error(f"Assume role unexpected error: {e}")
        return None


def _empty_result(detector):
    return {
        'detector': detector,
        'success': True,
        'scanned': False,
        'items': [],
        'errors': [],
        'total_savings': 0.0,
        'count': 0,
    }


# ============================================================
# EC2 INSTANCES
# ============================================================

def check_idle_ec2_instances(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    """
    Comprehensive EC2 idle instance checker.
    Detects idle via CPU + network + disk + LB/ASG membership.
    Only declares idle if CPU data is available AND >= 2 signals fire.
    """
    result = _empty_result('ec2')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['ec2', 'cloudwatch', 'elbv2', 'autoscaling'],
            aws_account=aws_account, detector='ec2',
        )
        if not clients:
            result['success'] = False
            return result
        ec2 = clients['ec2']
        cloudwatch = clients['cloudwatch']
        elbv2 = clients['elbv2']
        autoscaling = clients['autoscaling']
    else:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        elbv2 = boto3.client('elbv2', region_name=region)
        autoscaling = boto3.client('autoscaling', region_name=region)

    # Fetch instances
    try:
        instances_response = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'ec2', e))
        result['success'] = False
        return result
    except Exception as e:
        logger.error(f"EC2 describe failed: {e}")
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'ec2')

    instances = []
    for reservation in instances_response.get('Reservations', []):
        instances.extend(reservation.get('Instances', []))

    if not instances:
        return result

    end_time = datetime.utcnow()
    start_time_7d = end_time - timedelta(days=7)
    start_time_14d = end_time - timedelta(days=14)

    # ASG membership (once)
    asg_instance_ids = set()
    try:
        autoscale_groups = autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']
        for asg in autoscale_groups:
            for inst in asg.get('Instances', []):
                asg_instance_ids.add(inst['InstanceId'])
    except ClientError as e:
        if aws_account and 'AccessDenied' in str(e):
            result['errors'].append(handle_aws_error(aws_account, 'autoscaling', e))
    except Exception:
        pass

    # LB attachment (once)
    lb_attached_ids = set()
    try:
        target_groups = elbv2.describe_target_groups()['TargetGroups']
        for tg in target_groups:
            try:
                targets = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                for t in targets.get('TargetHealthDescriptions', []):
                    t_id = t.get('Target', {}).get('Id')
                    if t_id:
                        lb_attached_ids.add(t_id)
            except Exception:
                continue
    except ClientError as e:
        if aws_account and 'AccessDenied' in str(e):
            result['errors'].append(handle_aws_error(aws_account, 'load_balancer', e))
    except Exception:
        pass

    instance_pricing = {
        't2.micro': 0.0116, 't2.small': 0.023, 't2.medium': 0.0464,
        't3.micro': 0.0104, 't3.small': 0.0208, 't3.medium': 0.0416,
        't4g.micro': 0.0084, 't4g.small': 0.0168, 't4g.medium': 0.0336,
        'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
        'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
        'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
    }

    volume_rate = {
        'gp3': 0.08, 'gp2': 0.10, 'io1': 0.125, 'io2': 0.125,
        'st1': 0.045, 'sc1': 0.025, 'standard': 0.05,
    }

    for instance in instances:
        instance_id = instance['InstanceId']
        instance_name = next(
            (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'),
            'Unnamed',
        )
        instance_type = instance['InstanceType']

        # CPU (7 days)
        avg_cpu = 0.0
        cpu_data_available = False
        try:
            cpu_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_7d,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average'],
            )
            points = cpu_response.get('Datapoints', [])
            logger.info(f"EC2 {instance_id}: CloudWatch returned {len(points)} CPU datapoints")
            if points:
                avg_cpu = sum(p['Average'] for p in points) / len(points)
                cpu_data_available = True
        except ClientError as e:
            if aws_account and 'AccessDenied' in str(e):
                result['errors'].append(handle_aws_error(aws_account, 'cloudwatch_metrics', e))
        except Exception:
            pass

        # Network (14 days)
        network_in = network_out = 0.0
        try:
            ni = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2', MetricName='NetworkIn',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            network_in = sum(p['Sum'] for p in ni.get('Datapoints', [])) / (1024 * 1024)
        except Exception:
            pass
        try:
            no = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2', MetricName='NetworkOut',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            network_out = sum(p['Sum'] for p in no.get('Datapoints', [])) / (1024 * 1024)
        except Exception:
            pass

        # Disk (14 days)
        disk_read = disk_write = 0.0
        try:
            dr = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2', MetricName='DiskReadBytes',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            disk_read = sum(p['Sum'] for p in dr.get('Datapoints', [])) / (1024 * 1024)
        except Exception:
            pass
        try:
            dw = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2', MetricName='DiskWriteBytes',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time_14d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            disk_write = sum(p['Sum'] for p in dw.get('Datapoints', [])) / (1024 * 1024)
        except Exception:
            pass

        in_asg = instance_id in asg_instance_ids
        on_lb = instance_id in lb_attached_ids

        # Decide
        is_idle = False
        reasons = []
        if not cpu_data_available:
            # Cannot judge — no CPU data
            continue

        if avg_cpu < 5:
            reasons.append(f"CPU utilization extremely low ({avg_cpu:.2f}% avg over 7 days)")
        if network_in < 10 and network_out < 10:
            reasons.append(f"Network activity minimal ({network_in + network_out:.2f} MB over 14 days)")
        if disk_read < 50 and disk_write < 50:
            reasons.append(f"Disk I/O minimal ({disk_read + disk_write:.2f} MB over 14 days)")
        if not on_lb and not in_asg:
            reasons.append("Not connected to Load Balancer or Auto Scaling")

        signals = [
            avg_cpu < 5,
            (network_in < 10 and network_out < 10),
            (disk_read < 50 and disk_write < 50),
            (not on_lb and not in_asg),
        ]
        if sum(signals) >= 2:
            is_idle = True

        # Cost
        hourly = instance_pricing.get(instance_type, 0.05)
        monthly_cost = round(hourly * 730, 2)

        # Net savings: subtract attached EBS
        attached_ebs_cost = 0.0
        for bdm in instance.get('BlockDeviceMappings', []):
            volume_id = bdm.get('Ebs', {}).get('VolumeId')
            if volume_id:
                try:
                    vol = ec2.describe_volumes(VolumeIds=[volume_id])
                    for v in vol.get('Volumes', []):
                        size = v.get('Size', 0)
                        vtype = v.get('VolumeType', 'gp2')
                        attached_ebs_cost += size * volume_rate.get(vtype, 0.10)
                except Exception:
                    pass

        net_savings = round(max(0, monthly_cost - attached_ebs_cost), 2)

        if is_idle:
            result['items'].append({
                'instance_id': instance_id,
                'instance_name': instance_name,
                'instance_type': instance_type,
                'metrics': {
                    'avg_cpu': round(avg_cpu, 2),
                    'cpu_data_available': cpu_data_available,
                    'network_in_mb': round(network_in, 2),
                    'network_out_mb': round(network_out, 2),
                    'disk_read_mb': round(disk_read, 2),
                    'disk_write_mb': round(disk_write, 2),
                    'connected_to_lb': on_lb,
                    'in_autoscaling': in_asg,
                },
                'idle_reasons': reasons,
                'estimated_monthly_cost': monthly_cost,
                'attached_ebs_cost': round(attached_ebs_cost, 2),
                'estimated_monthly_savings': net_savings,
                'estimated_yearly_savings': round(net_savings * 12, 2),
            })
            result['total_savings'] += net_savings

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# AUTO SCALING GROUPS
# ============================================================

def check_idle_auto_scaling_groups(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('autoscaling')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['autoscaling', 'cloudwatch', 'ec2'],
            aws_account=aws_account, detector='autoscaling',
        )
        if not clients:
            result['success'] = False
            return result
        autoscaling = clients['autoscaling']
        cloudwatch = clients['cloudwatch']
        ec2 = clients['ec2']
    else:
        autoscaling = boto3.client('autoscaling', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        ec2 = boto3.client('ec2', region_name=region)

    try:
        asgs = autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'autoscaling', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'autoscaling')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    instance_pricing = {
        't2.micro': 0.0116, 't2.small': 0.023, 't3.micro': 0.0104,
        't3.small': 0.0208, 't3.medium': 0.0416, 'm5.large': 0.096,
        'm5.xlarge': 0.192, 'c5.large': 0.085, 'r5.large': 0.126,
    }

    for asg in asgs:
        asg_name = asg['AutoScalingGroupName']
        min_size = asg['MinSize']
        max_size = asg['MaxSize']
        desired = asg['DesiredCapacity']
        instance_ids = [i['InstanceId'] for i in asg.get('Instances', [])]
        current = len(instance_ids)

        reasons = []
        avg_cpu = 0.0

        # CPU across up to 3 instances
        cpu_vals = []
        for iid in instance_ids[:3]:
            try:
                cr = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2', MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'InstanceId', 'Value': iid}],
                    StartTime=start_time, EndTime=end_time,
                    Period=3600, Statistics=['Average'],
                )
                pts = cr.get('Datapoints', [])
                if pts:
                    cpu_vals.append(sum(p['Average'] for p in pts) / len(pts))
            except Exception:
                continue
        if cpu_vals:
            avg_cpu = sum(cpu_vals) / len(cpu_vals)
            if avg_cpu < 10:
                reasons.append(f"Low CPU utilization ({avg_cpu:.2f}% avg over 7 days)")

        # Scaling activity
        try:
            activities = autoscaling.describe_scaling_activities(
                AutoScalingGroupName=asg_name, MaxRecords=10
            )['Activities']
            recent = [a for a in activities if a['StartTime'] > start_time]
            if not recent:
                reasons.append("No scaling activities in the past 7 days")
        except Exception:
            pass

        if min_size > 1 and desired <= min_size:
            reasons.append(f"Min size is {min_size} but workload may only need 1 instance")
        if desired == min_size:
            reasons.append(f"Stuck at minimum size ({min_size})")

        is_idle = len(reasons) >= 2

        if not is_idle:
            continue

        # Estimate cost
        est_monthly = 0.0
        if instance_ids:
            try:
                info = ec2.describe_instances(InstanceIds=[instance_ids[0]])
                itype = info['Reservations'][0]['Instances'][0]['InstanceType']
                est_monthly = instance_pricing.get(itype, 0.05) * 730 * desired
            except Exception:
                est_monthly = desired * 10

        result['items'].append({
            'asg_name': asg_name,
            'min_size': min_size,
            'max_size': max_size,
            'desired_capacity': desired,
            'current_instances': current,
            'avg_cpu': round(avg_cpu, 2),
            'idle_reasons': reasons,
            'estimated_monthly_cost': round(est_monthly, 2),
            'estimated_monthly_savings': round(est_monthly, 2),
            'estimated_yearly_savings': round(est_monthly * 12, 2),
        })
        result['total_savings'] += est_monthly

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# LOAD BALANCERS
# ============================================================

def check_idle_load_balancers(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('load_balancer')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['elbv2', 'cloudwatch'],
            aws_account=aws_account, detector='load_balancer',
        )
        if not clients:
            result['success'] = False
            return result
        elbv2 = clients['elbv2']
        cloudwatch = clients['cloudwatch']
    else:
        elbv2 = boto3.client('elbv2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    try:
        lbs = elbv2.describe_load_balancers()['LoadBalancers']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'load_balancer', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'load_balancer')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    for lb in lbs:
        lb_name = lb['LoadBalancerName']
        lb_type = lb['Type']
        lb_arn = lb['LoadBalancerArn']
        lb_scheme = lb.get('Scheme', 'internal')

        total_requests = 0
        try:
            rc = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApplicationELB', MetricName='RequestCount',
                Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_arn}],
                StartTime=start_time, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            total_requests = int(sum(p['Sum'] for p in rc.get('Datapoints', [])))
        except Exception:
            pass

        total_gb = 0.0
        try:
            pb = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApplicationELB', MetricName='ProcessedBytes',
                Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_arn}],
                StartTime=start_time, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            total_gb = sum(p['Sum'] for p in pb.get('Datapoints', [])) / (1024 ** 3)
        except Exception:
            pass

        healthy_targets = 0
        total_targets = 0
        try:
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
            for tg in tgs:
                try:
                    health = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                    for t in health.get('TargetHealthDescriptions', []):
                        total_targets += 1
                        if t['TargetHealth']['State'] == 'healthy':
                            healthy_targets += 1
                except Exception:
                    continue
        except Exception:
            pass

        reasons = []
        if total_requests == 0:
            reasons.append("Zero requests in past 7 days")
        if total_gb < 0.001:
            reasons.append(f"No data processed ({total_gb:.4f} GB)")
        if healthy_targets == 0 and total_targets > 0:
            reasons.append("No healthy targets available")
        elif healthy_targets == 0 and total_targets == 0:
            reasons.append("No targets registered")

        is_idle = len(reasons) >= 2

        if not is_idle:
            continue

        monthly_cost = round(0.0225 * 730, 2)

        result['items'].append({
            'lb_name': lb_name,
            'lb_type': lb_type,
            'lb_scheme': lb_scheme,
            'total_requests': total_requests,
            'processed_gb': round(total_gb, 2),
            'healthy_targets': healthy_targets,
            'total_targets': total_targets,
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# LAMBDA
# ============================================================

def check_idle_lambda_functions(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('lambda')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['lambda', 'cloudwatch'],
            aws_account=aws_account, detector='lambda',
        )
        if not clients:
            result['success'] = False
            return result
        lambda_client = clients['lambda']
        cloudwatch = clients['cloudwatch']
    else:
        lambda_client = boto3.client('lambda', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    try:
        functions = []
        marker = None
        while True:
            kwargs = {'Marker': marker} if marker else {}
            resp = lambda_client.list_functions(**kwargs)
            functions.extend(resp['Functions'])
            marker = resp.get('NextMarker')
            if not marker:
                break
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'lambda', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'lambda')

    end_time = datetime.utcnow()
    start_time_7d = end_time - timedelta(days=7)
    start_time_30d = end_time - timedelta(days=30)

    for func in functions:
        name = func['FunctionName']
        memory = func.get('MemorySize', 128)
        runtime = func.get('Runtime', 'unknown')
        modified = func.get('LastModified', '')

        # Real invocation count
        inv_7d = 0
        inv_30d = 0
        try:
            r7 = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda', MetricName='Invocations',
                Dimensions=[{'Name': 'FunctionName', 'Value': name}],
                StartTime=start_time_7d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            inv_7d = int(sum(p['Sum'] for p in r7.get('Datapoints', [])))
        except Exception:
            pass
        try:
            r30 = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda', MetricName='Invocations',
                Dimensions=[{'Name': 'FunctionName', 'Value': name}],
                StartTime=start_time_30d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            inv_30d = int(sum(p['Sum'] for p in r30.get('Datapoints', [])))
        except Exception:
            pass

        # Duration (avg)
        avg_duration = 0.0
        try:
            dm = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda', MetricName='Duration',
                Dimensions=[{'Name': 'FunctionName', 'Value': name}],
                StartTime=start_time_7d, EndTime=end_time,
                Period=86400, Statistics=['Average'],
            )
            pts = dm.get('Datapoints', [])
            if pts:
                avg_duration = sum(p['Average'] for p in pts) / len(pts)
        except Exception:
            pass

        reasons = []
        if inv_30d == 0:
            reasons.append("No invocations in past 30 days")
        elif inv_7d == 0 and inv_30d > 0:
            reasons.append(f"No invocations in past 7 days (was {inv_30d} in prior 30)")
        if 0 < inv_7d < 10:
            reasons.append(f"Very low usage ({inv_7d} invocations in 7 days)")

        is_idle = len(reasons) >= 1

        if not is_idle:
            continue

        # Real cost estimate from actual invocations
        monthly_inv = inv_30d if inv_30d > 0 else inv_7d * 4
        request_cost = (monthly_inv / 1_000_000) * 0.20
        gb_seconds = (memory / 1024) * (avg_duration / 1000) * monthly_inv
        compute_cost = gb_seconds * 0.0000166667
        monthly_cost = round(request_cost + compute_cost, 2)

        result['items'].append({
            'function_name': name,
            'runtime': runtime,
            'memory_mb': memory,
            'last_modified': modified,
            'invocations_30d': inv_30d,
            'invocations_7d': inv_7d,
            'avg_duration_ms': round(avg_duration, 2),
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# ECS / FARGATE SERVICES
# ============================================================

def check_idle_ecs_services(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('ecs')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['ecs', 'cloudwatch'],
            aws_account=aws_account, detector='ecs',
        )
        if not clients:
            result['success'] = False
            return result
        ecs = clients['ecs']
        cloudwatch = clients['cloudwatch']
    else:
        ecs = boto3.client('ecs', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    try:
        cluster_arns = ecs.list_clusters()['clusterArns']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'ecs', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'ecs')

    if not cluster_arns:
        return result

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    for cluster_arn in cluster_arns:
        cluster_name = cluster_arn.split('/')[-1]
        try:
            service_arns = ecs.list_services(cluster=cluster_name)['serviceArns']
        except Exception:
            continue

        for service_arn in service_arns[:20]:
            service_name = service_arn.split('/')[-1]
            try:
                svc = ecs.describe_services(
                    cluster=cluster_name, services=[service_name]
                )['services'][0]
            except Exception:
                continue

            task_def = ecs.describe_task_definition(
                taskDefinition=svc['taskDefinition']
            )['taskDefinition']

            cpu = task_def.get('cpu', '256')
            memory = task_def.get('memory', '512')
            try:
                cpu_int = int(cpu) if str(cpu).isdigit() else 256
            except Exception:
                cpu_int = 256
            try:
                mem_int = int(memory) if str(memory).isdigit() else 512
            except Exception:
                mem_int = 512

            running = svc.get('runningCount', 0)
            desired = svc.get('desiredCount', 0)

            cpu_util = 0.0
            mem_util = 0.0
            try:
                cm = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ECS', MetricName='CPUUtilization',
                    Dimensions=[
                        {'Name': 'ClusterName', 'Value': cluster_name},
                        {'Name': 'ServiceName', 'Value': service_name},
                    ],
                    StartTime=start_time, EndTime=end_time,
                    Period=3600, Statistics=['Average'],
                )
                pts = cm.get('Datapoints', [])
                if pts:
                    cpu_util = sum(p['Average'] for p in pts) / len(pts)
            except Exception:
                pass
            try:
                mm = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ECS', MetricName='MemoryUtilization',
                    Dimensions=[
                        {'Name': 'ClusterName', 'Value': cluster_name},
                        {'Name': 'ServiceName', 'Value': service_name},
                    ],
                    StartTime=start_time, EndTime=end_time,
                    Period=3600, Statistics=['Average'],
                )
                pts = mm.get('Datapoints', [])
                if pts:
                    mem_util = sum(p['Average'] for p in pts) / len(pts)
            except Exception:
                pass

            reasons = []
            if running == 0:
                reasons.append(f"No running tasks ({running}/{desired})")
            elif cpu_util < 5:
                reasons.append(f"Low CPU utilization ({cpu_util:.2f}% avg)")
            if mem_util < 10:
                reasons.append(f"Low memory utilization ({mem_util:.2f}% avg)")
            if desired > 0 and running == 0:
                reasons.append("Service running but no tasks")

            if len(reasons) < 2:
                continue

            # Fargate pricing
            vcpu = cpu_int / 1024
            gb = mem_int / 1024
            monthly_cost = round((vcpu * 0.04048 + gb * 0.004445) * 730 * max(running, 1), 2)

            result['items'].append({
                'service_name': service_name,
                'cluster_name': cluster_name,
                'cpu': cpu_int,
                'memory_mb': mem_int,
                'running_tasks': running,
                'desired_tasks': desired,
                'cpu_utilization': round(cpu_util, 2),
                'memory_utilization': round(mem_util, 2),
                'idle_reasons': reasons,
                'estimated_monthly_cost': monthly_cost,
                'estimated_monthly_savings': monthly_cost,
                'estimated_yearly_savings': round(monthly_cost * 12, 2),
            })
            result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# NAT GATEWAYS
# ============================================================

def check_idle_nat_gateways(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('nat_gateway')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['ec2', 'cloudwatch'],
            aws_account=aws_account, detector='nat_gateway',
        )
        if not clients:
            result['success'] = False
            return result
        ec2 = clients['ec2']
        cloudwatch = clients['cloudwatch']
    else:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    try:
        nat_gateways = ec2.describe_nat_gateways()['NatGateways']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'nat_gateway', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'nat_gateway')

    nat_gateways = [ng for ng in nat_gateways if ng['State'] == 'available']
    if not nat_gateways:
        return result

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    for nat in nat_gateways:
        nat_id = nat['NatGatewayId']

        total_gb = 0.0
        try:
            bp = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway', MetricName='BytesOutToDestination',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            total_gb = sum(p['Sum'] for p in bp.get('Datapoints', [])) / (1024 ** 3)
        except Exception:
            pass

        total_packets = 0
        try:
            pk = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway', MetricName='PacketsOutToDestination',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            total_packets = int(sum(p['Sum'] for p in pk.get('Datapoints', [])))
        except Exception:
            pass

        avg_connections = 0.0
        try:
            conn = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway', MetricName='ActiveConnectionCount',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time, EndTime=end_time,
                Period=3600, Statistics=['Average'],
            )
            pts = conn.get('Datapoints', [])
            if pts:
                avg_connections = sum(p['Average'] for p in pts) / len(pts)
        except Exception:
            pass

        reasons = []
        if total_gb < 0.1:
            reasons.append(f"Minimal data processed ({total_gb:.2f} GB over 7 days)")
        if total_packets < 1000:
            reasons.append(f"Very low packet count ({total_packets})")
        if avg_connections < 1:
            reasons.append("No active connections")

        if len(reasons) < 2:
            continue

        monthly_cost = round(0.045 * 730, 2)

        result['items'].append({
            'nat_gateway_id': nat_id,
            'vpc_id': nat.get('VpcId'),
            'subnet_id': nat.get('SubnetId'),
            'data_processed_gb': round(total_gb, 2),
            'packets_processed': total_packets,
            'avg_connections': round(avg_connections, 2),
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# VPC ENDPOINTS
# ============================================================

def check_idle_vpc_endpoints(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('vpc_endpoint')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['ec2', 'cloudwatch'],
            aws_account=aws_account, detector='vpc_endpoint',
        )
        if not clients:
            result['success'] = False
            return result
        ec2 = clients['ec2']
        cloudwatch = clients['cloudwatch']
    else:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    try:
        endpoints = ec2.describe_vpc_endpoints()['VpcEndpoints']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'vpc_endpoint', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'vpc_endpoint')

    endpoints = [ep for ep in endpoints if ep['State'] == 'available']
    if not endpoints:
        return result

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    for ep in endpoints:
        ep_id = ep['VpcEndpointId']
        ep_type = ep.get('VpcEndpointType', 'Interface')

        total_packets = 0
        try:
            pk = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2', MetricName='PacketsIn',
                Dimensions=[{'Name': 'VpcEndpointId', 'Value': ep_id}],
                StartTime=start_time, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            total_packets = int(sum(p['Sum'] for p in pk.get('Datapoints', [])))
        except Exception:
            pass

        reasons = []
        if total_packets == 0:
            reasons.append("No traffic through endpoint in past 7 days")

        if not reasons:
            continue

        monthly_cost = 0.0
        if ep_type.lower() != 'gateway':
            monthly_cost = round(0.01 * 730, 2)

        # Gateway endpoints are free — skip
        if monthly_cost == 0.0:
            continue

        result['items'].append({
            'endpoint_id': ep_id,
            'service_name': ep.get('ServiceName'),
            'endpoint_type': ep_type,
            'vpc_id': ep.get('VpcId'),
            'total_packets': total_packets,
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# API GATEWAYS
# ============================================================

def check_idle_api_gateways(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('api_gateway')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['apigateway', 'apigatewayv2', 'cloudwatch'],
            aws_account=aws_account, detector='api_gateway',
        )
        if not clients:
            result['success'] = False
            return result
        apigw = clients['apigateway']
        apigwv2 = clients['apigatewayv2']
        cloudwatch = clients['cloudwatch']
    else:
        apigw = boto3.client('apigateway', region_name=region)
        apigwv2 = boto3.client('apigatewayv2', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    end_time = datetime.utcnow()
    start_time_7d = end_time - timedelta(days=7)
    start_time_30d = end_time - timedelta(days=30)

    # REST APIs
    try:
        rest_apis = apigw.get_rest_apis()['items']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'api_gateway', e))
        rest_apis = []
    except Exception:
        rest_apis = []

    # HTTP APIs
    try:
        http_apis = apigwv2.get_apis()['Items']
        result['scanned'] = True
    except ClientError as e:
        if aws_account and 'AccessDenied' in str(e):
            result['errors'].append(handle_aws_error(aws_account, 'api_gateway', e))
        http_apis = []
    except Exception:
        http_apis = []

    if aws_account:
        clear_detector_errors(aws_account, 'api_gateway')

    def _process_api(api_id, api_name, api_type):
        total_requests = 0
        requests_7d = 0
        try:
            r30 = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApiGateway', MetricName='Count',
                Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                StartTime=start_time_30d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            total_requests = int(sum(p['Sum'] for p in r30.get('Datapoints', [])))
        except Exception:
            pass
        try:
            r7 = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApiGateway', MetricName='Count',
                Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                StartTime=start_time_7d, EndTime=end_time,
                Period=86400, Statistics=['Sum'],
            )
            requests_7d = int(sum(p['Sum'] for p in r7.get('Datapoints', [])))
        except Exception:
            pass

        reasons = []
        if total_requests == 0:
            reasons.append("Zero API requests in past 30 days")
        elif total_requests < 1000:
            reasons.append(f"Very low usage ({total_requests} requests in 30 days)")
        if requests_7d == 0 and total_requests > 0:
            reasons.append("No requests in past 7 days")

        if not reasons:
            return None

        monthly_cost = round((total_requests / 1_000_000) * 3.50, 2) if api_type == 'REST' else round((total_requests / 1_000_000) * 1.00, 2)

        return {
            'api_id': api_id,
            'api_name': api_name,
            'api_type': api_type,
            'total_requests_30d': total_requests,
            'requests_7d': requests_7d,
            'active_stages': 0,
            'avg_connections': 0,
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        }

    for api in rest_apis:
        r = _process_api(api['id'], api.get('name', api['id']), 'REST')
        if r:
            result['items'].append(r)
            result['total_savings'] += r['estimated_monthly_savings']

    for api in http_apis:
        r = _process_api(
            api['ApiId'], api.get('Name', api['ApiId']),
            api.get('ProtocolType', 'HTTP'),
        )
        if r:
            result['items'].append(r)
            result['total_savings'] += r['estimated_monthly_savings']

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# CLOUDWATCH RESOURCES
# ============================================================

def check_idle_cloudwatch_resources(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    """
    Returns dict with sub-keys: log_groups, alarms, dashboards, metrics
    plus success/scanned/errors at the top level.
    """
    result = {
        'detector': 'cloudwatch',
        'success': True,
        'scanned': False,
        'errors': [],
        'total_savings': 0.0,
        'log_groups': {'count': 0, 'items': [], 'savings': 0.0},
        'alarms': {'count': 0, 'items': [], 'savings': 0.0},
        'dashboards': {'count': 0, 'items': []},
        'metrics': {'count': 0, 'items': [], 'savings': 0.0},
    }

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['logs', 'cloudwatch'],
            aws_account=aws_account, detector='cloudwatch',
        )
        if not clients:
            result['success'] = False
            return result
        logs = clients['logs']
        cloudwatch = clients['cloudwatch']
    else:
        logs = boto3.client('logs', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    # Log groups
    try:
        log_groups = []
        token = None
        while True:
            kwargs = {'nextToken': token} if token else {}
            resp = logs.describe_log_groups(**kwargs)
            log_groups.extend(resp['logGroups'])
            token = resp.get('nextToken')
            if not token:
                break
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'cloudwatch', e))
        log_groups = []
    except Exception:
        log_groups = []

    for lg in log_groups:
        name = lg['logGroupName']
        stored_bytes = lg.get('storedBytes', 0)
        stored_gb = stored_bytes / (1024 ** 3)
        retention = lg.get('retentionInDays', 0)

        days_since_last = 999
        try:
            streams = logs.describe_log_streams(
                logGroupName=name, orderBy='LastEventTime',
                descending=True, limit=1,
            )['logStreams']
            if streams and 'lastIngestionTime' in streams[0]:
                last_ingest = datetime.fromtimestamp(streams[0]['lastIngestionTime'] / 1000)
                days_since_last = (datetime.now() - last_ingest).days
        except Exception:
            pass

        reasons = []
        if stored_gb < 0.01:
            reasons.append(f"Minimal logs stored ({stored_gb:.4f} GB)")
        if days_since_last > 30:
            reasons.append(f"No logs ingested in {days_since_last} days")
        if retention == 0:
            reasons.append("No retention policy (logs stored indefinitely)")

        if len(reasons) < 2:
            continue

        monthly_cost = round(stored_gb * 0.03, 2)
        result['log_groups']['items'].append({
            'log_group_name': name,
            'stored_gb': round(stored_gb, 2),
            'retention_days': retention,
            'days_since_last_log': days_since_last,
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
        })
        result['log_groups']['savings'] += monthly_cost

    result['log_groups']['count'] = len(result['log_groups']['items'])
    result['log_groups']['savings'] = round(result['log_groups']['savings'], 2)

    # Alarms
    try:
        alarms = cloudwatch.describe_alarms()['MetricAlarms']
    except ClientError as e:
        if aws_account and 'AccessDenied' in str(e):
            result['errors'].append(handle_aws_error(aws_account, 'cloudwatch', e))
        alarms = []
    except Exception:
        alarms = []

    for alarm in alarms:
        name = alarm['AlarmName']
        state = alarm['StateValue']
        actions_enabled = alarm.get('ActionsEnabled', False)

        reasons = []
        if state == 'INSUFFICIENT_DATA':
            reasons.append("Alarm has insufficient data")
        if not actions_enabled:
            reasons.append("Alarm actions disabled")

        if not reasons:
            continue

        monthly_cost = 0.10
        result['alarms']['items'].append({
            'alarm_name': name,
            'state': state,
            'actions_enabled': actions_enabled,
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
        })
        result['alarms']['savings'] += monthly_cost

    result['alarms']['count'] = len(result['alarms']['items'])
    result['alarms']['savings'] = round(result['alarms']['savings'], 2)

    # Dashboards
    try:
        dashboards = cloudwatch.list_dashboards()['DashboardEntries']
    except Exception:
        dashboards = []

    for d in dashboards:
        name = d['DashboardName']
        last_modified = d.get('LastModified')
        if last_modified:
            days = (datetime.now(last_modified.tzinfo) - last_modified).days
        else:
            days = 999

        if days <= 90:
            continue

        result['dashboards']['items'].append({
            'dashboard_name': name,
            'days_since_modified': days,
            'idle_reasons': [f"Not modified in {days} days"],
        })

    result['dashboards']['count'] = len(result['dashboards']['items'])

    # Custom metrics
    try:
        metrics = cloudwatch.list_metrics()['Metrics']
        custom = [m for m in metrics if not m['Namespace'].startswith('AWS/')]

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)

        for m in custom[:50]:
            try:
                stats = cloudwatch.get_metric_statistics(
                    Namespace=m['Namespace'], MetricName=m['MetricName'],
                    Dimensions=m.get('Dimensions', []),
                    StartTime=start_time, EndTime=end_time,
                    Period=86400, Statistics=['Average'],
                )
                if stats.get('Datapoints'):
                    continue
            except Exception:
                pass

            monthly_cost = 0.30
            result['metrics']['items'].append({
                'namespace': m['Namespace'],
                'metric_name': m['MetricName'],
                'idle_reasons': ['No data points in past 30 days'],
                'estimated_monthly_cost': monthly_cost,
                'estimated_monthly_savings': monthly_cost,
            })
            result['metrics']['savings'] += monthly_cost
    except Exception:
        pass

    result['metrics']['count'] = len(result['metrics']['items'])
    result['metrics']['savings'] = round(result['metrics']['savings'], 2)

    total = (
        result['log_groups']['savings'] +
        result['alarms']['savings'] +
        result['metrics']['savings']
    )
    result['total_savings'] = round(total, 2)

    if aws_account:
        clear_detector_errors(aws_account, 'cloudwatch')

    return result


# ============================================================
# EBS VOLUMES (unattached)
# ============================================================

def check_idle_ebs_volumes(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('ec2')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region, ['ec2'],
            aws_account=aws_account, detector='ec2',
        )
        if not clients:
            result['success'] = False
            return result
        ec2 = clients['ec2']
    else:
        ec2 = boto3.client('ec2', region_name=region)

    try:
        volumes = ec2.describe_volumes()['Volumes']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'ec2', e))
        result['success'] = False
        return result

    volume_rate = {
        'gp3': 0.08, 'gp2': 0.10, 'io1': 0.125, 'io2': 0.125,
        'st1': 0.045, 'sc1': 0.025, 'standard': 0.05,
    }

    for vol in volumes:
        attachments = vol.get('Attachments', [])
        if attachments:
            continue

        state = vol.get('State')
        if state not in ('available',):
            continue

        size = vol.get('Size', 0)
        vtype = vol.get('VolumeType', 'gp2')
        rate = volume_rate.get(vtype, 0.10)
        monthly_cost = round(size * rate, 2)

        create_time = vol.get('CreateTime')
        days_unattached = 0
        if create_time:
            try:
                days_unattached = (datetime.now(create_time.tzinfo) - create_time).days
            except Exception:
                pass

        reasons = [f"Volume is unattached (state: {state})"]
        if days_unattached > 30:
            reasons.append(f"Unattached for {days_unattached} days")

        result['items'].append({
            'volume_id': vol['VolumeId'],
            'volume_type': vtype,
            'size_gb': size,
            'state': state,
            'days_unattached': days_unattached,
            'availability_zone': vol.get('AvailabilityZone'),
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# ELASTIC IPs (unattached)
# ============================================================

def check_idle_elastic_ips(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('elastic_ip')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region, ['ec2'],
            aws_account=aws_account, detector='elastic_ip',
        )
        if not clients:
            result['success'] = False
            return result
        ec2 = clients['ec2']
    else:
        ec2 = boto3.client('ec2', region_name=region)

    try:
        addresses = ec2.describe_addresses()['Addresses']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'elastic_ip', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'elastic_ip')

    for addr in addresses:
        is_attached = 'InstanceId' in addr or 'NetworkInterfaceId' in addr
        if is_attached:
            continue

        monthly_cost = 3.65  # $0.005/hr × 730

        result['items'].append({
            'public_ip': addr.get('PublicIp'),
            'allocation_id': addr.get('AllocationId'),
            'domain': addr.get('Domain', 'vpc'),
            'idle_reasons': ["Elastic IP is not associated with any resource"],
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# RDS INSTANCES (idle)
# ============================================================

def check_idle_rds_instances(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('rds')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region,
            ['rds', 'cloudwatch'],
            aws_account=aws_account, detector='rds',
        )
        if not clients:
            result['success'] = False
            return result
        rds = clients['rds']
        cloudwatch = clients['cloudwatch']
    else:
        rds = boto3.client('rds', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)

    try:
        instances = rds.describe_db_instances()['DBInstances']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'rds', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'rds')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    rds_pricing = {
        'db.t3.micro': 0.017, 'db.t3.small': 0.034, 'db.t3.medium': 0.068,
        'db.t4g.micro': 0.014, 'db.t4g.small': 0.028, 'db.t4g.medium': 0.056,
        'db.m5.large': 0.18, 'db.m5.xlarge': 0.36, 'db.r5.large': 0.24,
        'db.r5.xlarge': 0.48,
    }

    for inst in instances:
        if inst.get('DBInstanceStatus') != 'available':
            continue

        iid = inst['DBInstanceIdentifier']
        iclass = inst.get('DBInstanceClass', '')
        storage_gb = inst.get('AllocatedStorage', 20)

        avg_cpu = 0.0
        cpu_available = False
        try:
            cr = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS', MetricName='CPUUtilization',
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': iid}],
                StartTime=start_time, EndTime=end_time,
                Period=3600, Statistics=['Average'],
            )
            pts = cr.get('Datapoints', [])
            if pts:
                avg_cpu = sum(p['Average'] for p in pts) / len(pts)
                cpu_available = True
        except Exception:
            pass

        avg_conn = 0.0
        try:
            cm = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS', MetricName='DatabaseConnections',
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': iid}],
                StartTime=start_time, EndTime=end_time,
                Period=3600, Statistics=['Average'],
            )
            pts = cm.get('Datapoints', [])
            if pts:
                avg_conn = sum(p['Average'] for p in pts) / len(pts)
        except Exception:
            pass

        if not cpu_available:
            continue

        reasons = []
        if avg_cpu < 5:
            reasons.append(f"CPU average {avg_cpu:.2f}% over 7 days")
        if avg_conn < 1:
            reasons.append("No active connections over 7 days")

        if len(reasons) < 2:
            continue

        hourly = rds_pricing.get(iclass, 0.10)
        storage_cost = storage_gb * 0.115
        monthly_cost = round((hourly * 730) + storage_cost, 2)

        # RDS storage can't be removed without deleting the DB — net savings
        # is only the compute portion
        compute_savings = round(hourly * 730, 2)

        result['items'].append({
            'instance_id': iid,
            'instance_class': iclass,
            'engine': inst.get('Engine'),
            'storage_gb': storage_gb,
            'avg_cpu': round(avg_cpu, 2),
            'avg_connections': round(avg_conn, 2),
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': compute_savings,
            'estimated_yearly_savings': round(compute_savings * 12, 2),
        })
        result['total_savings'] += compute_savings

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# OLD SNAPSHOTS
# ============================================================

def check_idle_snapshots(role_arn=None, external_id=None, region='us-east-1', aws_account=None):
    result = _empty_result('snapshot')

    if role_arn and external_id:
        clients = _assume_and_clients(
            role_arn, external_id, region, ['ec2'],
            aws_account=aws_account, detector='snapshot',
        )
        if not clients:
            result['success'] = False
            return result
        ec2 = clients['ec2']
    else:
        ec2 = boto3.client('ec2', region_name=region)

    try:
        snapshots = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        result['scanned'] = True
    except ClientError as e:
        if aws_account:
            result['errors'].append(handle_aws_error(aws_account, 'snapshot', e))
        result['success'] = False
        return result

    if aws_account:
        clear_detector_errors(aws_account, 'snapshot')

    # Get all AMIs so we know which snapshots are referenced
    referenced_snapshot_ids = set()
    try:
        images = ec2.describe_images(Owners=['self'])['Images']
        for img in images:
            for bdm in img.get('BlockDeviceMappings', []):
                sid = bdm.get('Ebs', {}).get('SnapshotId')
                if sid:
                    referenced_snapshot_ids.add(sid)
    except Exception:
        pass

    cutoff = datetime.now() - timedelta(days=90)

    for snap in snapshots:
        sid = snap['SnapshotId']
        if sid in referenced_snapshot_ids:
            continue

        start_time = snap.get('StartTime')
        age_days = 0
        if start_time:
            try:
                age_days = (datetime.now(start_time.tzinfo) - start_time).days
            except Exception:
                pass

        if age_days < 90:
            continue

        size_gb = snap.get('VolumeSize', 0)
        monthly_cost = round(size_gb * 0.05, 2)

        reasons = [
            f"Snapshot is {age_days} days old",
            "Not referenced by any AMI",
        ]

        result['items'].append({
            'snapshot_id': sid,
            'volume_size_gb': size_gb,
            'description': snap.get('Description', ''),
            'age_days': age_days,
            'idle_reasons': reasons,
            'estimated_monthly_cost': monthly_cost,
            'estimated_monthly_savings': monthly_cost,
            'estimated_yearly_savings': round(monthly_cost * 12, 2),
        })
        result['total_savings'] += monthly_cost

    result['total_savings'] = round(result['total_savings'], 2)
    result['count'] = len(result['items'])
    return result


# ============================================================
# CACHE HELPERS — used by views.py
# ============================================================

def get_cached_idle_results(user, aws_account, force_refresh=False):
    """
    Load previously-saved idle findings from the DB.
    Returns None if nothing is cached and force_refresh is False.
    """
    from .models import (
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway,
        IdleCloudWatchLogGroup, IdleCloudWatchAlarm,
        IdleCloudWatchDashboard, IdleCloudWatchMetric,
    )
    from .idle_error_handler import get_scan_errors

    if force_refresh:
        return None

    cached_ec2 = IdleEC2Instance.objects.filter(
        aws_account=aws_account, is_resolved=False
    )
    if not cached_ec2.exists():
        return None

    # ---- EC2 ----
    ec2_items = []
    for i in cached_ec2:
        ec2_items.append({
            'instance_id': i.instance_id,
            'instance_name': i.instance_name,
            'instance_type': i.instance_type,
            'metrics': {
                'avg_cpu': float(i.cpu_avg),
                'network_in_mb': float(i.network_in_mb),
                'network_out_mb': float(i.network_out_mb),
                'disk_read_mb': float(i.disk_read_mb),
                'disk_write_mb': float(i.disk_write_mb),
            },
            'idle_reasons': i.reasons or [],
            'estimated_monthly_cost': float(i.monthly_cost),
            'estimated_monthly_savings': float(i.monthly_cost),
            'estimated_yearly_savings': float(i.monthly_cost) * 12,
        })

    # ---- ASG ----
    asg_qs = IdleAutoScalingGroup.objects.filter(aws_account=aws_account, is_resolved=False)
    asg_items = [{
        'asg_name': a.asg_name,
        'min_size': a.min_size, 'max_size': a.max_size,
        'desired_capacity': a.desired_capacity,
        'current_instances': a.current_instances,
        'avg_cpu': float(a.avg_cpu),
        'idle_reasons': a.reasons or [],
        'estimated_monthly_cost': float(a.monthly_cost),
        'estimated_monthly_savings': float(a.monthly_cost),
        'estimated_yearly_savings': float(a.monthly_cost) * 12,
    } for a in asg_qs]

    # ---- LB ----
    lb_qs = IdleLoadBalancer.objects.filter(aws_account=aws_account, is_resolved=False)
    lb_items = [{
        'lb_name': l.lb_name, 'lb_type': l.lb_type,
        'lb_scheme': l.lb_scheme, 'lb_state': l.lb_state,
        'total_requests': l.total_requests,
        'processed_gb': float(l.processed_gb),
        'healthy_targets': l.healthy_targets,
        'total_targets': l.total_targets,
        'idle_reasons': l.reasons or [],
        'estimated_monthly_cost': float(l.monthly_cost),
        'estimated_monthly_savings': float(l.monthly_cost),
        'estimated_yearly_savings': float(l.monthly_cost) * 12,
    } for l in lb_qs]

    # ---- Lambda ----
    lam_qs = IdleLambdaFunction.objects.filter(aws_account=aws_account, is_resolved=False)
    lam_items = [{
        'function_name': f.function_name, 'runtime': f.runtime,
        'memory_mb': f.memory_mb, 'last_modified': f.last_modified,
        'invocations_30d': f.invocations_30d,
        'invocations_7d': f.invocations_7d,
        'avg_duration_ms': float(f.avg_duration_ms),
        'idle_reasons': f.reasons or [],
        'estimated_monthly_cost': float(f.monthly_cost),
        'estimated_monthly_savings': float(f.monthly_cost),
        'estimated_yearly_savings': float(f.monthly_cost) * 12,
    } for f in lam_qs]

    # ---- ECS ----
    ecs_qs = IdleECSService.objects.filter(aws_account=aws_account, is_resolved=False)
    ecs_items = [{
        'service_name': s.service_name, 'cluster_name': s.cluster_name,
        'cpu': s.cpu, 'memory_mb': s.memory_mb,
        'running_tasks': s.running_tasks,
        'desired_tasks': s.desired_tasks,
        'cpu_utilization': float(s.cpu_utilization),
        'memory_utilization': float(s.memory_utilization),
        'idle_reasons': s.reasons or [],
        'estimated_monthly_cost': float(s.monthly_cost),
        'estimated_monthly_savings': float(s.monthly_cost),
        'estimated_yearly_savings': float(s.monthly_cost) * 12,
    } for s in ecs_qs]

    # ---- NAT ----
    nat_qs = IdleNATGateway.objects.filter(aws_account=aws_account, is_resolved=False)
    nat_items = [{
        'nat_gateway_id': n.nat_gateway_id,
        'vpc_id': n.vpc_id, 'subnet_id': n.subnet_id,
        'data_processed_gb': float(n.data_processed_gb),
        'packets_processed': n.packets_processed,
        'avg_connections': float(n.avg_connections),
        'idle_reasons': n.reasons or [],
        'estimated_monthly_cost': float(n.monthly_cost),
        'estimated_monthly_savings': float(n.monthly_cost),
        'estimated_yearly_savings': float(n.yearly_cost),
    } for n in nat_qs]

    # ---- VPCe ----
    vpce_qs = IdleVPCEndpoint.objects.filter(aws_account=aws_account, is_resolved=False)
    vpce_items = [{
        'endpoint_id': e.endpoint_id,
        'service_name': e.service_name,
        'endpoint_type': e.endpoint_type,
        'vpc_id': e.vpc_id,
        'total_packets': e.total_packets,
        'idle_reasons': e.reasons or [],
        'estimated_monthly_cost': float(e.monthly_cost),
        'estimated_monthly_savings': float(e.monthly_cost),
        'estimated_yearly_savings': float(e.monthly_cost) * 12,
    } for e in vpce_qs]

    # ---- API GW ----
    api_qs = IdleAPIGateway.objects.filter(aws_account=aws_account, is_resolved=False)
    api_items = [{
        'api_id': a.api_id, 'api_name': a.api_name, 'api_type': a.api_type,
        'total_requests_30d': a.total_requests_30d,
        'requests_7d': a.requests_7d,
        'active_stages': a.active_stages,
        'avg_connections': float(a.avg_connections),
        'idle_reasons': a.reasons or [],
        'estimated_monthly_cost': float(a.monthly_cost),
        'estimated_monthly_savings': float(a.monthly_cost),
        'estimated_yearly_savings': float(a.monthly_cost) * 12,
    } for a in api_qs]

    # ---- CloudWatch ----
    lg_qs = IdleCloudWatchLogGroup.objects.filter(aws_account=aws_account, is_resolved=False)
    alarm_qs = IdleCloudWatchAlarm.objects.filter(aws_account=aws_account, is_resolved=False)
    dash_qs = IdleCloudWatchDashboard.objects.filter(aws_account=aws_account, is_resolved=False)
    metric_qs = IdleCloudWatchMetric.objects.filter(aws_account=aws_account, is_resolved=False)

    lg_items = [{
        'log_group_name': g.log_group_name,
        'stored_gb': float(g.stored_gb),
        'retention_days': g.retention_days,
        'days_since_last_log': g.days_since_last_log,
        'idle_reasons': g.reasons or [],
        'estimated_monthly_cost': float(g.monthly_cost),
        'estimated_monthly_savings': float(g.monthly_cost),
    } for g in lg_qs]

    alarm_items = [{
        'alarm_name': a.alarm_name, 'state': a.state,
        'actions_enabled': a.actions_enabled,
        'idle_reasons': a.reasons or [],
        'estimated_monthly_cost': float(a.monthly_cost),
        'estimated_monthly_savings': float(a.monthly_cost),
    } for a in alarm_qs]

    dash_items = [{
        'dashboard_name': d.dashboard_name,
        'days_since_modified': d.days_since_modified,
        'idle_reasons': d.reasons or [],
    } for d in dash_qs]

    metric_items = [{
        'namespace': m.namespace, 'metric_name': m.metric_name,
        'idle_reasons': m.reasons or [],
        'estimated_monthly_cost': float(m.monthly_cost),
        'estimated_monthly_savings': float(m.monthly_cost),
    } for m in metric_qs]

    # ---- Totals ----
    def _sum(items, key='estimated_monthly_savings'):
        return round(sum(i.get(key, 0) for i in items), 2)

    total = (
        _sum(ec2_items) + _sum(asg_items) + _sum(lb_items) +
        _sum(lam_items) + _sum(ecs_items) + _sum(nat_items) +
        _sum(vpce_items) + _sum(api_items) + _sum(lg_items) +
        _sum(alarm_items) + _sum(metric_items)
    )
    total_findings = (
        len(ec2_items) + len(asg_items) + len(lb_items) +
        len(lam_items) + len(ecs_items) + len(nat_items) +
        len(vpce_items) + len(api_items) + len(lg_items) +
        len(alarm_items) + len(dash_items) + len(metric_items)
    )

    return {
        'success': True,
        'cached': True,
        'total_findings': total_findings,
        'total_savings': round(total, 2),
        'scan_errors': get_scan_errors(aws_account),
        'services_scanned': 12,
        'services_failed': 0,

        'ec2_instances':        {'count': len(ec2_items),   'items': ec2_items,   'savings': _sum(ec2_items)},
        'auto_scaling_groups':  {'count': len(asg_items),   'items': asg_items,   'savings': _sum(asg_items)},
        'load_balancers':       {'count': len(lb_items),    'items': lb_items,    'savings': _sum(lb_items)},
        'lambda_functions':     {'count': len(lam_items),   'items': lam_items,   'savings': _sum(lam_items)},
        'ecs_services':         {'count': len(ecs_items),   'items': ecs_items,   'savings': _sum(ecs_items)},
        'nat_gateways':         {'count': len(nat_items),   'items': nat_items,   'savings': _sum(nat_items)},
        'vpc_endpoints':        {'count': len(vpce_items),  'items': vpce_items,  'savings': _sum(vpce_items)},
        'api_gateways':         {'count': len(api_items),   'items': api_items,   'savings': _sum(api_items)},
        'ebs_volumes':          {'count': 0, 'items': [], 'savings': 0},
        'elastic_ips':          {'count': 0, 'items': [], 'savings': 0},
        'rds_instances':        {'count': 0, 'items': [], 'savings': 0},
        'snapshots':            {'count': 0, 'items': [], 'savings': 0},
        'cloudwatch': {
            'log_groups':  {'count': len(lg_items),     'items': lg_items,     'savings': _sum(lg_items)},
            'alarms':      {'count': len(alarm_items),  'items': alarm_items,  'savings': _sum(alarm_items)},
            'dashboards':  {'count': len(dash_items),   'items': dash_items},
            'metrics':     {'count': len(metric_items), 'items': metric_items, 'savings': _sum(metric_items)},
        },
    }


def clear_all_idle_data(aws_account):
    """
    Delete every idle finding row for this account.
    Returns the total number of rows deleted.
    """
    from .models import (
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway,
        IdleCloudWatchLogGroup, IdleCloudWatchAlarm,
        IdleCloudWatchDashboard, IdleCloudWatchMetric,
    )

    total = 0
    for model in [
        IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
        IdleLambdaFunction, IdleECSService, IdleNATGateway,
        IdleVPCEndpoint, IdleAPIGateway,
        IdleCloudWatchLogGroup, IdleCloudWatchAlarm,
        IdleCloudWatchDashboard, IdleCloudWatchMetric,
    ]:
        deleted, _ = model.objects.filter(aws_account=aws_account).delete()
        total += deleted

    logger.info(f"🗑️ Cleared {total} idle resource rows for {aws_account.account_id}")
    return total