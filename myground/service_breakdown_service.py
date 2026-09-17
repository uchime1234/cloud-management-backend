# myground/service_breakdown_service.py
"""
Service & Resource Breakdown
Scans AWS, groups by service, generates AI verdicts per resource.
"""

import boto3
from datetime import datetime, timezone
from decimal import Decimal
import requests
import json
import logging

from django.conf import settings
from django.utils import timezone as django_timezone

from .models import AWSAccount, ResourceAIAnalysis

logger = logging.getLogger(__name__)


# ============================================================
# PRICING TABLES (approximate)
# ============================================================

EC2_HOURLY = {
    't2.micro': 0.0116, 't2.small': 0.023, 't2.medium': 0.0464,
    't3.micro': 0.0104, 't3.small': 0.0208, 't3.medium': 0.0416, 't3.large': 0.0832,
    'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
    'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
    'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
    'default': 0.05,
}

RDS_HOURLY = {
    'db.t3.micro': 0.017, 'db.t3.small': 0.034, 'db.t3.medium': 0.068,
    'db.m5.large': 0.18, 'db.m5.xlarge': 0.36,
    'db.r5.large': 0.24, 'db.r5.xlarge': 0.48,
    'default': 0.10,
}


def assume_role(aws_account):
    """Assume IAM role."""
    sts = boto3.client(
        'sts',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    response = sts.assume_role(
        RoleArn=aws_account.role_arn,
        RoleSessionName="ServiceBreakdown",
        ExternalId=str(aws_account.external_id)
    )
    return response["Credentials"]


def get_client(service, creds, region='us-east-1'):
    return boto3.client(
        service,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region
    )


def get_cloudwatch_cpu(cw_client, namespace, dimensions, days=7):
    """Get average CPU over N days."""
    try:
        from datetime import timedelta
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        response = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName='CPUUtilization',
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=['Average']
        )
        points = response.get('Datapoints', [])
        if not points:
            return 0.0
        return round(sum(p['Average'] for p in points) / len(points), 2)
    except Exception:
        return 0.0


# ============================================================
# AI VERDICT GENERATOR
# ============================================================

AI_PROMPT_TEMPLATE = """You are a Senior AWS FinOps Expert analyzing a single cloud resource.

RESOURCE DETAILS:
- Service: {service_name} ({service_category})
- Resource ID: {resource_id}
- Type: {resource_type}
- Region: {region}
- Status: {status}
- On Since: {on_since}
- CPU Average (7 days): {cpu_avg}%
- Network In: {network_in_mb} MB
- Network Out: {network_out_mb} MB
- Monthly Cost: ${monthly_cost}
- Tags: {tags}
- Extra: {extra}

YOUR TASK:
Pick ONE verdict from this list:
- LEAVE_IT (healthy, no action needed)
- MONITOR_IT (not enough data, watch for 7 days)
- SCHEDULE_IT (only used during certain hours, schedule start/stop)
- DOWNSIZE_IT (over-provisioned, reduce size)
- STOP_IT (idle, stop to save money)
- TERMINATE_IT (unused, delete permanently)

Respond ONLY with valid JSON in this exact format:
{{
    "verdict": "STOP_IT",
    "short_reason": "One sentence summary (max 100 chars).",
    "detailed_explanation": "Write 4-6 detailed sentences explaining WHY this verdict. Reference specific numbers from the data above. Talk about the risk of leaving it as-is, the impact of the recommended action, and any context that matters. Make it sound like a real expert. Do NOT be generic - use the actual values given.",
    "savings_monthly": 11.20,
    "savings_yearly": 134.40,
    "risk": "LOW",
    "steps": [
        "Take a snapshot of attached EBS volumes first",
        "Stop the instance (not terminate yet)",
        "Monitor for 7 days for any breakage",
        "If no issues appear, terminate"
    ],
    "alternatives": [
        "Schedule 9AM-5PM only to save $7/month",
        "Downsize to t3.nano to save $8/month"
    ],
    "time_to_fix": "5 minutes",
    "one_click_available": true,
    "priority": 8
}}

Rules:
- savings_monthly: 0 if verdict is LEAVE_IT or MONITOR_IT
- savings_yearly: savings_monthly * 12
- risk: ZERO, LOW, MEDIUM, or HIGH
- priority: 1-10 (10 = most urgent)
- one_click_available: true only for STOP_IT / SCHEDULE_IT / TERMINATE_IT
- Use realistic AWS pricing knowledge
"""


def get_ai_verdict(resource_data):
    """Call Groq to get a verdict for one resource."""
    try:
        prompt = AI_PROMPT_TEMPLATE.format(**resource_data)
        
        headers = {
            "Authorization": f"Bearer {settings.GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": "You are a Senior AWS FinOps Expert. Respond ONLY with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.4,
            "max_tokens": 900,
            "response_format": {"type": "json_object"}
        }
        
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            content = result['choices'][0]['message']['content']
            return json.loads(content)
        else:
            logger.error(f"Groq error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"AI verdict error: {e}")
        return None


def fallback_verdict(resource_data):
    """Fallback if AI fails."""
    cpu = resource_data.get('cpu_avg', 0)
    status = resource_data.get('status', 'UNKNOWN')
    cost = float(resource_data.get('monthly_cost', 0))
    
    if status == 'STOPPED':
        return {
            "verdict": "TERMINATE_IT",
            "short_reason": "Instance is stopped — likely forgotten.",
            "detailed_explanation": f"This resource is currently stopped but still exists in your account. It hasn't been running, which suggests it may be a forgotten leftover from a past task. If it's not needed, terminating it removes the resource permanently from your AWS account. If you're unsure, you can monitor it for a few more days before deleting.",
            "savings_monthly": 0, "savings_yearly": 0,
            "risk": "LOW", "steps": ["Verify no snapshots needed", "Terminate the instance"],
            "alternatives": ["Keep it stopped for 30 more days"],
            "time_to_fix": "2 minutes", "one_click_available": True, "priority": 4
        }
    elif cpu < 5 and cost > 5:
        return {
            "verdict": "STOP_IT",
            "short_reason": f"CPU average is {cpu}% — resource is idle.",
            "detailed_explanation": f"This resource has been running at only {cpu}% average CPU utilization, which is far below the healthy threshold of 30-60%. It's costing you ${cost}/month while producing almost no work. Stopping this resource will immediately reduce your bill without impacting any real workload, since no meaningful traffic is hitting it. Take a snapshot first for safety.",
            "savings_monthly": round(cost, 2), "savings_yearly": round(cost * 12, 2),
            "risk": "LOW", "steps": ["Take a snapshot", "Stop the instance", "Monitor 7 days"],
            "alternatives": [f"Downsize for partial savings"],
            "time_to_fix": "5 minutes", "one_click_available": True, "priority": 7
        }
    else:
        return {
            "verdict": "MONITOR_IT",
            "short_reason": "Not enough data to recommend action.",
            "detailed_explanation": "We don't have enough usage history to give a confident recommendation. Monitor this resource for another 7 days to gather more data points. Once we have at least a week of stable CPU and network metrics, the AI can give you a clear verdict.",
            "savings_monthly": 0, "savings_yearly": 0,
            "risk": "ZERO", "steps": ["Check back in 7 days"],
            "alternatives": [],
            "time_to_fix": "N/A", "one_click_available": False, "priority": 1
        }


# ============================================================
# RESOURCE SCANNERS (EC2, RDS, S3, Lambda)
# ============================================================

def scan_ec2(creds, region='us-east-1'):
    """Scan all EC2 instances."""
    resources = []
    try:
        ec2 = get_client('ec2', creds, region)
        cw = get_client('cloudwatch', creds, region)
        
        instances = ec2.describe_instances()
        for reservation in instances.get('Reservations', []):
            for inst in reservation.get('Instances', []):
                state = inst['State']['Name']
                status = 'ON' if state == 'running' else 'STOPPED' if state == 'stopped' else 'UNKNOWN'
                
                # CPU metrics (only if running)
                cpu_avg = 0.0
                if status == 'ON':
                    cpu_avg = get_cloudwatch_cpu(
                        cw, 'AWS/EC2',
                        [{'Name': 'InstanceId', 'Value': inst['InstanceId']}]
                    )
                
                # Cost
                itype = inst.get('InstanceType', 'unknown')
                hourly = EC2_HOURLY.get(itype, EC2_HOURLY['default'])
                monthly = round(hourly * 730, 2) if status == 'ON' else 0.0
                
                # Name tag
                name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), inst['InstanceId'])
                
                # Tags dict
                tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                
                # On since
                on_since = inst.get('LaunchTime')
                
                resources.append({
                    'service_category': 'Compute',
                    'service_name': 'EC2',
                    'resource_id': inst['InstanceId'],
                    'resource_name': name,
                    'resource_type': itype,
                    'region': region,
                    'tags': tags,
                    'status': status,
                    'on_since': on_since,
                    'last_checked': datetime.now(timezone.utc),
                    'cpu_avg': cpu_avg,
                    'network_in_mb': 0.0,
                    'network_out_mb': 0.0,
                    'disk_read_mb': 0.0,
                    'disk_write_mb': 0.0,
                    'monthly_cost': Decimal(str(monthly)),
                    'resource_details': {
                        'vpc_id': inst.get('VpcId'),
                        'subnet_id': inst.get('SubnetId'),
                        'private_ip': inst.get('PrivateIpAddress'),
                        'public_ip': inst.get('PublicIpAddress'),
                    }
                })
    except Exception as e:
        logger.error(f"EC2 scan error: {e}")
    return resources


def scan_rds(creds, region='us-east-1'):
    """Scan all RDS instances."""
    resources = []
    try:
        rds = get_client('rds', creds, region)
        cw = get_client('cloudwatch', creds, region)
        
        instances = rds.describe_db_instances()
        for db in instances.get('DBInstances', []):
            status = 'ON' if db.get('DBInstanceStatus') == 'available' else 'UNKNOWN'
            
            cpu_avg = 0.0
            if status == 'ON':
                cpu_avg = get_cloudwatch_cpu(
                    cw, 'AWS/RDS',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                )
            
            iclass = db.get('DBInstanceClass', 'unknown')
            hourly = RDS_HOURLY.get(iclass, RDS_HOURLY['default'])
            storage_gb = db.get('AllocatedStorage', 20)
            storage_cost = storage_gb * 0.115
            monthly = round((hourly * 730) + storage_cost, 2) if status == 'ON' else 0.0
            
            tags = {t['Key']: t['Value'] for t in db.get('TagList', [])}
            
            resources.append({
                'service_category': 'Database',
                'service_name': 'RDS',
                'resource_id': db['DBInstanceIdentifier'],
                'resource_name': db['DBInstanceIdentifier'],
                'resource_type': iclass,
                'region': region,
                'tags': tags,
                'status': status,
                'on_since': db.get('InstanceCreateTime'),
                'last_checked': datetime.now(timezone.utc),
                'cpu_avg': cpu_avg,
                'network_in_mb': 0.0,
                'network_out_mb': 0.0,
                'disk_read_mb': 0.0,
                'disk_write_mb': 0.0,
                'monthly_cost': Decimal(str(monthly)),
                'resource_details': {
                    'engine': db.get('Engine'),
                    'allocated_storage_gb': storage_gb,
                    'multi_az': db.get('MultiAZ'),
                    'endpoint': db.get('Endpoint', {}).get('Address'),
                }
            })
    except Exception as e:
        logger.error(f"RDS scan error: {e}")
    return resources


def scan_s3(creds):
    """Scan all S3 buckets."""
    resources = []
    try:
        s3 = get_client('s3', creds)
        buckets = s3.list_buckets()
        for bucket in buckets.get('Buckets', []):
            # Rough estimate — real size needs CloudWatch or inventory
            monthly = 0.023 * 10  # Assume 10GB for baseline
            
            resources.append({
                'service_category': 'Storage',
                'service_name': 'S3',
                'resource_id': bucket['Name'],
                'resource_name': bucket['Name'],
                'resource_type': 'Bucket',
                'region': 'global',
                'tags': {},
                'status': 'ON',
                'on_since': bucket.get('CreationDate'),
                'last_checked': datetime.now(timezone.utc),
                'cpu_avg': 0.0,
                'network_in_mb': 0.0,
                'network_out_mb': 0.0,
                'disk_read_mb': 0.0,
                'disk_write_mb': 0.0,
                'monthly_cost': Decimal(str(round(monthly, 2))),
                'resource_details': {}
            })
    except Exception as e:
        logger.error(f"S3 scan error: {e}")
    return resources


def scan_lambda(creds, region='us-east-1'):
    """Scan all Lambda functions."""
    resources = []
    try:
        lam = get_client('lambda', creds, region)
        funcs = lam.list_functions()
        for fn in funcs.get('Functions', []):
            memory = fn.get('MemorySize', 128)
            monthly = round((memory / 1024) * 0.0000166667 * 1000000 + 0.20, 2)
            
            resources.append({
                'service_category': 'Compute',
                'service_name': 'Lambda',
                'resource_id': fn['FunctionName'],
                'resource_name': fn['FunctionName'],
                'resource_type': fn.get('Runtime', 'unknown'),
                'region': region,
                'tags': fn.get('Tags', {}),
                'status': 'ON',
                'on_since': None,
                'last_checked': datetime.now(timezone.utc),
                'cpu_avg': 0.0,
                'network_in_mb': 0.0,
                'network_out_mb': 0.0,
                'disk_read_mb': 0.0,
                'disk_write_mb': 0.0,
                'monthly_cost': Decimal(str(monthly)),
                'resource_details': {
                    'memory_mb': memory,
                    'timeout': fn.get('Timeout'),
                }
            })
    except Exception as e:
        logger.error(f"Lambda scan error: {e}")
    return resources


# ============================================================
# MAIN BREAKDOWN FUNCTION
# ============================================================

def generate_breakdown(aws_account, force_refresh=False):
    """
    Main function — scans AWS, generates AI verdicts, saves to DB.
    If force_refresh=False and data exists, returns cached data.
    """
    # Check cache
    if not force_refresh:
        existing = ResourceAIAnalysis.objects.filter(aws_account=aws_account)
        if existing.exists():
            logger.info(f"📦 Returning cached data: {existing.count()} resources")
            return build_response(aws_account, cached=True)
    
    logger.info(f"🔄 Fresh scan starting for {aws_account.account_id}")
    
    # Delete old data
    ResourceAIAnalysis.objects.filter(aws_account=aws_account).delete()
    
    # Assume role
    try:
        creds = assume_role(aws_account)
    except Exception as e:
        logger.error(f"Role assumption failed: {e}")
        return {'error': f'Failed to assume role: {e}'}
    
    # Scan all services
    all_resources = []
    all_resources.extend(scan_ec2(creds))
    all_resources.extend(scan_rds(creds))
    all_resources.extend(scan_s3(creds))
    all_resources.extend(scan_lambda(creds))
    
    logger.info(f"📊 Scanned {len(all_resources)} total resources")
    
    # For each resource, get AI verdict and save
    for r in all_resources:
        # Build AI input
        ai_input = {
            'service_name': r['service_name'],
            'service_category': r['service_category'],
            'resource_id': r['resource_id'],
            'resource_type': r['resource_type'],
            'region': r['region'],
            'status': r['status'],
            'on_since': r['on_since'].isoformat() if r['on_since'] else 'N/A',
            'cpu_avg': r['cpu_avg'],
            'network_in_mb': r['network_in_mb'],
            'network_out_mb': r['network_out_mb'],
            'monthly_cost': float(r['monthly_cost']),
            'tags': json.dumps(r['tags']),
            'extra': json.dumps(r.get('resource_details', {}))
        }
        
        verdict = get_ai_verdict(ai_input) or fallback_verdict(ai_input)
        
        # Save to DB
        ResourceAIAnalysis.objects.update_or_create(
            aws_account=aws_account,
            resource_id=r['resource_id'],
            defaults={
                'user': aws_account.user,
                'service_category': r['service_category'],
                'service_name': r['service_name'],
                'resource_name': r['resource_name'],
                'resource_type': r['resource_type'],
                'region': r['region'],
                'tags': r['tags'],
                'status': r['status'],
                'on_since': r['on_since'],
                'last_checked': r['last_checked'],
                'cpu_avg': r['cpu_avg'],
                'network_in_mb': r['network_in_mb'],
                'network_out_mb': r['network_out_mb'],
                'disk_read_mb': r['disk_read_mb'],
                'disk_write_mb': r['disk_write_mb'],
                'monthly_cost': r['monthly_cost'],
                'ai_verdict': verdict.get('verdict', 'MONITOR_IT'),
                'ai_short_reason': verdict.get('short_reason', ''),
                'ai_detailed_explanation': verdict.get('detailed_explanation', ''),
                'ai_savings_monthly': Decimal(str(verdict.get('savings_monthly', 0))),
                'ai_savings_yearly': Decimal(str(verdict.get('savings_yearly', 0))),
                'ai_risk': verdict.get('risk', 'LOW'),
                'ai_steps': verdict.get('steps', []),
                'ai_alternatives': verdict.get('alternatives', []),
                'ai_time_to_fix': verdict.get('time_to_fix', ''),
                'ai_one_click_available': verdict.get('one_click_available', False),
                'ai_priority': verdict.get('priority', 5),
                'resource_details': r.get('resource_details', {}),
            }
        )
    
    logger.info(f"✅ Saved {len(all_resources)} resources with AI verdicts")
    return build_response(aws_account, cached=False)


def build_response(aws_account, cached=False):
    """Format DB data into service + resource breakdown."""
    resources = ResourceAIAnalysis.objects.filter(aws_account=aws_account)
    
    # Group by service
    services_map = {}
    for r in resources:
        key = r.service_name
        if key not in services_map:
            services_map[key] = {
                'service_name': r.service_name,
                'service_category': r.service_category,
                'status': 'Active',
                'resource_count': 0,
                'monthly_cost': 0.0,
                'savings': 0.0,
                'resources': []
            }
        
        services_map[key]['resource_count'] += 1
        services_map[key]['monthly_cost'] += float(r.monthly_cost)
        services_map[key]['savings'] += float(r.ai_savings_monthly)
        
        services_map[key]['resources'].append({
            'resource_id': r.resource_id,
            'resource_name': r.resource_name,
            'resource_type': r.resource_type,
            'region': r.region,
            'status': r.status,
            'on_since': r.on_since.isoformat() if r.on_since else None,
            'last_checked': r.last_checked.isoformat() if r.last_checked else None,
            'cpu_avg': r.cpu_avg,
            'monthly_cost': float(r.monthly_cost),
            'ai_verdict': r.ai_verdict,
            'ai_short_reason': r.ai_short_reason,
            'ai_detailed_explanation': r.ai_detailed_explanation,
            'ai_savings_monthly': float(r.ai_savings_monthly),
            'ai_savings_yearly': float(r.ai_savings_yearly),
            'ai_risk': r.ai_risk,
            'ai_steps': r.ai_steps,
            'ai_alternatives': r.ai_alternatives,
            'ai_time_to_fix': r.ai_time_to_fix,
            'ai_one_click_available': r.ai_one_click_available,
            'ai_priority': r.ai_priority,
            'tags': r.tags,
            'resource_details': r.resource_details,
        })
    
    # Compute status per service
    for svc in services_map.values():
        idle_count = sum(1 for r in svc['resources'] if r['ai_verdict'] in ['STOP_IT', 'TERMINATE_IT'])
        if idle_count == svc['resource_count'] and svc['resource_count'] > 0:
            svc['status'] = 'Idle'
        elif idle_count > 0:
            svc['status'] = 'Partially Idle'
        else:
            svc['status'] = 'Active'
        svc['monthly_cost'] = round(svc['monthly_cost'], 2)
        svc['savings'] = round(svc['savings'], 2)
    
    services_list = sorted(services_map.values(), key=lambda x: x['monthly_cost'], reverse=True)
    all_resources_list = sorted(
        [r for svc in services_list for r in svc['resources']],
        key=lambda x: (-x['ai_priority'], -x['monthly_cost'])
    )
    
    total_cost = round(sum(s['monthly_cost'] for s in services_list), 2)
    total_savings = round(sum(s['savings'] for s in services_list), 2)
    
    return {
        'success': True,
        'cached': cached,
        'total_services': len(services_list),
        'total_resources': len(all_resources_list),
        'total_monthly_cost': total_cost,
        'total_savings': total_savings,
        'services': services_list,
        'resources': all_resources_list,
        'last_scan': django_timezone.now().isoformat(),
    }