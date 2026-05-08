import boto3
from datetime import datetime, timedelta
from django.conf import settings
from botocore.exceptions import ClientError
from .models import AWSCostCache, CostDriver, CostDataHistory  # Added CostDataHistory
from django.utils import timezone
import hashlib
import json
import requests
import time

from django.conf import settings

# aws_cost.py - Add this at the top after imports
import logging
logger = logging.getLogger(__name__)


def get_monthly_cost(aws_account):
    """Get current month's total spend"""
    try:
        # Assume role
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        credentials = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName='MonthlyCost',
            ExternalId=str(aws_account.external_id)
        )['Credentials']
        
        # Create Cost Explorer client
        ce = boto3.client(
            'ce',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        # Get current month dates
        today = datetime.now().date()
        first_day = today.replace(day=1)
        
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': first_day.isoformat(),
                'End': today.isoformat()
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        
        if response['ResultsByTime']:
            amount = float(response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])
            return round(amount, 2)
        return 0.0
        
    except Exception as e:
        print(f"Error getting monthly cost: {e}")
        return None


def get_latest_daily_cost(aws_account):
    """Get the most recent day with cost data available"""
    try:
        # Assume role
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        credentials = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName='LatestCost',
            ExternalId=str(aws_account.external_id)
        )['Credentials']
        
        ce = boto3.client(
            'ce',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        # Get last 5 days of data
        today = datetime.now().date()
        start_date = today - timedelta(days=5)
        
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.isoformat(),
                'End': today.isoformat()
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost']
        )
        
        # Find the most recent day with non-zero cost
        for result in reversed(response['ResultsByTime']):
            if result['Total'] and result['Total']['UnblendedCost']['Amount']:
                amount = float(result['Total']['UnblendedCost']['Amount'])
                date = result['TimePeriod']['Start']
                return {
                    'date': date,
                    'amount': round(amount, 2)
                }
        
        return {'date': None, 'amount': 0.0}
        
    except Exception as e:
        print(f"Error getting latest cost: {e}")
        return {'date': None, 'amount': 0.0}
        

def get_last_7_days_cost(aws_account):
    """Get daily costs for last 7 days - for the graph"""
    try:
        # Assume role
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        credentials = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName='Last7Days',
            ExternalId=str(aws_account.external_id)
        )['Credentials']
        
        ce = boto3.client(
            'ce',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        # Calculate date range
        today = datetime.now().date()
        start_date = today - timedelta(days=7)
        
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.isoformat(),
                'End': today.isoformat()
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost']
        )
        
        # Format data for chart
        chart_data = []
        for result in response['ResultsByTime']:
            date_str = result['TimePeriod']['Start']
            # Format date to match your frontend (e.g., "Sept 8")
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            formatted_date = date_obj.strftime('%b %d')  # "Sep 08"
            
            chart_data.append({
                'name': formatted_date,
                'cost': float(result['Total']['UnblendedCost']['Amount'])
            })
        
        return chart_data
        
    except Exception as e:
        print(f"Error getting 7 days cost: {e}")
        return []


def get_90_days_cost(aws_account):
    """Get total cost for last 90 days"""
    try:
        # Assume role
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        credentials = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName='NinetyDaysCost',
            ExternalId=str(aws_account.external_id)
        )['Credentials']
        
        ce = boto3.client(
            'ce',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=90)
        
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.isoformat(),
                'End': end_date.isoformat()
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        
        total = sum(
            float(r['Total']['UnblendedCost']['Amount']) 
            for r in response['ResultsByTime']
        )
        
        return round(total, 2)
        
    except Exception as e:
        print(f"Error getting 90 days cost: {e}")
        return None


# ============================================================
# DATABASE STORAGE FUNCTIONS (Instead of Redis Cache)
# ============================================================

def save_cost_data(aws_account, cost_type, data):
    """Save cost data to database permanently"""
    try:
        CostDataHistory.objects.update_or_create(
            aws_account=aws_account,
            cost_type=cost_type,
            defaults={
                'data': data,
                'updated_at': timezone.now()
            }
        )
        print(f"💾 Saved {cost_type} to database")
        return True
    except Exception as e:
        print(f"❌ Failed to save {cost_type}: {e}")
        return False


def get_cost_data(aws_account, cost_type):
    """Get cost data from database"""
    try:
        record = CostDataHistory.objects.get(
            aws_account=aws_account,
            cost_type=cost_type
        )
        print(f"✅ Retrieved {cost_type} from database")
        return record.data
    except CostDataHistory.DoesNotExist:
        print(f"❌ No data found for {cost_type}")
        return None
    except Exception as e:
        print(f"❌ Error retrieving {cost_type}: {e}")
        return None


def clear_cost_data(aws_account):
    """Clear all cost data for an account from database"""
    try:
        deleted_count, _ = CostDataHistory.objects.filter(aws_account=aws_account).delete()
        print(f"🗑️ Cleared {deleted_count} cost data records from database")
        return deleted_count
    except Exception as e:
        print(f"❌ Error clearing cost data: {e}")
        return 0


# ============================================================
# CACHED FUNCTIONS USING DATABASE STORAGE
# ============================================================

def get_cached_90_days_cost(aws_account):
    """Get 90 days cost from database or fetch fresh"""
    data = get_cost_data(aws_account, '90_days')
    if data is not None:
        return data
    
    # Fetch fresh
    fresh_data = get_90_days_cost(aws_account)
    if fresh_data is not None:
        save_cost_data(aws_account, '90_days', fresh_data)
    return fresh_data


# aws_cost.py - Make sure the function signature is correct

def get_cached_monthly_cost(aws_account, time_period=None):
    """Get monthly cost from database or fetch fresh"""
    # If time_period is provided, use it, otherwise use default
    if time_period:
        # Handle custom time period
        data = get_cost_data(aws_account, f'monthly_{time_period["start"]}')
        if data is not None:
            return data
        fresh_data = get_monthly_cost(aws_account, time_period)
        if fresh_data is not None:
            save_cost_data(aws_account, f'monthly_{time_period["start"]}', fresh_data)
        return fresh_data
    else:
        # Default behavior
        data = get_cost_data(aws_account, 'monthly')
        if data is not None:
            return data
        fresh_data = get_monthly_cost(aws_account)
        if fresh_data is not None:
            save_cost_data(aws_account, 'monthly', fresh_data)
        return fresh_data


def get_cached_7_days_cost(aws_account):
    """Get 7 days cost from database or fetch fresh"""
    data = get_cost_data(aws_account, '7_days')
    if data is not None:
        return data
    
    fresh_data = get_last_7_days_cost(aws_account)
    if fresh_data:
        save_cost_data(aws_account, '7_days', fresh_data)
    return fresh_data


def get_cached_yesterday_cost(aws_account):
    """Get yesterday cost from database or fetch fresh"""
    data = get_cost_data(aws_account, 'yesterday')
    if data is not None:
        return data
    
    fresh_data = get_latest_daily_cost(aws_account)
    if fresh_data:
        save_cost_data(aws_account, 'yesterday', fresh_data)
    return fresh_data


def get_cached_low_level_costs(aws_account):
    """Get low-level costs from database or fetch fresh"""
    data = get_cost_data(aws_account, 'low_level')
    if data is not None:
        return data
    
    fresh_data = get_low_level_costs(aws_account)
    if fresh_data:
        save_cost_data(aws_account, 'low_level', fresh_data)
    return fresh_data

# In aws_cost.py, update the get_service_insights function to filter small amounts

def get_service_insights(service, amount, percentage):
    """
    Return valuable insights for specific AWS services
    Only return insights for services with meaningful costs (> $1 or > 1%)
    """
    # Skip services with negligible costs (less than $1 or less than 0.5%)
    if amount < 1.0 and percentage < 0.5:
        return None
    
    insights = {
        'EC2': {
            'title': f'EC2 compute costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Your EC2 instances are the largest compute cost driver. Consider reviewing instance sizes and using Spot instances for non-production workloads.',
            'recommendation': 'Enable EC2 Auto Scaling, use Savings Plans, and clean up idle instances',
            'estimated_savings': amount * 0.3,
            'icon': '🖥️',
            'color': 'orange'
        },
        'Amazon Elastic Compute Cloud - Compute': {
            'title': f'EC2 compute costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Your EC2 instances are costing money. Review if these instances are still needed.',
            'recommendation': 'Consider stopping or terminating idle EC2 instances',
            'estimated_savings': amount * 0.3,
            'icon': '🖥️',
            'color': 'orange'
        },
        'EC2 - Other': {
            'title': f'EC2 other costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'These are additional EC2-related charges including EBS volumes, snapshots, and data transfer.',
            'recommendation': 'Review attached EBS volumes and snapshots for cleanup opportunities',
            'estimated_savings': amount * 0.2,
            'icon': '💾',
            'color': 'orange'
        },
        'AmazonS3': {
            'title': f'S3 storage costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Storage costs are growing. Implement lifecycle policies to move old data to cheaper tiers.',
            'recommendation': 'Set up S3 Lifecycle rules, enable Intelligent-Tiering, and delete incomplete multipart uploads',
            'estimated_savings': amount * 0.4,
            'icon': '📦',
            'color': 'green'
        },
        'AWSDataTransfer': {
            'title': f'Data transfer costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Data transfer is a significant cost. Optimize by keeping data within same region and using CloudFront.',
            'recommendation': 'Use CloudFront CDN, enable compression, and implement data transfer cost allocation tags',
            'estimated_savings': amount * 0.25,
            'icon': '🌐',
            'color': 'blue'
        },
        'AmazonRDS': {
            'title': f'RDS database costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Your databases are costing more than expected. Review instance sizes and consider Aurora Serverless.',
            'recommendation': 'Right-size RDS instances, use Reserved Instances, and enable Storage Auto Scaling',
            'estimated_savings': amount * 0.2,
            'icon': '🗄️',
            'color': 'purple'
        },
        'Amazon Relational Database Service': {
            'title': f'RDS database costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Your RDS instances are costing money.',
            'recommendation': 'Consider stopping idle RDS instances or downsizing',
            'estimated_savings': amount * 0.2,
            'icon': '🗄️',
            'color': 'purple'
        },
        'AmazonVPC': {
            'title': f'VPC/NAT Gateway costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'NAT Gateway and VPC costs are accumulating. Consider using VPC endpoints and optimizing data flow.',
            'recommendation': 'Use VPC Endpoints for AWS services, consolidate NAT Gateways, and review VPC Flow Logs',
            'estimated_savings': amount * 0.35,
            'icon': '🔌',
            'color': 'red'
        },
        'AWSLambda': {
            'title': f'Lambda compute costs: ${amount:.2f} ({percentage}% of total)',
            'description': 'Serverless costs are rising. Optimize function memory and execution time.',
            'recommendation': 'Review function memory settings, use Lambda Power Tuning, and implement Provisioned Concurrency wisely',
            'estimated_savings': amount * 0.2,
            'icon': '⚡',
            'color': 'yellow'
        }
    }
    
    # Default insights for unmapped services with meaningful cost
    if amount >= 1.0 or percentage >= 1.0:
        default = {
            'title': f'{service} costs: ${amount:.2f} ({percentage}% of total)',
            'description': f'This service contributes {percentage}% to your total bill. Review usage and optimize.',
            'recommendation': 'Review resource utilization and consider reservations for steady-state workloads',
            'estimated_savings': amount * 0.15,
            'icon': '📊',
            'color': 'gray'
        }
        return insights.get(service, default)
    
    return None

# In aws_cost.py, update the analyze_cost_drivers function

def analyze_cost_drivers(aws_account, monthly_cost):
    """
    Analyze AWS costs to identify top drivers with valuable insights
    Only include services with meaningful costs (> $1 or > 1% of total)
    """
    try:
        print(f"🔍 Starting cost driver analysis for {aws_account.account_alias}...")
        
        # Assume role
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        credentials = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName='CostDrivers',
            ExternalId=str(aws_account.external_id)
        )['Credentials']
        
        ce = boto3.client(
            'ce',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        today = datetime.now().date()
        first_day = today.replace(day=1)
        
        # Get cost breakdown by service
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': first_day.isoformat(),
                'End': today.isoformat()
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        drivers = []
        if response['ResultsByTime']:
            groups = response['ResultsByTime'][0].get('Groups', [])
            
            # Filter out zero-cost services
            service_costs = []
            for group in groups:
                service = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                # Only include services with meaningful cost (> $0.50)
                if amount > 0.50:
                    service_costs.append((service, amount))
            
            service_costs.sort(key=lambda x: x[1], reverse=True)
            
            # Generate valuable insights for top 5 services (only those with meaningful cost)
            for service, amount in service_costs[:5]:
                percentage = (amount / monthly_cost * 100) if monthly_cost > 0 else 0
                
                # Skip if the percentage is very small (less than 0.5% of total)
                if percentage < 0.5 and amount < 1.0:
                    continue
                
                # Get service-specific insights
                insights = get_service_insights(service, amount, percentage)
                
                # Skip if no insights returned (meaningless cost)
                if not insights:
                    continue
                
                driver = {
                    'title': insights['title'],
                    'description': insights['description'],
                    'service': service,
                    'amount': round(amount, 2),
                    'percentage': round(percentage, 1),
                    'recommendation': insights['recommendation'],
                    'estimated_savings': round(insights['estimated_savings'], 2),
                    'icon': insights['icon'],
                    'color': insights['color'],
                    'impact': 'high' if percentage > 20 else 'medium' if percentage > 10 else 'low'
                }
                drivers.append(driver)
            
            # Save to CostDriver database model
            for driver in drivers:
                CostDriver.objects.update_or_create(
                    aws_account=aws_account,
                    service_name=driver['service'],
                    driver_type='top',
                    defaults={
                        'title': driver['title'],
                        'description': driver['description'],
                        'impact_percentage': driver['percentage'],
                        'recommendation': driver['recommendation'],
                        'estimated_savings': driver['estimated_savings']
                    }
                )
        
        print(f"✅ Analyzed {len(drivers)} meaningful cost drivers")
        return drivers
        
    except Exception as e:
        print(f"Error analyzing cost drivers: {e}")
        return []

def get_cached_cost_drivers(aws_account, monthly_cost=None):
    """
    Get cost drivers from database, or analyze fresh data if not exists
    """
    # Try to get from database first
    data = get_cost_data(aws_account, 'cost_drivers')
    if data is not None:
        return data
    
    # If no monthly cost provided, get it first
    if monthly_cost is None:
        monthly_cost = get_cached_monthly_cost(aws_account)
    
    # Analyze fresh cost drivers (this is the slow part)
    print(f"🔍 Analyzing cost drivers from AWS...")
    drivers_data = analyze_cost_drivers(aws_account, monthly_cost)
    
    if drivers_data:
        # Save to database
        save_cost_data(aws_account, 'cost_drivers', drivers_data)
    
    return drivers_data


def get_low_level_costs(aws_account):
    """
    Get granular cost breakdown by USAGE_TYPE (NAT Gateway, Data Transfer, etc.)
    """
    try:
        # Assume role
        sts = boto3.client(
            'sts',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        credentials = sts.assume_role(
            RoleArn=aws_account.role_arn,
            RoleSessionName='LowLevelCosts',
            ExternalId=str(aws_account.external_id)
        )['Credentials']
        
        ce = boto3.client(
            'ce',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1'
        )
        
        # Last 7 days
        today = datetime.now().date()
        start_date = today - timedelta(days=7)
        
        # Group by USAGE_TYPE to get granular costs
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.isoformat(),
                'End': today.isoformat()
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}]
        )
        
        # Collect all usage types and their costs
        usage_costs = {}
        for result in response['ResultsByTime']:
            for group in result.get('Groups', []):
                usage_type = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                if amount > 0:
                    usage_costs[usage_type] = usage_costs.get(usage_type, 0) + amount
        
        # Map to readable names and categories
        low_level_items = []
        
        # Define mappings
        mappings = {
            # NAT Gateway
            'NatGateway-Hours': ('NAT Gateway (Hourly)', 'Network'),
            'NatGateway-GB-Processed': ('NAT Gateway (Data)', 'Network'),
            
            # Elastic IPs
            'ElasticIP:IdleAddress': ('Unattached Elastic IPs', 'Idle Resources'),
            
            # Load Balancers
            'LoadBalancer-Usage': ('Load Balancer Hours', 'Load Balancers'),
            'ElasticLoadBalancing:LCU': ('Load Balancer Capacity Units', 'Load Balancers'),
            
            # Data Transfer
            'DataTransfer-Out-Bytes': ('Data Transfer Out', 'Network'),
            'USE1-EUN1-AWS-Out-Bytes': ('Data Transfer (US-East to Europe)', 'Network'),
            'USE1-USE2-AWS-Out-Bytes': ('Data Transfer (US-East to US-West)', 'Network'),
            
            # API Requests
            'USE1-APIRequest': ('API Requests (US-East)', 'API Calls'),
            'APIGateway-Request': ('API Gateway Requests', 'API Calls'),
            
            # VPC
            'VPC-Endpoint-Hours': ('VPC Endpoint Hours', 'Network'),
            'VPC-Peering-Hours': ('VPC Peering Hours', 'Network'),
            
            # Transit Gateway
            'TransitGateway-Bytes': ('Transit Gateway Data', 'Network'),
            
            # VPN
            'VPNConnection-Hours': ('VPN Connection Hours', 'Network'),
            
            # CloudWatch
            'CloudWatch-Metric-Requests': ('CloudWatch Metrics', 'Monitoring'),
            'CloudWatch-Log-Data-Scanned': ('CloudWatch Logs Scanned', 'Monitoring'),
            
            # S3
            'S3-Requests-Tier1': ('S3 GET/HEAD Requests', 'Storage'),
            'S3-Requests-Tier2': ('S3 PUT/COPY Requests', 'Storage'),
            
            # Lambda
            'Lambda-Invocations': ('Lambda Invocations', 'Compute'),
            'Lambda-GB-Second': ('Lambda Compute Time', 'Compute'),
        }
        
        # Build the list
        total = 0
        for usage_type, amount in sorted(usage_costs.items(), key=lambda x: x[1], reverse=True):
            name, category = mappings.get(usage_type, (usage_type, 'Other'))
            low_level_items.append({
                'name': name,
                'usage_type': usage_type,
                'amount': round(amount, 2),
                'category': category
            })
            total += amount
        
        # Calculate percentages
        for item in low_level_items:
            item['percentage'] = round((item['amount'] / total * 100), 1) if total > 0 else 0
        
        return {
            'items': low_level_items,
            'total': round(total, 2),
            'period': {
                'start': start_date.isoformat(),
                'end': today.isoformat()
            }
        }
        
    except Exception as e:
        print(f"Error getting low-level costs: {e}")
        return {'items': [], 'total': 0, 'error': str(e)}


def generate_cost_analysis(aws_account, cost_data, cost_drivers):
    """
    Generate AI-powered cost analysis using GROQ API
    """
    default_advice = "Unable to generate analysis at this time. Please check your AWS Cost Explorer for detailed insights."
    
    try:
        # Prepare the data for the AI
        analysis_data = {
            "account_alias": aws_account.account_alias,
            "account_id": aws_account.account_id,
            "total_90_days": cost_data.get('total_90_days', 0),
            "current_month": cost_data.get('monthly_cost', 0),
            "avg_daily_spend": round(cost_data.get('monthly_cost', 0) / 30, 2) if cost_data.get('monthly_cost', 0) > 0 else 0,
            "latest_day_cost": cost_data.get('latest_daily_cost', 0),
            "cost_drivers": []
        }
        
        # Add cost drivers
        for driver in cost_drivers[:5]:
            analysis_data["cost_drivers"].append({
                "service": driver['service'],
                "cost": driver['amount'],
                "percentage": driver['percentage']
            })
        
        # Build the prompt
        prompt = f"""As a Senior Cloud Financial Expert (FinOps Specialist), analyze this AWS cost data:

AWS Account: {analysis_data['account_alias']}
Current Month Spend: ${analysis_data['current_month']}
Last 90 Days Total: ${analysis_data['total_90_days']}
Average Daily Spend: ${analysis_data['avg_daily_spend']}
Latest Day Cost: ${analysis_data['latest_day_cost']}

Top Cost Drivers:
{chr(10).join([f"- {d['service']}: ${d['cost']} ({d['percentage']}% of total)" for d in analysis_data['cost_drivers']])}

Provide:
1. A brief analysis of the spending pattern
2. For each top driver, one specific, actionable recommendation to reduce costs
3. Estimated savings for each recommendation
4. Total estimated monthly savings

Format your response with clear sections and bullet points. Keep it concise but actionable."""

        headers = {
            "Authorization": f"Bearer {settings.GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Cloud Financial Expert specializing in AWS cost optimization. Provide practical, actionable advice with estimated savings percentages. Be specific and concise."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 800
        }
        
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Attempt {attempt + 1}: Generating AI cost analysis with GROQ...")
                response = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=45
                )
                
                if response.status_code == 200:
                    result = response.json()
                    analysis = result['choices'][0]['message']['content']
                    
                    if analysis:
                        logger.info(f"✅ Analysis generated successfully")
                        
                        # Save to database
                        from .models import AWSCostAnalysis
                        AWSCostAnalysis.objects.update_or_create(
                            aws_account=aws_account,
                            analysis_type='ai_insights',
                            defaults={
                                'analysis_data': analysis_data,
                                'analysis_result': analysis,
                                'cost_drivers_used': analysis_data['cost_drivers']
                            }
                        )
                        
                        return analysis
                    else:
                        logger.warning("AI returned empty analysis")
                        return default_advice
                        
                elif response.status_code == 429:
                    logger.warning(f"Rate limited, waiting {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    logger.error(f"GROQ API error: {response.status_code} - {response.text}")
                    if attempt == max_retries - 1:
                        return default_advice
                    time.sleep(retry_delay)
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed (attempt {attempt + 1}): {str(e)}")
                if attempt == max_retries - 1:
                    return default_advice
                time.sleep(retry_delay)
                
    except Exception as e:
        logger.error(f"Error in generate_cost_analysis: {str(e)}")
        return default_advice


def get_cached_cost_analysis(aws_account, cost_data, cost_drivers):
    """
    Get cached analysis from database or generate new one
    """
    try:
        from django.utils import timezone
        from datetime import timedelta
        from .models import AWSCostAnalysis
        
        # Check if we have a recent analysis (less than 24 hours old)
        recent_analysis = AWSCostAnalysis.objects.filter(
            aws_account=aws_account,
            analysis_type='ai_insights',
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).first()
        
        if recent_analysis:
            logger.info(f"✅ Using cached analysis from {recent_analysis.created_at}")
            return recent_analysis.analysis_result
        
        logger.info("❌ No recent analysis found, generating new one...")
        return generate_cost_analysis(aws_account, cost_data, cost_drivers)
        
    except Exception as e:
        logger.error(f"Error getting cached analysis: {e}")
        return generate_cost_analysis(aws_account, cost_data, cost_drivers)
