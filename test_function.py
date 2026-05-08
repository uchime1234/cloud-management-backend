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


# Run all checks
if __name__ == "__main__":
    from myground.models import AWSAccount
    
    account = AWSAccount.objects.filter(status='connected').first()
    
    if account:
        print("\n" + "🚀 STARTING IDLE RESOURCES SCAN")
        print("=" * 80)
        
        # Check Load Balancers
        lb_results = check_idle_load_balancers(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Check Lambda Functions
        lambda_results = check_idle_lambda_functions(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Final summary
        print("\n" + "=" * 80)
        print("🎯 FINAL SUMMARY")
        print("=" * 80)
        print(f"📊 Idle Load Balancers: {len(lb_results)}")
        print(f"📡 Idle Lambda Functions: {len(lambda_results)}")
        
        total_savings = sum(lb['estimated_monthly_cost'] for lb in lb_results) + \
                       sum(l['estimated_monthly_cost'] for l in lambda_results)
        
        if total_savings > 0:
            print(f"\n💰 TOTAL POTENTIAL MONTHLY SAVINGS: ${total_savings:.2f}")
            print(f"💰 TOTAL POTENTIAL YEARLY SAVINGS: ${total_savings * 12:.2f}")