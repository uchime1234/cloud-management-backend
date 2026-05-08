# discovery/elb_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_elb_services(creds, region):
    """Discover Elastic Load Balancing resources (ALB, NLB, CLB, GWLB)"""
    services = []
    try:
        # ========== APPLICATION LOAD BALANCERS ==========
        elbv2_client = boto3.client(
            'elbv2',
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
        
        # ALB/NLB/GWLB
        load_balancers = elbv2_client.describe_load_balancers()
        for lb in load_balancers.get('LoadBalancers', []):
            lb_arn = lb['LoadBalancerArn']
            lb_name = lb['LoadBalancerName']
            lb_type = lb.get('Type', 'application')
            state = lb.get('State', {}).get('Code', 'active')
            scheme = lb.get('Scheme', 'internal')
            vpc_id = lb.get('VpcId')
            created_time = lb.get('CreatedTime')
            
            # Base hourly rate
            base_hourly_rate = 0.0225  # ALB/NLB
            capacity_unit_cost = 0.008  # LCU for ALB
            
            if lb_type == 'application':
                service_id = 'application_load_balancer'
                capacity_unit_type = 'LCU'
            elif lb_type == 'network':
                service_id = 'network_load_balancer'
                capacity_unit_cost = 0.006  # NCU for NLB
                capacity_unit_type = 'NCU'
            elif lb_type == 'gateway':
                service_id = 'gateway_load_balancer'
                base_hourly_rate = 0.0125
                capacity_unit_cost = 0.0035  # GLCU for GWLB
                capacity_unit_type = 'GLCU'
            
            # Monthly cost: base + estimated capacity units
            base_monthly_cost = base_hourly_rate * 730
            estimated_capacity_units = 10  # Assume 10 capacity units per hour
            capacity_monthly_cost = capacity_unit_cost * estimated_capacity_units * 730
            total_monthly_cost = base_monthly_cost + capacity_monthly_cost
            
            services.append({
                'service_id': service_id,
                'resource_id': lb_arn,
                'resource_name': lb_name,
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                'details': {
                    'load_balancer_arn': lb_arn,
                    'load_balancer_name': lb_name,
                    'dns_name': lb.get('DNSName'),
                    'type': lb_type,
                    'scheme': scheme,
                    'vpc_id': vpc_id,
                    'state': state,
                    'created_time': created_time.isoformat() if created_time else None,
                    'availability_zones': lb.get('AvailabilityZones', []),
                    'security_groups': lb.get('SecurityGroups', []),
                    'ip_address_type': lb.get('IpAddressType', 'ipv4'),
                    'customer_owned_ipv4_pool': lb.get('CustomerOwnedIpv4Pool'),
                    'tags': get_elbv2_tags(elbv2_client, lb_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== LISTENERS ==========
            try:
                listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                for listener in listeners.get('Listeners', []):
                    services.append({
                        'service_id': f"{lb_type}_listener",
                        'resource_id': listener['ListenerArn'],
                        'resource_name': f"{lb_name}-{listener.get('Port', 'unknown')}",
                        'region': region,
                        'service_type': 'Networking',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'listener_arn': listener['ListenerArn'],
                            'load_balancer_arn': lb_arn,
                            'port': listener.get('Port'),
                            'protocol': listener.get('Protocol'),
                            'ssl_policy': listener.get('SslPolicy'),
                            'certificates': listener.get('Certificates', []),
                            'default_actions': listener.get('DefaultActions', []),
                            'alpn_policy': listener.get('AlpnPolicy', [])
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
            
            # ========== TARGET GROUPS ==========
            try:
                target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)
                for tg in target_groups.get('TargetGroups', []):
                    # Get target health
                    try:
                        health = elbv2_client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                        target_health = health.get('TargetHealthDescriptions', [])
                    except:
                        target_health = []
                    
                    services.append({
                        'service_id': 'target_group',
                        'resource_id': tg['TargetGroupArn'],
                        'resource_name': tg['TargetGroupName'],
                        'region': region,
                        'service_type': 'Networking',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'target_group_arn': tg['TargetGroupArn'],
                            'target_group_name': tg['TargetGroupName'],
                            'protocol': tg.get('Protocol'),
                            'port': tg.get('Port'),
                            'vpc_id': tg.get('VpcId'),
                            'health_check_protocol': tg.get('HealthCheckProtocol'),
                            'health_check_port': tg.get('HealthCheckPort'),
                            'health_check_path': tg.get('HealthCheckPath'),
                            'health_check_interval_seconds': tg.get('HealthCheckIntervalSeconds'),
                            'health_check_timeout_seconds': tg.get('HealthCheckTimeoutSeconds'),
                            'healthy_threshold_count': tg.get('HealthyThresholdCount'),
                            'unhealthy_threshold_count': tg.get('UnhealthyThresholdCount'),
                            'target_type': tg.get('TargetType', 'instance'),
                            'target_count': len(target_health),
                            'target_health_summary': summarize_target_health(target_health)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== CLASSIC LOAD BALANCERS ==========
        elb_client = boto3.client(
            'elb',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region
        )
        
        classic_lbs = elb_client.describe_load_balancers()
        for lb in classic_lbs.get('LoadBalancerDescriptions', []):
            lb_name = lb['LoadBalancerName']
            dns_name = lb.get('DNSName')
            scheme = lb.get('Scheme', 'internet-facing')
            vpc_id = lb.get('VPCId')
            created_time = lb.get('CreatedTime')
            
            # Classic LB: $0.025 per hour + $0.008 per GB processed
            base_hourly_rate = 0.025
            base_monthly_cost = base_hourly_rate * 730
            estimated_data_gb = 100  # Assume 100GB data processed
            data_cost = estimated_data_gb * 0.008
            total_monthly_cost = base_monthly_cost + data_cost
            
            services.append({
                'service_id': 'classic_load_balancer',
                'resource_id': lb_name,
                'resource_name': lb_name,
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                'details': {
                    'load_balancer_name': lb_name,
                    'dns_name': dns_name,
                    'scheme': scheme,
                    'vpc_id': vpc_id,
                    'created_time': created_time.isoformat() if created_time else None,
                    'availability_zones': lb.get('AvailabilityZones', []),
                    'subnets': lb.get('Subnets', []),
                    'security_groups': lb.get('SecurityGroups', []),
                    'listener_descriptions': [
                        {
                            'protocol': l['Listener'].get('Protocol'),
                            'load_balancer_port': l['Listener'].get('LoadBalancerPort'),
                            'instance_protocol': l['Listener'].get('InstanceProtocol'),
                            'instance_port': l['Listener'].get('InstancePort')
                        } for l in lb.get('ListenerDescriptions', [])
                    ],
                    'health_check': lb.get('HealthCheck', {}),
                    'instances': [i['InstanceId'] for i in lb.get('Instances', [])],
                    'backend_server_descriptions': lb.get('BackendServerDescriptions', []),
                    'connection_settings': lb.get('ConnectionSettings', {}),
                    'cross_zone_load_balancing': lb.get('CrossZoneLoadBalancing', {}).get('Enabled', False),
                    'access_log': lb.get('AccessLog', {}).get('Enabled', False),
                    'connection_draining': lb.get('ConnectionDraining', {}).get('Enabled', False),
                    'tags': get_elb_tags(elb_client, lb_name)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
    except Exception as e:
        print(f"Error discovering ELB services in {region}: {str(e)}")
    
    return services

def get_elbv2_tags(client, resource_arn):
    """Get tags for ELBv2 resource"""
    try:
        response = client.describe_tags(ResourceArns=[resource_arn])
        return response.get('TagDescriptions', [{}])[0].get('Tags', [])
    except:
        return []

def get_elb_tags(client, load_balancer_name):
    """Get tags for Classic ELB"""
    try:
        response = client.describe_tags(LoadBalancerNames=[load_balancer_name])
        return response.get('TagDescriptions', [{}])[0].get('Tags', [])
    except:
        return []

def summarize_target_health(target_health):
    """Summarize target health status"""
    summary = {'healthy': 0, 'unhealthy': 0, 'unused': 0, 'draining': 0}
    for target in target_health:
        state = target.get('TargetHealth', {}).get('State', 'unknown')
        if state == 'healthy':
            summary['healthy'] += 1
        elif state == 'unhealthy':
            summary['unhealthy'] += 1
        elif state == 'unused':
            summary['unused'] += 1
        elif state == 'draining':
            summary['draining'] += 1
    return summary