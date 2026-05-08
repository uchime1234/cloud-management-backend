# discovery/route53_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_route53_services(creds):
    """Discover Route53 hosted zones, health checks, and related services (global)"""
    services = []
    try:
        client = boto3.client(
            'route53',
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
        
        # ========== HOSTED ZONES ==========
        hosted_zones = client.list_hosted_zones()
        for zone in hosted_zones.get('HostedZones', []):
            zone_id = zone['Id'].split('/')[-1]
            zone_name = zone['Name']
            private_zone = zone.get('Config', {}).get('PrivateZone', False)
            
            # Hosted zone: $0.50 per month
            monthly_cost = 0.50
            
            service_id = 'hosted_zone_private' if private_zone else 'hosted_zone'
            
            # Get resource record sets count for billing
            record_sets = client.list_resource_record_sets(HostedZoneId=zone_id)
            record_count = len(record_sets.get('ResourceRecordSets', []))
            
            services.append({
                'service_id': service_id,
                'resource_id': zone['Id'],
                'resource_name': zone_name.rstrip('.'),
                'region': 'global',
                'service_type': 'Networking',
                'estimated_monthly_cost': monthly_cost,
                'details': {
                    'hosted_zone_id': zone_id,
                    'name': zone_name,
                    'private_zone': private_zone,
                    'record_count': record_count,
                    'comment': zone.get('Config', {}).get('Comment'),
                    'linked_service': zone.get('LinkedService'),
                    'resource_record_set_count': zone.get('ResourceRecordSetCount', 0),
                    'tags': get_route53_tags(client, zone['Id'])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== QUERY LOGGING ==========
            try:
                loggings = client.list_query_logging_configs(HostedZoneId=zone_id)
                for log_config in loggings.get('QueryLoggingConfigs', []):
                    services.append({
                        'service_id': 'query_logging',
                        'resource_id': log_config['Id'],
                        'resource_name': f"{zone_name.rstrip('.')} Query Logs",
                        'region': 'global',
                        'service_type': 'Networking',
                        'estimated_monthly_cost': 0.50,
                'count': 1,  # $0.50 per GB logged
                        'details': {
                            'hosted_zone_id': zone_id,
                            'cloudwatch_log_group_arn': log_config.get('CloudWatchLogsLogGroupArn'),
                            'status': 'enabled'
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== HEALTH CHECKS ==========
        health_checks = client.list_health_checks()
        for health_check in health_checks.get('HealthChecks', []):
            health_check_id = health_check['Id']
            health_check_config = health_check.get('HealthCheckConfig', {})
            
            # Health check pricing
            health_check_type = health_check_config.get('Type', 'HTTP')
            monthly_cost = 0.50  # Basic health check
            
            # Enhanced/HTTPS health checks cost more
            if health_check_type == 'HTTPS' and health_check_config.get('EnableSNI', False):
                monthly_cost = 1.00
            elif health_check_config.get('RequestInterval', 30) == 10:
                monthly_cost = 2.00  # Fast health check
            
            service_id = 'health_check_enhanced' if monthly_cost > 0.50 else 'health_check'
            
            services.append({
                'service_id': service_id,
                'resource_id': health_check['Id'],
                'resource_name': health_check_config.get('FullyQualifiedDomainName', health_check_id),
                'region': 'global',
                'service_type': 'Networking',
                'estimated_monthly_cost': monthly_cost,
                'details': {
                    'health_check_id': health_check_id,
                    'type': health_check_config.get('Type'),
                    'domain_name': health_check_config.get('FullyQualifiedDomainName'),
                    'ip_address': health_check_config.get('IPAddress'),
                    'port': health_check_config.get('Port', 80),
                    'resource_path': health_check_config.get('ResourcePath'),
                    'request_interval': health_check_config.get('RequestInterval', 30),
                    'failure_threshold': health_check_config.get('FailureThreshold', 3),
                    'measure_latency': health_check_config.get('MeasureLatency', False),
                    'inverted': health_check_config.get('Inverted', False),
                    'disabled': health_check_config.get('Disabled', False),
                    'enable_sni': health_check_config.get('EnableSNI', False),
                    'child_health_checks': health_check_config.get('ChildHealthChecks', []),
                    'health_threshold': health_check_config.get('HealthThreshold'),
                    'alarm_identifier': health_check_config.get('AlarmIdentifier'),
                    'tags': get_route53_tags(client, health_check['Id'])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== DNS FIREWALL ==========
        try:
            route53resolver = boto3.client(
                'route53resolver',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name='us-east-1'
            )
            
            firewall_domain_lists = route53resolver.list_firewall_domain_lists()
            for domain_list in firewall_domain_lists.get('FirewallDomainLists', []):
                # $0.60 per domain list per month
                monthly_cost = 0.60
                
                services.append({
                    'service_id': 'dns_firewall',
                    'resource_id': domain_list['Arn'],
                    'resource_name': domain_list['Name'],
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'firewall_domain_list_id': domain_list['Id'],
                        'name': domain_list['Name'],
                        'arn': domain_list['Arn'],
                        'domain_count': domain_list.get('DomainCount', 0),
                        'status': domain_list.get('Status'),
                        'status_message': domain_list.get('StatusMessage'),
                        'managed_owner_name': domain_list.get('ManagedOwnerName'),
                        'creator_request_id': domain_list.get('CreatorRequestId'),
                        'creation_time': domain_list.get('CreationTime'),
                        'modification_time': domain_list.get('ModificationTime')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            
            # ========== DNS FIREWALL RULE GROUPS ==========
            firewall_rule_groups = route53resolver.list_firewall_rule_groups()
            for rule_group in firewall_rule_groups.get('FirewallRuleGroups', []):
                services.append({
                    'service_id': 'dns_firewall',
                    'resource_id': rule_group['Arn'],
                    'resource_name': rule_group['Name'],
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.60,
                'count': 1,  # $0.60 per rule group-month
                    'details': {
                        'firewall_rule_group_id': rule_group['Id'],
                        'name': rule_group['Name'],
                        'arn': rule_group['Arn'],
                        'rule_count': rule_group.get('RuleCount', 0),
                        'status': rule_group.get('Status'),
                        'status_message': rule_group.get('StatusMessage'),
                        'owner_id': rule_group.get('OwnerId'),
                        'share_status': rule_group.get('ShareStatus'),
                        'creator_request_id': rule_group.get('CreatorRequestId'),
                        'creation_time': rule_group.get('CreationTime'),
                        'modification_time': rule_group.get('ModificationTime')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== RESOLVER ENDPOINTS ==========
        try:
            route53resolver = boto3.client(
                'route53resolver',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name='us-east-1'
            )
            
            # Inbound endpoints
            inbound_endpoints = route53resolver.list_resolver_endpoints(
                Filters=[{'Name': 'Direction', 'Values': ['INBOUND']}]
            )
            for endpoint in inbound_endpoints.get('ResolverEndpoints', []):
                hourly_cost = 0.125
                monthly_cost = hourly_cost * 730
                
                services.append({
                    'service_id': 'resolver_inbound_endpoint',
                    'resource_id': endpoint['Arn'],
                    'resource_name': endpoint['Name'],
                    'region': endpoint.get('HostVPCId', 'global'),
                    'service_type': 'Networking',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'resolver_endpoint_id': endpoint['Id'],
                        'name': endpoint.get('Name'),
                        'arn': endpoint['Arn'],
                        'direction': endpoint.get('Direction'),
                        'ip_address_count': endpoint.get('IpAddressCount', 0),
                        'host_vpc_id': endpoint.get('HostVPCId'),
                        'security_group_ids': endpoint.get('SecurityGroupIds', []),
                        'status': endpoint.get('Status'),
                        'status_message': endpoint.get('StatusMessage'),
                        'creation_time': endpoint.get('CreationTime'),
                        'modification_time': endpoint.get('ModificationTime'),
                        'tags': endpoint.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            
            # Outbound endpoints
            outbound_endpoints = route53resolver.list_resolver_endpoints(
                Filters=[{'Name': 'Direction', 'Values': ['OUTBOUND']}]
            )
            for endpoint in outbound_endpoints.get('ResolverEndpoints', []):
                hourly_cost = 0.125
                monthly_cost = hourly_cost * 730
                
                services.append({
                    'service_id': 'resolver_outbound_endpoint',
                    'resource_id': endpoint['Arn'],
                    'resource_name': endpoint['Name'],
                    'region': endpoint.get('HostVPCId', 'global'),
                    'service_type': 'Networking',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'resolver_endpoint_id': endpoint['Id'],
                        'name': endpoint.get('Name'),
                        'arn': endpoint['Arn'],
                        'direction': endpoint.get('Direction'),
                        'ip_address_count': endpoint.get('IpAddressCount', 0),
                        'host_vpc_id': endpoint.get('HostVPCId'),
                        'security_group_ids': endpoint.get('SecurityGroupIds', []),
                        'status': endpoint.get('Status'),
                        'status_message': endpoint.get('StatusMessage'),
                        'creation_time': endpoint.get('CreationTime'),
                        'modification_time': endpoint.get('ModificationTime'),
                        'tags': endpoint.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== DOMAIN REGISTRATIONS ==========
        try:
            route53domains = boto3.client(
                'route53domains',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name='us-east-1'
            )
            
            domains = route53domains.list_domains()
            for domain in domains.get('Domains', []):
                domain_name = domain['DomainName']
                
                # Domain registration cost varies by TLD, using .com as example
                yearly_cost = 12.00
                
                services.append({
                    'service_id': 'domain_registration',
                    'resource_id': domain_name,
                    'resource_name': domain_name,
                    'region': 'global',
                    'service_type': 'Networking',
                    'estimated_monthly_cost': round(yearly_cost / 12, 2),
                'count': 1,
                    'details': {
                        'domain_name': domain_name,
                        'auto_renew': domain.get('AutoRenew', False),
                        'expiry': domain.get('Expiry').isoformat() if domain.get('Expiry') else None,
                        'transfer_lock': domain.get('TransferLock', False),
                        'status': domain.get('DomainStatus', []),
                        'privacy_protection_enabled': check_domain_privacy(route53domains, domain_name)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== TRAFFIC FLOW POLICIES ==========
        try:
            traffic_policies = client.list_traffic_policies()
            for policy in traffic_policies.get('TrafficPolicySummaries', []):
                # $50 per policy per month
                monthly_cost = 50.00
                
                services.append({
                    'service_id': 'traffic_flow',
                    'resource_id': policy['Id'],
                    'resource_name': policy['Name'],
                    'region': 'global',
                    'service_type': 'Networking',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'traffic_policy_id': policy['Id'],
                        'name': policy['Name'],
                        'type': policy.get('Type'),
                        'latest_version': policy.get('LatestTrafficPolicyVersion'),
                        'traffic_policy_count': policy.get('TrafficPolicyCount', 0)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering Route53 services: {str(e)}")
    
    return services

def get_route53_tags(client, resource_id):
    """Get tags for Route53 resource"""
    try:
        response = client.list_tags_for_resource(
            ResourceType='hostedzone' if 'hostedzone' in resource_id else 'healthcheck',
            ResourceId=resource_id.split('/')[-1]
        )
        return response.get('ResourceTagSet', {}).get('Tags', [])
    except:
        return []

def check_domain_privacy(client, domain_name):
    """Check if domain has privacy protection enabled"""
    try:
        detail = client.get_domain_detail(DomainName=domain_name)
        return detail.get('PrivacyProtection', False)
    except:
        return False