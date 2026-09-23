# discovery/route53_discovery.py
import boto3
import urllib3
from datetime import datetime, timezone
from botocore.config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def discover_route53_services(creds, region='us-east-1'):
    """Discover Route53 hosted zones, health checks, and related services (global)"""
    services = []
    try:
        client = boto3.client(
            'route53',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name='us-east-1',
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

            monthly_cost = 0.50
            service_id = 'hosted_zone_private' if private_zone else 'hosted_zone'

            try:
                record_sets = client.list_resource_record_sets(HostedZoneId=zone_id)
                record_count = len(record_sets.get('ResourceRecordSets', []))
            except Exception:
                record_count = 0

            services.append({
                'service_id': service_id,
                'resource_id': zone['Id'],
                'resource_name': zone_name.rstrip('.'),
                'region': 'global',
                'service_type': 'Networking',
                'estimated_monthly_cost': monthly_cost,
                'count': 1,
                'details': {
                    'hosted_zone_id': zone_id,
                    'name': zone_name,
                    'private_zone': private_zone,
                    'record_count': record_count,
                    'comment': zone.get('Config', {}).get('Comment'),
                    'linked_service': zone.get('LinkedService'),
                    'resource_record_set_count': zone.get('ResourceRecordSetCount', 0),
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })

        # ========== HEALTH CHECKS ==========
        health_checks = client.list_health_checks()
        for health_check in health_checks.get('HealthChecks', []):
            health_check_id = health_check['Id']
            hc_config = health_check.get('HealthCheckConfig', {})

            hc_type = hc_config.get('Type', 'HTTP')
            monthly_cost = 0.50
            if hc_type == 'HTTPS' and hc_config.get('EnableSNI', False):
                monthly_cost = 1.00
            elif hc_config.get('RequestInterval', 30) == 10:
                monthly_cost = 2.00

            service_id = 'health_check_enhanced' if monthly_cost > 0.50 else 'health_check'

            services.append({
                'service_id': service_id,
                'resource_id': health_check['Id'],
                'resource_name': hc_config.get('FullyQualifiedDomainName', health_check_id),
                'region': 'global',
                'service_type': 'Networking',
                'estimated_monthly_cost': monthly_cost,
                'count': 1,
                'details': {
                    'health_check_id': health_check_id,
                    'type': hc_config.get('Type'),
                    'domain_name': hc_config.get('FullyQualifiedDomainName'),
                    'port': hc_config.get('Port', 80),
                    'resource_path': hc_config.get('ResourcePath'),
                    'request_interval': hc_config.get('RequestInterval', 30),
                    'failure_threshold': hc_config.get('FailureThreshold', 3),
                    'measure_latency': hc_config.get('MeasureLatency', False),
                    'inverted': hc_config.get('Inverted', False),
                    'disabled': hc_config.get('Disabled', False),
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })

        # ========== RESOLVER ENDPOINTS (best-effort) ==========
        try:
            route53resolver = boto3.client(
                'route53resolver',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name='us-east-1'
            )

            endpoints = route53resolver.list_resolver_endpoints()
            for endpoint in endpoints.get('ResolverEndpoints', []):
                direction = endpoint.get('Direction', 'INBOUND')
                monthly_cost = 0.125 * 730

                services.append({
                    'service_id': f"resolver_{direction.lower()}_endpoint",
                    'resource_id': endpoint['Arn'],
                    'resource_name': endpoint['Name'],
                    'region': 'global',
                    'service_type': 'Networking',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                    'count': 1,
                    'details': {
                        'resolver_endpoint_id': endpoint['Id'],
                        'name': endpoint.get('Name'),
                        'direction': direction,
                        'ip_address_count': endpoint.get('IpAddressCount', 0),
                        'host_vpc_id': endpoint.get('HostVPCId'),
                        'status': endpoint.get('Status'),
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except Exception:
            pass

    except Exception as e:
        print(f"Error discovering Route53 services: {str(e)}")

    return services