# discovery/cloudfront_discovery.py
import boto3
import urllib3
from datetime import datetime, timezone
from botocore.config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def discover_cloudfront_distributions(creds, region='us-east-1'):
    """Discover CloudFront distributions (global service)"""
    services = []
    try:
        client = boto3.client(
            'cloudfront',
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

        # ========== CLOUDFRONT DISTRIBUTIONS ==========
        distributions = client.list_distributions()
        if 'DistributionList' in distributions and 'Items' in distributions['DistributionList']:
            for dist in distributions['DistributionList']['Items']:
                dist_id = dist['Id']
                domain_name = dist['DomainName']
                enabled = dist.get('Enabled', False)
                status = dist.get('Status')

                services.append({
                    'service_id': 'distribution',
                    'resource_id': dist['ARN'],
                    'resource_name': dist_id,
                    'region': 'global',
                    'service_type': 'Networking',
                    'estimated_monthly_cost': 0.00,
                    'count': 1,
                    'details': {
                        'distribution_id': dist_id,
                        'arn': dist['ARN'],
                        'domain_name': domain_name,
                        'status': status,
                        'enabled': enabled,
                        'aliases': dist.get('Aliases', {}).get('Items', []),
                        'price_class': dist.get('PriceClass'),
                        'web_acl_id': dist.get('WebACLId'),
                        'http_version': dist.get('HttpVersion'),
                        'is_ipv6_enabled': dist.get('IsIPV6Enabled', False),
                        'comment': dist.get('Comment'),
                        'last_modified_time': dist.get('LastModifiedTime').isoformat() if dist.get('LastModifiedTime') else None,
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })

                # Origin Shield
                if dist.get('OriginShield', {}).get('Enabled', False):
                    services.append({
                        'service_id': 'origin_shield',
                        'resource_id': f"{dist['ARN']}/origin-shield",
                        'resource_name': f"{dist_id} Origin Shield",
                        'region': 'global',
                        'service_type': 'Networking',
                        'estimated_monthly_cost': 0.00,
                        'count': 1,
                        'details': {
                            'distribution_id': dist_id,
                            'enabled': True,
                            'origin_shield_region': dist['OriginShield'].get('OriginShieldRegion')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })

        # ========== CLOUDFRONT FUNCTIONS ==========
        try:
            functions = client.list_functions()
            for function in functions.get('FunctionList', {}).get('Items', []):
                services.append({
                    'service_id': 'cloudfront_functions',
                    'resource_id': function['FunctionMetadata']['FunctionARN'],
                    'resource_name': function['Name'],
                    'region': 'global',
                    'service_type': 'Compute',
                    'estimated_monthly_cost': 0.00,
                    'count': 1,
                    'details': {
                        'function_name': function['Name'],
                        'function_arn': function['FunctionMetadata']['FunctionARN'],
                        'status': function['FunctionMetadata'].get('Status'),
                        'stage': function.get('Stage'),
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except Exception:
            pass

        # ========== CLOUDFRONT ORIGIN ACCESS CONTROLS ==========
        try:
            oacs = client.list_origin_access_controls()
            for oac in oacs.get('OriginAccessControlList', {}).get('Items', []):
                services.append({
                    'service_id': 'origin_access_control',
                    'resource_id': oac['Id'],
                    'resource_name': oac.get('Name'),
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                    'count': 1,
                    'details': {
                        'oac_id': oac['Id'],
                        'name': oac.get('Name'),
                        'description': oac.get('Description'),
                        'signing_protocol': oac.get('SigningProtocol'),
                        'signing_behavior': oac.get('SigningBehavior'),
                        'origin_access_control_origin_type': oac.get('OriginAccessControlOriginType')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except Exception:
            pass

        # ========== CLOUDFRONT PUBLIC KEYS ==========
        try:
            public_keys = client.list_public_keys()
            for public_key in public_keys.get('PublicKeyList', {}).get('Items', []):
                services.append({
                    'service_id': 'public_key',
                    'resource_id': public_key['Id'],
                    'resource_name': public_key.get('Name'),
                    'region': 'global',
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                    'count': 1,
                    'details': {
                        'public_key_id': public_key['Id'],
                        'name': public_key.get('Name'),
                        'created_time': public_key.get('CreatedTime').isoformat() if public_key.get('CreatedTime') else None,
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except Exception:
            pass

    except Exception as e:
        print(f"Error discovering CloudFront distributions: {str(e)}")

    return services