# discovery/guardduty_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_guardduty_services(creds, region):
    """Discover GuardDuty detectors, findings, and threat detection configurations"""
    services = []
    try:
        client = boto3.client(
            'guardduty',
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
        
        # ========== GUARDDUTY DETECTORS ==========
        detectors = client.list_detectors()
        for detector_id in detectors.get('DetectorIds', []):
            try:
                detector = client.get_detector(DetectorId=detector_id)
                status = detector.get('Status', 'ENABLED')
                finding_publishing_frequency = detector.get('FindingPublishingFrequency', 'SIX_HOURS')
                created_at = detector.get('CreatedAt')
                service_role = detector.get('ServiceRole')
                
                # GuardDuty pricing: $4 per million EC2 events, $0.20 per million S3 events
                # Estimate based on typical usage
                estimated_ec2_events = 500000  # 500k EC2 events
                estimated_s3_events = 1000000  # 1M S3 events
                estimated_k8s_events = 200000   # 200k K8s events
                
                monthly_cost = (
                    (estimated_ec2_events / 1000000) * 4.00 +
                    (estimated_s3_events / 1000000) * 0.20 +
                    (estimated_k8s_events / 1000000) * 0.20
                )
                
                services.append({
                    'service_id': 'guardduty_detector',
                    'resource_id': detector_id,
                    'resource_name': f"GuardDuty Detector {region}",
                    'region': region,
                    'service_type': 'Security',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'detector_id': detector_id,
                        'status': status,
                        'finding_publishing_frequency': finding_publishing_frequency,
                        'created_at': created_at,
                        'service_role': service_role,
                        'features': detector.get('Features', []),
                        'tags': get_guardduty_tags(client, detector_id)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== GUARDDUTY FINDINGS ==========
                findings = client.list_findings(DetectorId=detector_id, MaxResults=100)
                finding_ids = findings.get('FindingIds', [])
                
                if finding_ids:
                    finding_details = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:10])  # Limit to 10
                    
                    for finding in finding_details.get('Findings', []):
                        services.append({
                            'service_id': 'guardduty_finding',
                            'resource_id': finding['Id'],
                            'resource_name': finding.get('Title', finding['Id']),
                            'region': region,
                            'service_type': 'Security',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # No cost for findings
                            'details': {
                                'finding_id': finding['Id'],
                                'account_id': finding.get('AccountId'),
                                'region': finding.get('Region'),
                                'severity': finding.get('Severity'),
                                'type': finding.get('Type'),
                                'title': finding.get('Title'),
                                'description': finding.get('Description'),
                                'created_at': finding.get('CreatedAt'),
                                'updated_at': finding.get('UpdatedAt'),
                                'resource': finding.get('Resource', {}),
                                'service': finding.get('Service', {})
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                
                # ========== GUARDDUTY IPSETS ==========
                ip_sets = client.list_ip_sets(DetectorId=detector_id)
                for ip_set_id in ip_sets.get('IpSetIds', []):
                    try:
                        ip_set = client.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
                        
                        services.append({
                            'service_id': 'guardduty_ipset',
                            'resource_id': ip_set_id,
                            'resource_name': ip_set.get('Name'),
                            'region': region,
                            'service_type': 'Security',
                            'estimated_monthly_cost': 0.00,
                'count': 1,
                            'details': {
                                'ip_set_id': ip_set_id,
                                'name': ip_set.get('Name'),
                                'format': ip_set.get('Format'),
                                'location': ip_set.get('Location'),
                                'status': ip_set.get('Status'),
                                'tags': ip_set.get('Tags', [])
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                    except:
                        pass
                
                # ========== GUARDDUTY THREAT INTELLIGENCE SETS ==========
                threat_sets = client.list_threat_intel_sets(DetectorId=detector_id)
                for threat_set_id in threat_sets.get('ThreatIntelSetIds', []):
                    try:
                        threat_set = client.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=threat_set_id)
                        
                        services.append({
                            'service_id': 'guardduty_threatintel',
                            'resource_id': threat_set_id,
                            'resource_name': threat_set.get('Name'),
                            'region': region,
                            'service_type': 'Security',
                            'estimated_monthly_cost': 0.00,
                'count': 1,
                            'details': {
                                'threat_intel_set_id': threat_set_id,
                                'name': threat_set.get('Name'),
                                'format': threat_set.get('Format'),
                                'location': threat_set.get('Location'),
                                'status': threat_set.get('Status'),
                                'tags': threat_set.get('Tags', [])
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                    except:
                        pass
                
                # ========== GUARDDUTY MALWARE PROTECTION ==========
                try:
                    malware = client.get_malware_protection_plan(DetectorId=detector_id)
                    if malware:
                        services.append({
                            'service_id': 'guardduty_malware',
                            'resource_id': f"{detector_id}/malware",
                            'resource_name': "Malware Protection",
                            'region': region,
                            'service_type': 'Security',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.15 per GB scanned
                            'details': {
                                'detector_id': detector_id,
                                'protected_resource': malware.get('ProtectedResource', {}),
                                'actions': malware.get('Actions', {}),
                                'status': malware.get('Status'),
                                'created_at': malware.get('CreatedAt'),
                                'updated_at': malware.get('UpdatedAt')
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
                
                # ========== GUARDDUTY MEMBERS ==========
                members = client.list_members(DetectorId=detector_id)
                for member in members.get('Members', []):
                    services.append({
                        'service_id': 'guardduty_member',
                        'resource_id': member['AccountId'],
                        'resource_name': member.get('Email', member['AccountId']),
                        'region': region,
                        'service_type': 'Security',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Costs per account
                        'details': {
                            'account_id': member['AccountId'],
                            'detector_id': member.get('DetectorId'),
                            'email': member.get('Email'),
                            'relationship_status': member.get('RelationshipStatus'),
                            'invited_at': member.get('InvitedAt'),
                            'updated_at': member.get('UpdatedAt'),
                            'administrator_id': member.get('AdministratorId')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
            except Exception as e:
                print(f"Error describing GuardDuty detector {detector_id}: {str(e)}")
        
        # ========== GUARDDUTY ADMINISTRATOR ACCOUNT ==========
        try:
            admin = client.list_organization_admin_accounts()
            for admin_account in admin.get('AdminAccounts', []):
                services.append({
                    'service_id': 'guardduty_admin',
                    'resource_id': admin_account['AdminAccountId'],
                    'resource_name': f"GuardDuty Admin {admin_account['AdminAccountId']}",
                    'region': region,
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'admin_account_id': admin_account['AdminAccountId'],
                        'status': admin_account.get('AdminStatus')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering GuardDuty services in {region}: {str(e)}")
    
    return services

def get_guardduty_tags(client, detector_id):
    """Get tags for GuardDuty detector"""
    try:
        response = client.list_tags_for_resource(ResourceArn=f"arn:aws:guardduty:{client.meta.region_name}:{client.meta.region_name}:detector/{detector_id}")
        return response.get('Tags', {})
    except:
        return {}