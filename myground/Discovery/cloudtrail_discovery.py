# discovery/cloudtrail_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

# Add this to the top of each discovery file (vpc_discovery.py, ec2_discovery.py, etc.)
import boto3
import urllib3
from botocore.config import Config

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_boto3_client(service, creds, region):
    """Create boto3 client with SSL verification disabled"""
    return boto3.client(
        service,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region,
        config=Config(
            connect_timeout=30,
            read_timeout=30,
            retries={'max_attempts': 3}
        ),
        verify=False  # Disable SSL verification
    )

def discover_cloudtrail_services(creds, region):
    """Discover CloudTrail trails, event data stores, insights, and lake resources"""
    services = []
    try:
        client = boto3.client(
            'cloudtrail',
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
        
        # ========== CLOUDTRAIL TRAILS ==========
        trails = client.describe_trails()
        for trail in trails.get('trailList', []):
            trail_name = trail['Name']
            trail_arn = trail['TrailARN']
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            is_org_trail = trail.get('IsOrganizationTrail', False)
            home_region = trail.get('HomeRegion', region)
            s3_bucket_name = trail.get('S3BucketName')
            s3_key_prefix = trail.get('S3KeyPrefix')
            sns_topic_name = trail.get('SnsTopicName')
            sns_topic_arn = trail.get('SnsTopicARN')
            cloud_watch_logs_log_group_arn = trail.get('CloudWatchLogsLogGroupArn')
            cloud_watch_logs_role_arn = trail.get('CloudWatchLogsRoleArn')
            kms_key_id = trail.get('KmsKeyId')
            has_custom_event_selectors = trail.get('HasCustomEventSelectors', False)
            has_insight_selectors = trail.get('HasInsightSelectors', False)
            is_logging = False
            latest_delivery_time = None
            latest_delivery_attempt = None
            latest_notification_attempt = None
            time_logging_started = None
            time_logging_stopped = None
            
            # Get trail status
            try:
                status = client.get_trail_status(Name=trail_arn)
                is_logging = status.get('IsLogging', False)
                latest_delivery_time = status.get('LatestDeliveryTime')
                latest_delivery_attempt = status.get('LatestDeliveryAttempt')
                latest_delivery_attempt_time = status.get('LatestDeliveryAttemptTime')
                latest_notification_attempt = status.get('LatestNotificationAttempt')
                latest_notification_attempt_time = status.get('LatestNotificationAttemptTime')
                time_logging_started = status.get('TimeLoggingStarted')
                time_logging_stopped = status.get('TimeLoggingStopped')
            except Exception as e:
                print(f"Error getting trail status for {trail_name}: {str(e)}")
            
            # Get event selectors
            event_selectors = []
            advanced_event_selectors = []
            try:
                selectors = client.get_event_selectors(TrailName=trail_arn)
                event_selectors = selectors.get('EventSelectors', [])
                advanced_event_selectors = selectors.get('AdvancedEventSelectors', [])
            except:
                pass
            
            # Get insight selectors
            insight_selectors = []
            try:
                insights = client.get_insight_selectors(TrailName=trail_arn)
                insight_selectors = insights.get('InsightSelectors', [])
            except:
                pass
            
            # CloudTrail pricing:
            # - Management events: $2.00 per 100,000 events
            # - Data events: $0.10 per 100,000 events
            # - Insights events: $0.35 per 100,000 events
            
            # Estimate monthly costs based on typical usage
            # Assume 500,000 management events, 2,000,000 data events, 100,000 insights events
            estimated_management_events = 500000
            estimated_data_events = 2000000
            estimated_insights_events = 100000 if has_insight_selectors else 0
            
            management_cost = (estimated_management_events / 100000) * 2.00
            data_cost = (estimated_data_events / 100000) * 0.10
            insights_cost = (estimated_insights_events / 100000) * 0.35 if has_insight_selectors else 0
            
            monthly_cost = management_cost + data_cost + insights_cost
            
            services.append({
                'service_id': 'cloudtrail_trail',
                'resource_id': trail_arn,
                'resource_name': trail_name,
                'region': home_region if not is_multi_region else 'global',
                'service_type': 'Security, Identity & Compliance',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'home_region': home_region,
                    'is_multi_region_trail': is_multi_region,
                    'is_organization_trail': is_org_trail,
                    's3_bucket_name': s3_bucket_name,
                    's3_key_prefix': s3_key_prefix,
                    'sns_topic_name': sns_topic_name,
                    'sns_topic_arn': sns_topic_arn,
                    'cloud_watch_logs_log_group_arn': cloud_watch_logs_log_group_arn,
                    'cloud_watch_logs_role_arn': cloud_watch_logs_role_arn,
                    'kms_key_id': kms_key_id,
                    'has_custom_event_selectors': has_custom_event_selectors,
                    'has_insight_selectors': has_insight_selectors,
                    'is_logging': is_logging,
                    'latest_delivery_time': latest_delivery_time.isoformat() if latest_delivery_time else None,
                    'latest_delivery_attempt': latest_delivery_attempt,
                    'latest_delivery_attempt_time': latest_delivery_attempt_time,
                    'latest_notification_attempt': latest_notification_attempt,
                    'latest_notification_attempt_time': latest_notification_attempt_time,
                    'time_logging_started': time_logging_started.isoformat() if time_logging_started else None,
                    'time_logging_stopped': time_logging_stopped.isoformat() if time_logging_stopped else None,
                    'event_selectors': event_selectors,
                    'advanced_event_selectors': advanced_event_selectors,
                    'insight_selectors': insight_selectors,
                    'tags': get_cloudtrail_tags(client, trail_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== CLOUDTRAIL DATA EVENTS ==========
            if has_custom_event_selectors and (event_selectors or advanced_event_selectors):
                # Count data event selectors
                data_event_count = 0
                for selector in event_selectors:
                    if selector.get('IncludeManagementEvents') is False:
                        data_resources = selector.get('DataResources', [])
                        data_event_count += len(data_resources)
                
                for selector in advanced_event_selectors:
                    if selector.get('Name', '').lower().find('data') >= 0 or any('Data' in str(f) for f in selector.get('FieldSelectors', [])):
                        data_event_count += 1
                
                services.append({
                    'service_id': 'cloudtrail_data_events',
                    'resource_id': f"{trail_arn}/data-events",
                    'resource_name': f"{trail_name} Data Events",
                    'region': home_region if not is_multi_region else 'global',
                    'service_type': 'Security, Identity & Compliance',
                    'estimated_monthly_cost': round(data_cost, 2),
                'count': 1,  # Already included in trail cost
                    'details': {
                        'trail_arn': trail_arn,
                        'trail_name': trail_name,
                        'event_selector_count': len(event_selectors),
                        'advanced_event_selector_count': len(advanced_event_selectors),
                        'data_resource_count': data_event_count,
                        'event_selectors': event_selectors,
                        'advanced_event_selectors': advanced_event_selectors
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            
            # ========== CLOUDTRAIL INSIGHTS ==========
            if has_insight_selectors and insight_selectors:
                services.append({
                    'service_id': 'cloudtrail_insights',
                    'resource_id': f"{trail_arn}/insights",
                    'resource_name': f"{trail_name} Insights",
                    'region': home_region if not is_multi_region else 'global',
                    'service_type': 'Security, Identity & Compliance',
                    'estimated_monthly_cost': round(insights_cost, 2),
                'count': 1,  # Already included in trail cost
                    'details': {
                        'trail_arn': trail_arn,
                        'trail_name': trail_name,
                        'insight_selectors': insight_selectors,
                        'insight_types': [i.get('InsightType') for i in insight_selectors if i.get('InsightType')],
                        'enabled': True
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
        # ========== CLOUDTRAIL LAKE (EVENT DATA STORES) ==========
        try:
            # List all event data stores
            event_data_stores = client.list_event_data_stores()
            for eds in event_data_stores.get('EventDataStores', []):
                eds_arn = eds['EventDataStoreArn']
                eds_name = eds.get('Name', eds_arn.split('/')[-1])
                eds_status = eds.get('Status', 'ENABLED')
                
                try:
                    # Get detailed information
                    eds_detail = client.get_event_data_store(EventDataStoreArn=eds_arn)
                    
                    # CloudTrail Lake pricing:
                    # - Ingestion: $2.50 per GB ingested
                    # - Storage: $0.50 per GB-month
                    # - Analysis: $0.00765 per GB scanned
                    
                    # Estimate costs
                    estimated_ingested_gb = 10  # Assume 10GB ingested per month
                    estimated_storage_gb = 50   # Assume 50GB stored
                    estimated_scanned_gb = 100   # Assume 100GB scanned for queries
                    
                    ingestion_cost = estimated_ingested_gb * 2.50
                    storage_cost = estimated_storage_gb * 0.50
                    analysis_cost = estimated_scanned_gb * 0.00765
                    
                    monthly_cost = ingestion_cost + storage_cost + analysis_cost
                    
                    # Get retention period
                    retention_period = eds_detail.get('RetentionPeriod', 2557)  # 7 years default
                    
                    # Get termination protection
                    termination_protection = eds_detail.get('TerminationProtectionEnabled', False)
                    
                    # Get multi-region enabled
                    multi_region_enabled = eds_detail.get('MultiRegionEnabled', False)
                    
                    # Get organization enabled
                    organization_enabled = eds_detail.get('OrganizationEnabled', False)
                    
                    # Get advanced event selectors
                    advanced_event_selectors = eds_detail.get('AdvancedEventSelectors', [])
                    
                    services.append({
                        'service_id': 'cloudtrail_lake',
                        'resource_id': eds_arn,
                        'resource_name': eds_name,
                        'region': region if not multi_region_enabled else 'global',
                        'service_type': 'Security, Identity & Compliance',
                        'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                        'details': {
                            'event_data_store_arn': eds_arn,
                            'name': eds_name,
                            'status': eds_status,
                            'retention_period_days': retention_period,
                            'termination_protection_enabled': termination_protection,
                            'multi_region_enabled': multi_region_enabled,
                            'organization_enabled': organization_enabled,
                            'created_timestamp': eds_detail.get('CreatedTimestamp').isoformat() if eds_detail.get('CreatedTimestamp') else None,
                            'updated_timestamp': eds_detail.get('UpdatedTimestamp').isoformat() if eds_detail.get('UpdatedTimestamp') else None,
                            'advanced_event_selectors': advanced_event_selectors,
                            'billing_mode': eds_detail.get('BillingMode', 'EXTENDABLE_RETENTION_PRICING'),
                            'partition_keys': eds_detail.get('PartitionKeys', []),
                            'kms_key_id': eds_detail.get('KmsKeyId'),
                            'tags': get_cloudtrail_event_data_store_tags(client, eds_arn)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
                    # ========== CLOUDTRAIL LAKE QUERIES ==========
                    try:
                        # List recent queries for this event data store
                        queries = client.list_queries(EventDataStore=eds_arn, MaxResults=20)
                        for query in queries.get('Queries', []):
                            query_id = query['QueryId']
                            query_status = query.get('QueryStatus', 'UNKNOWN')
                            creation_time = query.get('CreationTime')
                            
                            # Get detailed query information
                            try:
                                query_detail = client.describe_query(EventDataStore=eds_arn, QueryId=query_id)
                                query_string = query_detail.get('QueryString', '')
                                query_scan_status = query_detail.get('QueryStatus', {})
                                query_statistics = query_detail.get('QueryStatistics', {})
                            except:
                                query_string = ''
                                query_scan_status = {}
                                query_statistics = {}
                            
                            services.append({
                                'service_id': 'cloudtrail_lake_query',
                                'resource_id': query_id,
                                'resource_name': f"Query {query_id[-8:]}",
                                'region': region,
                                'service_type': 'Security, Identity & Compliance',
                                'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost per GB scanned
                                'details': {
                                    'event_data_store_arn': eds_arn,
                                    'event_data_store_name': eds_name,
                                    'query_id': query_id,
                                    'query_status': query_status,
                                    'creation_time': creation_time.isoformat() if creation_time else None,
                                    'query_string': query_string[:200] + '...' if len(query_string) > 200 else query_string,
                                    'query_string_preview': query_string[:50] + '...' if query_string else None,
                                    'scan_status': query_scan_status,
                                    'statistics': query_statistics,
                                    'delivery_s3_uri': query_detail.get('DeliveryS3Uri') if 'query_detail' in locals() else None
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    except Exception as e:
                        print(f"Error listing queries for event data store {eds_name}: {str(e)}")
                        
                except Exception as e:
                    print(f"Error describing event data store {eds_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing event data stores in {region}: {str(e)}")
        
        # ========== CLOUDTRAIL CHANNELS ==========
        try:
            channels = client.list_channels(MaxResults=50)
            for channel in channels.get('Channels', []):
                channel_arn = channel['ChannelArn']
                channel_name = channel.get('Name', channel_arn.split('/')[-1])
                channel_source = channel.get('Source', 'UNKNOWN')
                channel_destination = channel.get('Destination', 'UNKNOWN')
                
                try:
                    # Get detailed channel information
                    channel_detail = client.get_channel(Channel=channel_arn)
                    
                    # Get ingestions
                    ingestions = channel_detail.get('Ingestions', [])
                    
                    services.append({
                        'service_id': 'cloudtrail_channel',
                        'resource_id': channel_arn,
                        'resource_name': channel_name,
                        'region': region,
                        'service_type': 'Security, Identity & Compliance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'channel_arn': channel_arn,
                            'name': channel_name,
                            'source': channel_source,
                            'source_type': channel_detail.get('SourceConfig', {}).get('SourceType') if channel_detail.get('SourceConfig') else None,
                            'destination': channel_destination,
                            'destination_type': channel_detail.get('DestinationConfig', {}).get('DestinationType') if channel_detail.get('DestinationConfig') else None,
                            'destination_location': channel_detail.get('DestinationConfig', {}).get('Location') if channel_detail.get('DestinationConfig') else None,
                            'ingestion_status': channel_detail.get('IngestionStatus'),
                            'ingestion_count': len(ingestions),
                            'ingestions': ingestions[:5] if ingestions else [],  # Limit to 5
                            'tags': get_cloudtrail_channel_tags(client, channel_arn)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                except Exception as e:
                    print(f"Error describing channel {channel_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing channels in {region}: {str(e)}")
        
        # ========== CLOUDTRAIL IMPORT TRACES ==========
        try:
            imports = client.list_imports(MaxResults=50)
            for import_summary in imports.get('Imports', []):
                import_id = import_summary['ImportId']
                import_status = import_summary.get('ImportStatus', 'UNKNOWN')
                created_timestamp = import_summary.get('CreatedTimestamp')
                
                try:
                    # Get detailed import information
                    import_detail = client.get_import(ImportId=import_id)
                    
                    # Calculate import size and cost
                    destinations = import_detail.get('Destinations', [])
                    start_event_time = import_detail.get('StartEventTime')
                    end_event_time = import_detail.get('EndEventTime')
                    import_source = import_detail.get('ImportSource', {})
                    
                    services.append({
                        'service_id': 'cloudtrail_import',
                        'resource_id': import_id,
                        'resource_name': f"Import {import_id[-8:]}",
                        'region': region,
                        'service_type': 'Security, Identity & Compliance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # $2.50 per GB imported
                        'details': {
                            'import_id': import_id,
                            'import_status': import_status,
                            'created_timestamp': created_timestamp.isoformat() if created_timestamp else None,
                            'updated_timestamp': import_summary.get('UpdatedTimestamp').isoformat() if import_summary.get('UpdatedTimestamp') else None,
                            'destinations': destinations,
                            'start_event_time': start_event_time.isoformat() if start_event_time else None,
                            'end_event_time': end_event_time.isoformat() if end_event_time else None,
                            'import_source_type': import_source.get('SourceType') if import_source else None,
                            'import_source_location': import_source.get('Location') if import_source else None,
                            'import_statistics': import_detail.get('ImportStatistics', {}),
                            'completed': import_detail.get('Completed', False)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                except Exception as e:
                    print(f"Error describing import {import_id}: {str(e)}")
        except Exception as e:
            print(f"Error listing imports in {region}: {str(e)}")
        
        # ========== CLOUDTRAIL DASHBOARDS ==========
        try:
            dashboards = client.list_dashboards(MaxResults=50)
            for dashboard in dashboards.get('Dashboards', []):
                dashboard_arn = dashboard['DashboardArn']
                dashboard_name = dashboard.get('Name', dashboard_arn.split('/')[-1])
                dashboard_type = dashboard.get('Type', 'CUSTOM')
                dashboard_status = dashboard.get('Status', 'ACTIVE')
                created_timestamp = dashboard.get('CreatedTimestamp')
                
                services.append({
                    'service_id': 'cloudtrail_dashboard',
                    'resource_id': dashboard_arn,
                    'resource_name': dashboard_name,
                    'region': region,
                    'service_type': 'Security, Identity & Compliance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Free
                    'details': {
                        'dashboard_arn': dashboard_arn,
                        'name': dashboard_name,
                        'type': dashboard_type,
                        'status': dashboard_status,
                        'created_timestamp': created_timestamp.isoformat() if created_timestamp else None,
                        'updated_timestamp': dashboard.get('UpdatedTimestamp').isoformat() if dashboard.get('UpdatedTimestamp') else None,
                        'widgets': dashboard.get('Widgets', [])[:10],  # Limit to 10
                        'tags': get_cloudtrail_dashboard_tags(client, dashboard_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except Exception as e:
            print(f"Error listing dashboards in {region}: {str(e)}")
        
        # ========== CLOUDTRAIL SERVICE LINKED CHANNELS ==========
        try:
            # These are automatically created channels for AWS services
            service_linked_channels = client.list_channels(MaxResults=100)
            for channel in service_linked_channels.get('Channels', []):
                if 'AWSService' in str(channel.get('Source')) or 'aws-service' in str(channel.get('Name')):
                    channel_arn = channel['ChannelArn']
                    channel_name = channel.get('Name', channel_arn.split('/')[-1])
                    
                    services.append({
                        'service_id': 'cloudtrail_service_linked_channel',
                        'resource_id': channel_arn,
                        'resource_name': channel_name,
                        'region': region,
                        'service_type': 'Security, Identity & Compliance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'channel_arn': channel_arn,
                            'name': channel_name,
                            'source': channel.get('Source'),
                            'destination': channel.get('Destination'),
                            'service_linked': True
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        except:
            pass
        
        # ========== CLOUDTRAIL DELEGATED ADMINISTRATORS ==========
        try:
            # Check if this account is a delegated administrator
            if is_management_account(client):
                delegated_admins = client.list_delegated_administrators()
                for admin in delegated_admins.get('DelegatedAdministrators', []):
                    admin_account_id = admin['AccountId']
                    
                    services.append({
                        'service_id': 'cloudtrail_delegated_admin',
                        'resource_id': admin_account_id,
                        'resource_name': f"Delegated Admin {admin_account_id}",
                        'region': 'global',
                        'service_type': 'Security, Identity & Compliance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'account_id': admin_account_id,
                            'delegation_time': admin.get('DelegationTime').isoformat() if admin.get('DelegationTime') else None,
                            'service_principal': admin.get('ServicePrincipal', 'cloudtrail.amazonaws.com')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
        except:
            pass
        
        # ========== CLOUDTRAIL PUBLIC KEYS ==========
        try:
            # For event data store encryption verification
            public_keys = client.list_public_keys()
            for public_key in public_keys.get('PublicKeyList', []):
                key_id = public_key.get('Fingerprint', public_key.get('Value', '')[:20])
                
                services.append({
                    'service_id': 'cloudtrail_public_key',
                    'resource_id': public_key.get('Fingerprint', 'unknown'),
                    'resource_name': f"Public Key {key_id}",
                    'region': region,
                    'service_type': 'Security, Identity & Compliance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'fingerprint': public_key.get('Fingerprint'),
                        'validity_start_time': public_key.get('ValidityStartTime').isoformat() if public_key.get('ValidityStartTime') else None,
                        'validity_end_time': public_key.get('ValidityEndTime').isoformat() if public_key.get('ValidityEndTime') else None,
                        'value_preview': str(public_key.get('Value', ''))[:50] + '...' if public_key.get('Value') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDTRAIL TAGS FOR ALL RESOURCES ==========
        # This is handled within each resource's tags method
        
    except Exception as e:
        print(f"Error discovering CloudTrail services in {region}: {str(e)}")
    
    return services

def get_cloudtrail_tags(client, trail_arn):
    """Get tags for CloudTrail trail"""
    try:
        response = client.list_tags(ResourceIdList=[trail_arn])
        if response.get('ResourceTagList'):
            return response['ResourceTagList'][0].get('TagsList', [])
        return []
    except Exception as e:
        print(f"Error getting CloudTrail tags: {str(e)}")
        return []

def get_cloudtrail_event_data_store_tags(client, eds_arn):
    """Get tags for CloudTrail Lake event data store"""
    try:
        response = client.list_tags(ResourceIdList=[eds_arn])
        if response.get('ResourceTagList'):
            return response['ResourceTagList'][0].get('TagsList', [])
        return []
    except Exception as e:
        print(f"Error getting event data store tags: {str(e)}")
        return []

def get_cloudtrail_channel_tags(client, channel_arn):
    """Get tags for CloudTrail channel"""
    try:
        response = client.list_tags(ResourceIdList=[channel_arn])
        if response.get('ResourceTagList'):
            return response['ResourceTagList'][0].get('TagsList', [])
        return []
    except Exception as e:
        print(f"Error getting channel tags: {str(e)}")
        return []

def get_cloudtrail_dashboard_tags(client, dashboard_arn):
    """Get tags for CloudTrail dashboard"""
    try:
        response = client.list_tags(ResourceIdList=[dashboard_arn])
        if response.get('ResourceTagList'):
            return response['ResourceTagList'][0].get('TagsList', [])
        return []
    except Exception as e:
        print(f"Error getting dashboard tags: {str(e)}")
        return []

def is_management_account(client):
    """Check if current account is the management account"""
    try:
        # Try to call an organization API - if it succeeds and we can see trails,
        # we might be the management account
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        # Simple heuristic - check if there are organization trails
        trails = client.describe_trails()
        for trail in trails.get('trailList', []):
            if trail.get('IsOrganizationTrail', False):
                return True
        return False
    except:
        return False

def calculate_retention_period_days(retention_period):
    """Convert retention period to human-readable format"""
    if retention_period == 2557:
        return "7 years"
    elif retention_period == 365:
        return "1 year"
    elif retention_period == 730:
        return "2 years"
    elif retention_period == 1095:
        return "3 years"
    elif retention_period == 1825:
        return "5 years"
    else:
        return f"{retention_period} days"