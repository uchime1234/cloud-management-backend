# discovery/cloudwatch_discovery.py
import boto3
from datetime import datetime, timedelta       
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

def discover_cloudwatch_services(creds, region):
    """Discover CloudWatch resources: alarms, dashboards, logs, metrics"""
    services = []
    try:
        # ========== CLOUDWATCH ALARMS ==========
        cloudwatch_client = boto3.client(
            'cloudwatch',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region
              config=Config(
            connect_timeout=30,
            read_timeout=30,
            retries={'max_attempts': 3}
        ),
        verify=False
        )
        
        alarms = cloudwatch_client.describe_alarms()
        all_alarms = alarms.get('MetricAlarms', []) + alarms.get('CompositeAlarms', [])
        
        for alarm in all_alarms:
            alarm_name = alarm['AlarmName']
            alarm_arn = alarm['AlarmArn']
            alarm_type = 'composite' if 'CompositeAlarm' in alarm else 'metric'
            
            # CloudWatch alarms: $0.10 per alarm per month
            monthly_cost = 0.10
            
            services.append({
                'service_id': 'cloudwatch_alarm',
                'resource_id': alarm_arn,
                'resource_name': alarm_name,
                'region': region,
                'service_type': 'Monitoring',
                'estimated_monthly_cost': monthly_cost,
                'details': {
                    'alarm_name': alarm_name,
                    'alarm_arn': alarm_arn,
                    'alarm_description': alarm.get('AlarmDescription'),
                    'alarm_type': alarm_type,
                    'state_value': alarm.get('StateValue'),
                    'state_reason': alarm.get('StateReason'),
                    'state_updated_timestamp': alarm.get('StateUpdatedTimestamp').isoformat() if alarm.get('StateUpdatedTimestamp') else None,
                    'actions_enabled': alarm.get('ActionsEnabled', False),
                    'ok_actions': alarm.get('OKActions', []),
                    'alarm_actions': alarm.get('AlarmActions', []),
                    'insufficient_data_actions': alarm.get('InsufficientDataActions', []),
                    'metric_name': alarm.get('MetricName'),
                    'namespace': alarm.get('Namespace'),
                    'statistic': alarm.get('Statistic'),
                    'period': alarm.get('Period'),
                    'evaluation_periods': alarm.get('EvaluationPeriods'),
                    'threshold': alarm.get('Threshold'),
                    'comparison_operator': alarm.get('ComparisonOperator'),
                    'datapoints_to_alarm': alarm.get('DatapointsToAlarm'),
                    'treat_missing_data': alarm.get('TreatMissingData'),
                    'tags': get_cloudwatch_alarm_tags(cloudwatch_client, alarm_arn)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== CLOUDWATCH DASHBOARDS ==========
        dashboards = cloudwatch_client.list_dashboards()
        for dashboard in dashboards.get('DashboardEntries', []):
            dashboard_name = dashboard['DashboardName']
            dashboard_arn = dashboard.get('DashboardArn')
            
            # First dashboard is free, additional dashboards $3 per month
            # Since we don't know which is first, assume cost
            monthly_cost = 3.00
            
            services.append({
                'service_id': 'cloudwatch_dashboard',
                'resource_id': dashboard_arn if dashboard_arn else dashboard_name,
                'resource_name': dashboard_name,
                'region': region,
                'service_type': 'Monitoring',
                'estimated_monthly_cost': monthly_cost,
                'details': {
                    'dashboard_name': dashboard_name,
                    'dashboard_arn': dashboard_arn,
                    'last_modified': dashboard.get('LastModified').isoformat() if dashboard.get('LastModified') else None,
                    'size': dashboard.get('Size'),
                    'widget_count': estimate_dashboard_widgets(cloudwatch_client, dashboard_name)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== CLOUDWATCH LOGS ==========
        logs_client = boto3.client(
            'logs',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region
        )
        
        # Log groups
        log_groups = logs_client.describe_log_groups()
        for log_group in log_groups.get('logGroups', []):
            log_group_name = log_group['logGroupName']
            log_group_arn = log_group.get('arn')
            stored_bytes = log_group.get('storedBytes', 0)
            stored_gb = stored_bytes / (1024 * 1024 * 1024)
            retention_days = log_group.get('retentionInDays', 'Never Expire')
            
            # CloudWatch Logs pricing: $0.50 per GB ingested, $0.03 per GB archived
            # Assume 1GB ingested per month for estimation
            estimated_ingested_gb = 1.0
            storage_gb = stored_gb * 0.03  # Storage cost
            
            # Calculate ingestion cost
            if retention_days == 'Never Expire' or retention_days > 0:
                monthly_cost = (estimated_ingested_gb * 0.50) + storage_gb
            else:
                monthly_cost = 0.00
            
            services.append({
                'service_id': 'cloudwatch_log_group',
                'resource_id': log_group_arn if log_group_arn else log_group_name,
                'resource_name': log_group_name.split('/')[-1],
                'region': region,
                'service_type': 'Monitoring',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'log_group_name': log_group_name,
                    'log_group_arn': log_group_arn,
                    'creation_time': datetime.fromtimestamp(log_group.get('creationTime', 0)/1000).isoformat() if log_group.get('creationTime') else None,
                    'retention_in_days': retention_days,
                    'metric_filter_count': log_group.get('metricFilterCount', 0),
                    'stored_bytes': stored_bytes,
                    'stored_gb': round(stored_gb, 2),
                    'kms_key_id': log_group.get('kmsKeyId'),
                    'data_protection_status': log_group.get('dataProtectionStatus', 'DISABLED'),
                    'tags': get_log_group_tags(logs_client, log_group_name)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== LOG STREAMS ==========
            try:
                log_streams = logs_client.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=5  # Only get recent streams
                )
                
                for stream in log_streams.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    
                    services.append({
                        'service_id': 'cloudwatch_log_stream',
                        'resource_id': f"{log_group_arn}:{stream_name}",
                        'resource_name': stream_name,
                        'region': region,
                        'service_type': 'Monitoring',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost included in log group
                        'details': {
                            'log_group_name': log_group_name,
                            'log_stream_name': stream_name,
                            'creation_time': datetime.fromtimestamp(stream.get('creationTime', 0)/1000).isoformat() if stream.get('creationTime') else None,
                            'first_event_timestamp': datetime.fromtimestamp(stream.get('firstEventTimestamp', 0)/1000).isoformat() if stream.get('firstEventTimestamp') else None,
                            'last_event_timestamp': datetime.fromtimestamp(stream.get('lastEventTimestamp', 0)/1000).isoformat() if stream.get('lastEventTimestamp') else None,
                            'last_ingestion_time': datetime.fromtimestamp(stream.get('lastIngestionTime', 0)/1000).isoformat() if stream.get('lastIngestionTime') else None,
                            'upload_sequence_token': stream.get('uploadSequenceToken'),
                            'arn': stream.get('arn'),
                            'stored_bytes': stream.get('storedBytes', 0)
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
            
            # ========== LOG METRIC FILTERS ==========
            try:
                metric_filters = logs_client.describe_metric_filters(logGroupName=log_group_name)
                for filter_data in metric_filters.get('metricFilters', []):
                    services.append({
                        'service_id': 'cloudwatch_log_metric_filter',
                        'resource_id': filter_data.get('filterName', f"{log_group_name}-filter"),
                        'resource_name': filter_data.get('filterName'),
                        'region': region,
                        'service_type': 'Monitoring',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # No separate charge
                        'details': {
                            'log_group_name': log_group_name,
                            'filter_name': filter_data.get('filterName'),
                            'filter_pattern': filter_data.get('filterPattern'),
                            'metric_transformations': filter_data.get('metricTransformations', []),
                            'creation_time': datetime.fromtimestamp(filter_data.get('creationTime', 0)/1000).isoformat() if filter_data.get('creationTime') else None
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== CLOUDWATCH INSIGHT RULES ==========
        try:
            insight_rules = cloudwatch_client.describe_insight_rules()
            for rule in insight_rules.get('InsightRules', []):
                rule_name = rule['Name']
                rule_state = rule.get('State')
                
                # $0.20 per insight rule per hour
                hourly_cost = 0.20
                monthly_cost = hourly_cost * 730
                
                services.append({
                    'service_id': 'cloudwatch_insight_rule',
                    'resource_id': rule.get('Arn', rule_name),
                    'resource_name': rule_name,
                    'region': region,
                    'service_type': 'Monitoring',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'name': rule_name,
                        'arn': rule.get('Arn'),
                        'state': rule_state,
                        'definition': rule.get('Definition', {}),
                        'tags': rule.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDWATCH SYNTHETICS ==========
        try:
            synthetics_client = boto3.client(
                'synthetics',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region
            )
            
            canaries = synthetics_client.describe_canaries()
            for canary in canaries.get('Canaries', []):
                canary_name = canary['Name']
                canary_arn = canary.get('Arn')
                runtime_version = canary.get('RuntimeVersion')
                schedule = canary.get('Schedule', {})
                
                # Synthetics canary pricing: $0.001 per canary run
                # Assume hourly runs: 24 * 30 = 720 runs per month
                runs_per_month = 720
                monthly_cost = runs_per_month * 0.001
                
                services.append({
                    'service_id': 'cloudwatch_synthetics_canary',
                    'resource_id': canary_arn,
                    'resource_name': canary_name,
                    'region': region,
                    'service_type': 'Monitoring',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'name': canary_name,
                        'arn': canary_arn,
                        'runtime_version': runtime_version,
                        'schedule': {
                            'expression': schedule.get('Expression'),
                            'duration_in_seconds': schedule.get('DurationInSeconds', 0)
                        },
                        'status': canary.get('Status', {}).get('State'),
                        'engine_arn': canary.get('EngineArn'),
                        'vpc_config': canary.get('VpcConfig', {}),
                        'timeline': {
                            'created': canary.get('Timeline', {}).get('Created').isoformat() if canary.get('Timeline', {}).get('Created') else None,
                            'last_modified': canary.get('Timeline', {}).get('LastModified').isoformat() if canary.get('Timeline', {}).get('LastModified') else None,
                            'last_started': canary.get('Timeline', {}).get('LastStarted').isoformat() if canary.get('Timeline', {}).get('LastStarted') else None,
                            'last_stopped': canary.get('Timeline', {}).get('LastStopped').isoformat() if canary.get('Timeline', {}).get('LastStopped') else None
                        },
                        'tags': canary.get('Tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDWATCH SERVICE LENS ==========
        try:
            service_lens = cloudwatch_client.list_service_lens_service_insight_visualizations()
            for insight in service_lens.get('ServiceInsightVisualizations', []):
                services.append({
                    'service_id': 'cloudwatch_service_lens',
                    'resource_id': insight.get('Arn'),
                    'resource_name': insight.get('Name'),
                    'region': region,
                    'service_type': 'Monitoring',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Included in CloudWatch
                    'details': {
                        'name': insight.get('Name'),
                        'arn': insight.get('Arn'),
                        'description': insight.get('Description'),
                        'visualization_type': insight.get('VisualizationType')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDWATCH CONTRIBUTOR INSIGHTS ==========
        try:
            contributor_rules = cloudwatch_client.describe_contributor_insights()
            for rule in contributor_rules.get('ContributorInsightRules', []):
                rule_name = rule['Name']
                rule_arn = rule.get('Arn')
                
                services.append({
                    'service_id': 'cloudwatch_contributor_insights',
                    'resource_id': rule_arn,
                    'resource_name': rule_name,
                    'region': region,
                    'service_type': 'Monitoring',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.30 per million events
                    'details': {
                        'name': rule_name,
                        'arn': rule_arn,
                        'rule_state': rule.get('RuleState'),
                        'rule_definition': rule.get('RuleDefinition', {}),
                        'tags': rule.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering CloudWatch services in {region}: {str(e)}")
    
    return services

def get_cloudwatch_alarm_tags(client, alarm_arn):
    """Get tags for CloudWatch alarm"""
    try:
        response = client.list_tags_for_resource(ResourceARN=alarm_arn)
        return response.get('Tags', [])
    except:
        return []

def get_log_group_tags(client, log_group_name):
    """Get tags for CloudWatch Log Group"""
    try:
        response = client.list_tags_log_group(logGroupName=log_group_name)
        return response.get('tags', {})
    except:
        return {}

def estimate_dashboard_widgets(client, dashboard_name):
    """Estimate number of widgets in dashboard"""
    try:
        dashboard = client.get_dashboard(DashboardName=dashboard_name)
        import json
        body = json.loads(dashboard.get('DashboardBody', '{}'))
        return len(body.get('widgets', []))
    except:
        return 0