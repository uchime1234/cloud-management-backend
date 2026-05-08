# discovery/stepfunctions_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_stepfunctions_services(creds, region):
    """Discover Step Functions state machines and activities"""
    services = []
    try:
        client = boto3.client(
            'stepfunctions',
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
        
        # ========== STANDARD STATE MACHINES ==========
        state_machines = client.list_state_machines()
        for sm in state_machines.get('stateMachines', []):
            sm_arn = sm['stateMachineArn']
            sm_name = sm['name']
            sm_type = sm.get('type', 'STANDARD')
            created_date = sm.get('creationDate')
            
            # Get state machine details
            try:
                details = client.describe_state_machine(stateMachineArn=sm_arn)
                definition = parse_json(details.get('definition', '{}'))
                role_arn = details.get('roleArn')
                logging_config = details.get('loggingConfiguration', {})
                tracing_config = details.get('tracingConfiguration', {})
                
                # Estimate cost
                if sm_type == 'STANDARD':
                    # $25 per million state transitions
                    monthly_cost = 25.00  # Assume 1M transitions
                    service_id = 'stepfunctions_standard'
                else:
                    # EXPRESS: $1 per million requests + $0.10 per GB
                    monthly_cost = 1.00 + 0.10  # Assume 1M requests + 1GB
                    service_id = 'stepfunctions_express'
                
                services.append({
                    'service_id': service_id,
                    'resource_id': sm_arn,
                    'resource_name': sm_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'state_machine_arn': sm_arn,
                        'name': sm_name,
                        'type': sm_type,
                        'status': details.get('status'),
                        'definition': definition,
                        'role_arn': role_arn,
                        'creation_date': created_date.isoformat() if created_date else None,
                        'logging_configuration': {
                            'level': logging_config.get('level'),
                            'include_execution_data': logging_config.get('includeExecutionData'),
                            'destinations': logging_config.get('destinations', [])
                        },
                        'tracing_configuration': {
                            'enabled': tracing_config.get('enabled', False)
                        },
                        'tags': get_stepfunctions_tags(client, sm_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== STATE MACHINE EXECUTIONS ==========
                try:
                    executions = client.list_executions(
                        stateMachineArn=sm_arn,
                        maxResults=10,
                        statusFilter='RUNNING'
                    )
                    for execution in executions.get('executions', []):
                        exec_arn = execution['executionArn']
                        exec_name = execution['name']
                        
                        services.append({
                            'service_id': 'stepfunctions_execution',
                            'resource_id': exec_arn,
                            'resource_name': exec_name,
                            'region': region,
                            'service_type': 'Application Integration',
                            'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost included in transitions
                            'details': {
                                'execution_arn': exec_arn,
                                'name': exec_name,
                                'state_machine_arn': sm_arn,
                                'status': execution.get('status'),
                                'start_date': execution.get('startDate').isoformat() if execution.get('startDate') else None,
                                'stop_date': execution.get('stopDate').isoformat() if execution.get('stopDate') else None,
                                'input': parse_json(execution.get('input')),
                                'output': parse_json(execution.get('output')) if execution.get('output') else None
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                except:
                    pass
                    
            except Exception as e:
                print(f"Error describing state machine {sm_arn}: {str(e)}")
        
        # ========== ACTIVITIES ==========
        try:
            activities = client.list_activities()
            for activity in activities.get('activities', []):
                activity_arn = activity['activityArn']
                activity_name = activity['name']
                created_date = activity.get('creationDate')
                
                # $25 per million state transitions
                monthly_cost = 25.00  # Assume 1M transitions
                
                services.append({
                    'service_id': 'stepfunctions_activity',
                    'resource_id': activity_arn,
                    'resource_name': activity_name,
                    'region': region,
                    'service_type': 'Application Integration',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'activity_arn': activity_arn,
                        'name': activity_name,
                        'creation_date': created_date.isoformat() if created_date else None,
                        'tags': get_stepfunctions_tags(client, activity_arn)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== MAP RUNS ==========
        for sm in state_machines.get('stateMachines', []):
            try:
                map_runs = client.list_map_runs(stateMachineArn=sm['stateMachineArn'])
                for map_run in map_runs.get('mapRuns', []):
                    map_run_arn = map_run['mapRunArn']
                    
                    services.append({
                        'service_id': 'stepfunctions_map_run',
                        'resource_id': map_run_arn,
                        'resource_name': map_run.get('executionArn', '').split(':')[-1],
                        'region': region,
                        'service_type': 'Application Integration',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost included in transitions
                        'details': {
                            'map_run_arn': map_run_arn,
                            'execution_arn': map_run.get('executionArn'),
                            'state_machine_arn': sm['stateMachineArn'],
                            'start_date': map_run.get('startDate').isoformat() if map_run.get('startDate') else None,
                            'stop_date': map_run.get('stopDate').isoformat() if map_run.get('stopDate') else None
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
    except Exception as e:
        print(f"Error discovering Step Functions services in {region}: {str(e)}")
    
    return services

def get_stepfunctions_tags(client, resource_arn):
    """Get tags for Step Functions resource"""
    try:
        response = client.list_tags_for_resource(resourceArn=resource_arn)
        return response.get('tags', [])
    except:
        return []