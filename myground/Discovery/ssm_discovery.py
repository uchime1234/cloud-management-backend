# discovery/ssm_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_ssm_services(creds, region):
    """Discover Systems Manager resources: parameters, documents, inventory, patches, sessions"""
    services = []
    try:
        client = boto3.client(
            'ssm',
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
        
        # ========== SSM PARAMETERS ==========
        parameters = client.describe_parameters(MaxResults=50)
        for param in parameters.get('Parameters', []):
            param_name = param['Name']
            param_type = param['Type']
            param_version = param.get('Version', 1)
            last_modified = param.get('LastModifiedDate')
            
            # Parameter pricing
            # Standard: free, Advanced: $0.05 per month
            if param.get('Policies') or param_type == 'SecureString' and param.get('KeyId'):
                # Check if it's an advanced parameter
                is_advanced = any(p.get('PolicyType') == 'Expiration' for p in param.get('Policies', []))
                
                if is_advanced:
                    service_id = 'ssm_parameter_advanced'
                    monthly_cost = 0.05
                else:
                    service_id = 'ssm_parameter_secure'
                    monthly_cost = 0.00
            else:
                service_id = 'ssm_parameter_standard'
                monthly_cost = 0.00
            
            services.append({
                'service_id': service_id,
                'resource_id': param.get('ARN', param_name),
                'resource_name': param_name.split('/')[-1],
                'region': region,
                'service_type': 'Management & Governance',
                'estimated_monthly_cost': monthly_cost,
                'details': {
                    'name': param_name,
                    'arn': param.get('ARN'),
                    'type': param_type,
                    'version': param_version,
                    'last_modified_date': last_modified.isoformat() if last_modified else None,
                    'last_modified_user': param.get('LastModifiedUser'),
                    'description': param.get('Description'),
                    'tier': param.get('Tier', 'Standard'),
                    'policies': param.get('Policies', []),
                    'data_type': param.get('DataType', 'text'),
                    'key_id': param.get('KeyId') if param_type == 'SecureString' else None,
                    'tags': get_ssm_parameter_tags(client, param_name)
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== SSM DOCUMENTS ==========
        documents = client.list_documents(MaxResults=50)
        for doc in documents.get('DocumentIdentifiers', []):
            doc_name = doc['Name']
            doc_owner = doc.get('Owner', 'Amazon')
            doc_version = doc.get('DocumentVersion', '1')
            
            # Only track custom documents (not owned by AWS)
            if doc_owner != 'Amazon':
                try:
                    doc_detail = client.describe_document(Name=doc_name)
                    doc_info = doc_detail.get('Document', {})
                    
                    services.append({
                        'service_id': 'ssm_document',
                        'resource_id': doc_info.get('Arn', doc_name),
                        'resource_name': doc_name,
                        'region': region,
                        'service_type': 'Management & Governance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,  # Free
                        'details': {
                            'name': doc_name,
                            'arn': doc_info.get('Arn'),
                            'owner': doc_owner,
                            'version': doc_version,
                            'document_type': doc_info.get('DocumentType'),
                            'document_format': doc_info.get('DocumentFormat'),
                            'schema_version': doc_info.get('SchemaVersion'),
                            'description': doc_info.get('Description'),
                            'platform_types': doc_info.get('PlatformTypes', []),
                            'target_type': doc_info.get('TargetType'),
                            'tags': doc.get('Tags', []),
                            'created_date': doc_info.get('CreatedDate').isoformat() if doc_info.get('CreatedDate') else None,
                            'status': doc_info.get('Status'),
                            'document_hash': doc_info.get('DocumentHash'),
                            'latest_version': doc_detail.get('DocumentVersion'),
                            'default_version': doc_detail.get('DefaultVersion')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                except Exception as e:
                    print(f"Error describing SSM document {doc_name}: {str(e)}")
        
        # ========== SSM MANAGED INSTANCES ==========
        instances = client.describe_instance_information()
        for instance in instances.get('InstanceInformationList', []):
            instance_id = instance['InstanceId']
            ping_status = instance.get('PingStatus', 'Online')
            platform_type = instance.get('PlatformType', 'Linux')
            platform_name = instance.get('PlatformName', 'Unknown')
            platform_version = instance.get('PlatformVersion', 'Unknown')
            agent_version = instance.get('AgentVersion', 'Unknown')
            is_on_prem = instance_id.startswith('mi-')
            
            # On-prem instances: $0.008 per hour
            if is_on_prem:
                monthly_cost = 0.008 * 730  # ~$5.84 per month
                service_id = 'ssm_on_prem_instance'
            else:
                monthly_cost = 0.00  # EC2 instances are free
                service_id = 'ssm_managed_instance'
            
            services.append({
                'service_id': service_id,
                'resource_id': instance.get('InstanceArn', instance_id),
                'resource_name': instance_id,
                'region': region,
                'service_type': 'Management & Governance',
                'estimated_monthly_cost': round(monthly_cost, 2) if monthly_cost > 0 else 0.00,
                'details': {
                    'instance_id': instance_id,
                    'instance_arn': instance.get('InstanceArn'),
                    'ping_status': ping_status,
                    'last_ping_date_time': instance.get('LastPingDateTime').isoformat() if instance.get('LastPingDateTime') else None,
                    'agent_version': agent_version,
                    'platform_type': platform_type,
                    'platform_name': platform_name,
                    'platform_version': platform_version,
                    'resource_type': instance.get('ResourceType'),
                    'ip_address': instance.get('IPAddress'),
                    'computer_name': instance.get('ComputerName'),
                    'association_status': instance.get('AssociationStatus'),
                    'last_association_execution_date': instance.get('LastAssociationExecutionDate').isoformat() if instance.get('LastAssociationExecutionDate') else None,
                    'last_successful_association_execution_date': instance.get('LastSuccessfulAssociationExecutionDate').isoformat() if instance.get('LastSuccessfulAssociationExecutionDate') else None,
                    'is_on_premises': is_on_prem,
                    'activation_id': instance.get('ActivationId'),
                    'iam_role': instance.get('IamRole'),
                    'registration_date': instance.get('RegistrationDate').isoformat() if instance.get('RegistrationDate') else None
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== SSM ASSOCIATIONS ==========
        associations = client.list_associations(MaxResults=50)
        for assoc in associations.get('Associations', []):
            assoc_id = assoc['AssociationId']
            assoc_name = assoc.get('Name', '')
            instance_id = assoc.get('InstanceId', 'N/A')
            
            try:
                assoc_detail = client.describe_association(AssociationId=assoc_id)
                assoc_info = assoc_detail.get('AssociationDescription', {})
                
                services.append({
                    'service_id': 'ssm_association',
                    'resource_id': assoc_id,
                    'resource_name': f"{assoc_name} - {instance_id}",
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'association_id': assoc_id,
                        'association_name': assoc_info.get('AssociationName'),
                        'document_name': assoc_info.get('Name'),
                        'document_version': assoc_info.get('DocumentVersion'),
                        'instance_id': assoc_info.get('InstanceId'),
                        'targets': assoc_info.get('Targets', []),
                        'schedule_expression': assoc_info.get('ScheduleExpression'),
                        'output_location': assoc_info.get('OutputLocation', {}),
                        'last_execution_date': assoc_info.get('LastExecutionDate').isoformat() if assoc_info.get('LastExecutionDate') else None,
                        'last_successful_execution_date': assoc_info.get('LastSuccessfulExecutionDate').isoformat() if assoc_info.get('LastSuccessfulExecutionDate') else None,
                        'status': assoc_info.get('Status', {}).get('Date'),
                        'association_status': assoc_info.get('AssociationStatus', {}).get('Status'),
                        'compliance_severity': assoc_info.get('ComplianceSeverity'),
                        'automation_target_parameter_name': assoc_info.get('AutomationTargetParameterName'),
                        'max_concurrency': assoc_info.get('MaxConcurrency'),
                        'max_errors': assoc_info.get('MaxErrors'),
                        'sync_compliance': assoc_info.get('SyncCompliance'),
                        'apply_only_at_cron_interval': assoc_info.get('ApplyOnlyAtCronInterval', False),
                        'tags': assoc.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            except Exception as e:
                print(f"Error describing SSM association {assoc_id}: {str(e)}")
        
        # ========== SSM PATCH BASELINES ==========
        patch_baselines = client.describe_patch_baselines(MaxResults=50)
        for baseline in patch_baselines.get('BaselineIdentities', []):
            baseline_id = baseline['BaselineId']
            baseline_name = baseline['BaselineName']
            baseline_description = baseline.get('BaselineDescription', '')
            operating_system = baseline.get('OperatingSystem', 'WINDOWS')
            is_default = baseline.get('DefaultBaseline', False)
            
            services.append({
                'service_id': 'ssm_patch_baseline',
                'resource_id': baseline_id,
                'resource_name': baseline_name,
                'region': region,
                'service_type': 'Management & Governance',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'baseline_id': baseline_id,
                    'baseline_name': baseline_name,
                    'baseline_description': baseline_description,
                    'operating_system': operating_system,
                    'is_default': is_default,
                    'tags': baseline.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== SSM MAINTENANCE WINDOWS ==========
        maintenance_windows = client.describe_maintenance_windows(MaxResults=50)
        for window in maintenance_windows.get('WindowIdentities', []):
            window_id = window['WindowId']
            window_name = window.get('Name', window_id)
            schedule = window.get('Schedule', '')
            duration = window.get('Duration', 1)
            cutoff = window.get('Cutoff', 1)
            enabled = window.get('Enabled', True)
            
            services.append({
                'service_id': 'ssm_maintenance_window',
                'resource_id': window_id,
                'resource_name': window_name,
                'region': region,
                'service_type': 'Management & Governance',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'window_id': window_id,
                    'name': window_name,
                    'description': window.get('Description'),
                    'schedule': schedule,
                    'schedule_timezone': window.get('ScheduleTimezone'),
                    'schedule_offset': window.get('ScheduleOffset'),
                    'duration': duration,
                    'cutoff': cutoff,
                    'enabled': enabled,
                    'next_execution_time': window.get('NextExecutionTime'),
                    'tags': window.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== SSM AUTOMATION EXECUTIONS ==========
        try:
            automations = client.list_automation_executions(MaxResults=50)
            for automation in automations.get('AutomationExecutionMetadataList', []):
                execution_id = automation['AutomationExecutionId']
                document_name = automation.get('DocumentName', '')
                execution_status = automation.get('AutomationExecutionStatus', 'Unknown')
                start_time = automation.get('StartTime')
                
                services.append({
                    'service_id': 'ssm_automation',
                    'resource_id': execution_id,
                    'resource_name': f"{document_name} - {execution_id[-8:]}",
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'automation_execution_id': execution_id,
                        'document_name': document_name,
                        'document_version': automation.get('DocumentVersion'),
                        'execution_status': execution_status,
                        'execution_end_time': automation.get('ExecutionEndTime').isoformat() if automation.get('ExecutionEndTime') else None,
                        'execution_start_time': start_time.isoformat() if start_time else None,
                        'executed_by': automation.get('ExecutedBy'),
                        'log_file': automation.get('LogFile'),
                        'outputs': automation.get('Outputs', {}),
                        'mode': automation.get('Mode'),
                        'parent_automation_execution_id': automation.get('ParentAutomationExecutionId'),
                        'current_action': automation.get('CurrentAction'),
                        'target': automation.get('Target'),
                        'target_parameter_name': automation.get('TargetParameterName'),
                        'targets': automation.get('Targets', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM SESSION MANAGER ==========
        try:
            sessions = client.describe_sessions(State='Active')
            for session in sessions.get('Sessions', []):
                session_id = session['SessionId']
                target = session.get('Target', '')
                owner = session.get('Owner', '')
                start_date = session.get('StartDate')
                
                services.append({
                    'service_id': 'ssm_session',
                    'resource_id': session_id,
                    'resource_name': f"Session {session_id[-8:]}",
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Data transfer billed separately
                    'details': {
                        'session_id': session_id,
                        'target': target,
                        'status': session.get('Status'),
                        'start_date': start_date.isoformat() if start_date else None,
                        'owner': owner,
                        'reason': session.get('Reason'),
                        'output_url': session.get('OutputUrl', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM INVENTORY ==========
        try:
            inventory_types = client.get_inventory_schema()
            for inventory_type in inventory_types.get('Schemas', []):
                type_name = inventory_type['TypeName']
                version = inventory_type.get('Version', '1.0')
                
                services.append({
                    'service_id': 'ssm_inventory',
                    'resource_id': f"inventory-{type_name}",
                    'resource_name': type_name.split(':')[-1],
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Free for EC2, paid for on-prem
                    'details': {
                        'type_name': type_name,
                        'version': version,
                        'display_name': inventory_type.get('DisplayName'),
                        'attributes': inventory_type.get('Attributes', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM COMPLIANCE ==========
        try:
            compliance_summary = client.list_compliance_summaries(MaxResults=50)
            for compliance in compliance_summary.get('ComplianceSummaryItems', []):
                compliance_type = compliance['ComplianceType']
                
                services.append({
                    'service_id': 'ssm_compliance',
                    'resource_id': f"compliance-{compliance_type}",
                    'resource_name': compliance_type,
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'compliance_type': compliance_type,
                        'compliant_count': compliance.get('CompliantSummary', {}).get('CompliantCount', 0),
                        'non_compliant_count': compliance.get('NonCompliantSummary', {}).get('NonCompliantCount', 0),
                        'severity_summary': compliance.get('SeveritySummary', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM OPSMETADATA ==========
        try:
            ops_metadata = client.list_ops_metadata(MaxResults=50)
            for ops in ops_metadata.get('OpsMetadataList', []):
                ops_id = ops['OpsMetadataId']
                resource_id = ops.get('ResourceId', '')
                
                services.append({
                    'service_id': 'ssm_opsmetadata',
                    'resource_id': ops_id,
                    'resource_name': ops.get('ResourceId', ops_id),
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'ops_metadata_id': ops_id,
                        'resource_id': resource_id,
                        'created_date': ops.get('CreatedDate').isoformat() if ops.get('CreatedDate') else None,
                        'last_modified_date': ops.get('LastModifiedDate').isoformat() if ops.get('LastModifiedDate') else None,
                        'last_modified_user': ops.get('LastModifiedUser'),
                        'version': ops.get('Version')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM RESOURCE DATA SYNC ==========
        try:
            syncs = client.list_resource_data_sync()
            for sync in syncs.get('ResourceDataSyncItems', []):
                sync_name = sync['SyncName']
                sync_type = sync.get('SyncType', 'SyncFromSource')
                
                services.append({
                    'service_id': 'ssm_resource_data_sync',
                    'resource_id': sync_name,
                    'resource_name': sync_name,
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'sync_name': sync_name,
                        'sync_type': sync_type,
                        'sync_source': sync.get('SyncSource', {}),
                        's3_destination': sync.get('S3Destination', {}),
                        'last_sync_time': sync.get('LastSyncTime').isoformat() if sync.get('LastSyncTime') else None,
                        'last_successful_sync_time': sync.get('LastSuccessfulSyncTime').isoformat() if sync.get('LastSuccessfulSyncTime') else None,
                        'sync_created_time': sync.get('SyncCreatedTime').isoformat() if sync.get('SyncCreatedTime') else None,
                        'sync_status': sync.get('SyncStatus')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM OPSITEMS ==========
        try:
            ops_items = client.describe_ops_items(MaxResults=50)
            for ops_item in ops_items.get('OpsItemSummaries', []):
                ops_item_id = ops_item['OpsItemId']
                
                services.append({
                    'service_id': 'ssm_opsitem',
                    'resource_id': ops_item_id,
                    'resource_name': f"OpsItem {ops_item_id[-8:]}",
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'ops_item_id': ops_item_id,
                        'title': ops_item.get('Title'),
                        'source': ops_item.get('Source'),
                        'priority': ops_item.get('Priority'),
                        'severity': ops_item.get('Severity'),
                        'status': ops_item.get('Status'),
                        'category': ops_item.get('Category'),
                        'created_by': ops_item.get('CreatedBy'),
                        'created_time': ops_item.get('CreatedTime').isoformat() if ops_item.get('CreatedTime') else None,
                        'last_modified_by': ops_item.get('LastModifiedBy'),
                        'last_modified_time': ops_item.get('LastModifiedTime').isoformat() if ops_item.get('LastModifiedTime') else None,
                        'actual_start_time': ops_item.get('ActualStartTime').isoformat() if ops_item.get('ActualStartTime') else None,
                        'actual_end_time': ops_item.get('ActualEndTime').isoformat() if ops_item.get('ActualEndTime') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== SSM INCIDENT MANAGER ==========
        try:
            # Check if Incident Manager is available in this region
            ssm_incidents = boto3.client(
                'ssm-incidents',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region
            )
            
            # List response plans
            response_plans = ssm_incidents.list_response_plans()
            for plan in response_plans.get('responsePlanSummaries', []):
                plan_arn = plan['arn']
                plan_name = plan['name']
                
                # $0.125 per contact per month
                monthly_cost = 0.125
                
                services.append({
                    'service_id': 'ssm_incident_manager',
                    'resource_id': plan_arn,
                    'resource_name': plan_name,
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': monthly_cost,
                    'details': {
                        'response_plan_arn': plan_arn,
                        'name': plan_name,
                        'display_name': plan.get('displayName'),
                        'tags': plan.get('tags', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering SSM services in {region}: {str(e)}")
    
    return services

def get_ssm_parameter_tags(client, parameter_name):
    """Get tags for SSM parameter"""
    try:
        response = client.list_tags_for_resource(
            ResourceType='Parameter',
            ResourceId=parameter_name
        )
        return response.get('TagList', [])
    except:
        return []