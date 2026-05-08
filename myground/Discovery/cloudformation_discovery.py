# discovery/cloudformation_discovery.py
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

def discover_cloudformation_services(creds, region):
    """Discover CloudFormation stacks, stack sets, and resources"""
    services = []
    try:
        client = boto3.client(
            'cloudformation',
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
        
        # ========== CLOUDFORMATION STACKS ==========
        stacks = client.list_stacks(
            StackStatusFilter=[
                'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE',
                'DELETE_FAILED', 'CREATE_FAILED', 'ROLLBACK_COMPLETE', 'IMPORT_COMPLETE'
            ]
        )
        
        for stack_summary in stacks.get('StackSummaries', []):
            stack_name = stack_summary['StackName']
            stack_id = stack_summary['StackId']
            stack_status = stack_summary['StackStatus']
            creation_time = stack_summary['CreationTime']
            
            try:
                # Get detailed stack information
                stack_detail = client.describe_stacks(StackName=stack_name)
                stack = stack_detail['Stacks'][0]
                
                # Get stack resources
                resources = client.list_stack_resources(StackName=stack_name)
                resource_count = len(resources.get('StackResourceSummaries', []))
                
                # Get stack events (latest 10)
                events = client.describe_stack_events(StackName=stack_name)
                recent_events = events.get('StackEvents', [])[:10]
                
                # CloudFormation is free, only resources are billed
                services.append({
                    'service_id': 'cfn_stack',
                    'resource_id': stack_id,
                    'resource_name': stack_name,
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'stack_id': stack_id,
                        'stack_name': stack_name,
                        'status': stack_status,
                        'status_reason': stack.get('StackStatusReason'),
                        'description': stack.get('Description'),
                        'creation_time': creation_time.isoformat() if creation_time else None,
                        'last_updated_time': stack.get('LastUpdatedTime').isoformat() if stack.get('LastUpdatedTime') else None,
                        'deletion_time': stack.get('DeletionTime').isoformat() if stack.get('DeletionTime') else None,
                        'rollback_configuration': stack.get('RollbackConfiguration', {}),
                        'timeout_in_minutes': stack.get('TimeoutInMinutes'),
                        'capabilities': stack.get('Capabilities', []),
                        'outputs': stack.get('Outputs', []),
                        'parameters': stack.get('Parameters', []),
                        'tags': stack.get('Tags', []),
                        'enable_termination_protection': stack.get('EnableTerminationProtection', False),
                        'parent_id': stack.get('ParentId'),
                        'root_id': stack.get('RootId'),
                        'drift_information': stack.get('DriftInformation', {}),
                        'resource_count': resource_count,
                        'recent_events': [
                            {
                                'event_id': e.get('EventId'),
                                'timestamp': e.get('Timestamp').isoformat() if e.get('Timestamp') else None,
                                'resource_status': e.get('ResourceStatus'),
                                'resource_status_reason': e.get('ResourceStatusReason'),
                                'resource_type': e.get('ResourceType'),
                                'logical_resource_id': e.get('LogicalResourceId'),
                                'physical_resource_id': e.get('PhysicalResourceId')
                            }
                            for e in recent_events
                        ]
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== STACK RESOURCES ==========
                for resource in resources.get('StackResourceSummaries', [])[:20]:  # Limit to 20 per stack
                    logical_id = resource['LogicalResourceId']
                    physical_id = resource.get('PhysicalResourceId', 'N/A')
                    resource_type = resource['ResourceType']
                    resource_status = resource['ResourceStatus']
                    last_updated = resource.get('LastUpdatedTimestamp')
                    
                    services.append({
                        'service_id': 'cfn_stack_resource',
                        'resource_id': f"{stack_id}/{logical_id}",
                        'resource_name': logical_id,
                        'region': region,
                        'service_type': 'Management & Governance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'stack_id': stack_id,
                            'stack_name': stack_name,
                            'logical_resource_id': logical_id,
                            'physical_resource_id': physical_id,
                            'resource_type': resource_type,
                            'resource_status': resource_status,
                            'resource_status_reason': resource.get('ResourceStatusReason'),
                            'last_updated_timestamp': last_updated.isoformat() if last_updated else None,
                            'drift_information': resource.get('DriftInformation', {})
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
            except Exception as e:
                print(f"Error describing CloudFormation stack {stack_name}: {str(e)}")
        
        # ========== CLOUDFORMATION STACK SETS ==========
        try:
            stack_sets = client.list_stack_sets()
            for stack_set_summary in stack_sets.get('Summaries', []):
                stack_set_name = stack_set_summary['StackSetName']
                stack_set_id = stack_set_summary.get('StackSetId', stack_set_name)
                stack_set_status = stack_set_summary.get('Status', 'ACTIVE')
                description = stack_set_summary.get('Description')
                
                try:
                    # Get detailed stack set information
                    stack_set_detail = client.describe_stack_set(StackSetName=stack_set_name)
                    stack_set = stack_set_detail['StackSet']
                    
                    # Get stack set operations
                    operations = client.list_stack_set_operations(StackSetName=stack_set_name)
                    operation_count = len(operations.get('Summaries', []))
                    
                    services.append({
                        'service_id': 'cfn_stackset',
                        'resource_id': stack_set_id,
                        'resource_name': stack_set_name,
                        'region': region,
                        'service_type': 'Management & Governance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'stack_set_id': stack_set_id,
                            'stack_set_name': stack_set_name,
                            'status': stack_set_status,
                            'description': description,
                            'capabilities': stack_set.get('Capabilities', []),
                            'parameters': stack_set.get('Parameters', []),
                            'template_body': stack_set.get('TemplateBody')[:500] + '...' if stack_set.get('TemplateBody') and len(stack_set.get('TemplateBody', '')) > 500 else stack_set.get('TemplateBody'),
                            'execution_role_name': stack_set.get('ExecutionRoleName'),
                            'administration_role_arn': stack_set.get('AdministrationRoleARN'),
                            'permission_model': stack_set.get('PermissionModel'),
                            'auto_deployment': stack_set.get('AutoDeployment', {}),
                            'operation_count': operation_count,
                            'tags': stack_set.get('Tags', []),
                            'created_at': stack_set_summary.get('CreatedTimestamp').isoformat() if stack_set_summary.get('CreatedTimestamp') else None,
                            'updated_at': stack_set_summary.get('LastUpdatedTimestamp').isoformat() if stack_set_summary.get('LastUpdatedTimestamp') else None
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
                    # ========== STACK SET INSTANCES ==========
                    try:
                        instances = client.list_stack_instances(StackSetName=stack_set_name)
                        for instance in instances.get('Summaries', []):
                            services.append({
                                'service_id': 'cfn_stackset_instance',
                                'resource_id': f"{stack_set_id}/{instance.get('Account')}/{instance.get('Region')}",
                                'resource_name': f"{stack_set_name} - {instance.get('Account')} - {instance.get('Region')}",
                                'region': region,
                                'service_type': 'Management & Governance',
                                'estimated_monthly_cost': 0.00,
                'count': 1,
                                'details': {
                                    'stack_set_id': stack_set_id,
                                    'stack_set_name': stack_set_name,
                                    'account': instance.get('Account'),
                                    'region': instance.get('Region'),
                                    'stack_id': instance.get('StackId'),
                                    'status': instance.get('Status'),
                                    'status_reason': instance.get('StatusReason'),
                                    'stack_instance_status': instance.get('StackInstanceStatus', {}),
                                    'organizational_unit_id': instance.get('OrganizationalUnitId'),
                                    'drift_information': instance.get('DriftInformation', {})
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    except:
                        pass
                        
                except Exception as e:
                    print(f"Error describing CloudFormation stack set {stack_set_name}: {str(e)}")
        except:
            pass
        
        # ========== CLOUDFORMATION CHANGE SETS ==========
        for stack_summary in stacks.get('StackSummaries', []):
            stack_name = stack_summary['StackName']
            try:
                change_sets = client.list_change_sets(StackName=stack_name)
                for change_set_summary in change_sets.get('Summaries', []):
                    change_set_name = change_set_summary['ChangeSetName']
                    change_set_id = change_set_summary['ChangeSetId']
                    change_set_status = change_set_summary['Status']
                    execution_status = change_set_summary.get('ExecutionStatus')
                    
                    services.append({
                        'service_id': 'cfn_change_set',
                        'resource_id': change_set_id,
                        'resource_name': change_set_name,
                        'region': region,
                        'service_type': 'Management & Governance',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'change_set_id': change_set_id,
                            'change_set_name': change_set_name,
                            'stack_name': stack_name,
                            'stack_id': change_set_summary.get('StackId'),
                            'status': change_set_status,
                            'status_reason': change_set_summary.get('StatusReason'),
                            'execution_status': execution_status,
                            'description': change_set_summary.get('Description'),
                            'creation_time': change_set_summary.get('CreationTime').isoformat() if change_set_summary.get('CreationTime') else None
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== CLOUDFORMATION MACROS ==========
        try:
            macros = client.list_macros()
            for macro_summary in macros.get('MacroSummaries', []):
                macro_name = macro_summary['Name']
                macro_id = macro_summary.get('MacroId', macro_name)
                
                services.append({
                    'service_id': 'cfn_macro',
                    'resource_id': macro_id,
                    'resource_name': macro_name,
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Lambda billing applies
                    'details': {
                        'macro_name': macro_name,
                        'macro_id': macro_id,
                        'description': macro_summary.get('Description'),
                        'function_arn': macro_summary.get('FunctionArn'),
                        'log_group_name': macro_summary.get('LogGroupName'),
                        'log_role_arn': macro_summary.get('LogRoleARN'),
                        'status': macro_summary.get('Status')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDFORMATION REGISTRY (EXTENSIONS) ==========
        try:
            # Public extensions
            public_extensions = client.list_types(
                Visibility='PUBLIC',
                ProvisioningType='FULLY_MUTABLE'
            )
            for ext in public_extensions.get('TypeSummaries', [])[:20]:  # Limit to 20
                services.append({
                    'service_id': 'cfn_registry',
                    'resource_id': ext.get('TypeArn', ext['TypeName']),
                    'resource_name': ext['TypeName'],
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'type_name': ext.get('TypeName'),
                        'type_arn': ext.get('TypeArn'),
                        'type': ext.get('Type'),
                        'description': ext.get('Description'),
                        'publisher_id': ext.get('PublisherId'),
                        'publisher_name': ext.get('PublisherName'),
                        'latest_version_id': ext.get('LatestVersionId'),
                        'default_version_id': ext.get('DefaultVersionId')
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            
            # Private extensions in this account
            private_extensions = client.list_types(
                Visibility='PRIVATE',
                ProvisioningType='FULLY_MUTABLE'
            )
            for ext in private_extensions.get('TypeSummaries', []):
                services.append({
                    'service_id': 'cfn_private_registry',
                    'resource_id': ext.get('TypeArn', ext['TypeName']),
                    'resource_name': ext['TypeName'],
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'type_name': ext.get('TypeName'),
                        'type_arn': ext.get('TypeArn'),
                        'type': ext.get('Type'),
                        'description': ext.get('Description'),
                        'latest_version_id': ext.get('LatestVersionId'),
                        'default_version_id': ext.get('DefaultVersionId'),
                        'time_created': ext.get('TimeCreated').isoformat() if ext.get('TimeCreated') else None
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDFORMATION GENERATED TEMPLATES ==========
        try:
            generated_templates = client.list_generated_templates()
            for template in generated_templates.get('GeneratedTemplates', []):
                template_name = template['GeneratedTemplateName']
                template_id = template['GeneratedTemplateId']
                
                services.append({
                    'service_id': 'cfn_generated_template',
                    'resource_id': template_id,
                    'resource_name': template_name,
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'generated_template_id': template_id,
                        'generated_template_name': template_name,
                        'status': template.get('Status'),
                        'status_reason': template.get('StatusReason'),
                        'creation_time': template.get('CreationTime').isoformat() if template.get('CreationTime') else None,
                        'last_updated_time': template.get('LastUpdatedTime').isoformat() if template.get('LastUpdatedTime') else None,
                        'progress': template.get('Progress'),
                        'stack_count': template.get('StackCount'),
                        'template_configuration': template.get('TemplateConfiguration', {})
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== CLOUDFORMATION RESOURCE SCANS ==========
        try:
            resource_scans = client.list_resource_scans()
            for scan in resource_scans.get('ResourceScanSummaries', []):
                scan_id = scan['ResourceScanId']
                
                services.append({
                    'service_id': 'cfn_resource_scan',
                    'resource_id': scan_id,
                    'resource_name': f"Resource Scan {scan_id[-8:]}",
                    'region': region,
                    'service_type': 'Management & Governance',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'resource_scan_id': scan_id,
                        'status': scan.get('Status'),
                        'status_reason': scan.get('StatusReason'),
                        'start_time': scan.get('StartTime').isoformat() if scan.get('StartTime') else None,
                        'end_time': scan.get('EndTime').isoformat() if scan.get('EndTime') else None,
                        'percentage_completed': scan.get('PercentageCompleted'),
                        'resource_types_scanned': scan.get('ResourceTypesScanned', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering CloudFormation services in {region}: {str(e)}")
    
    return services