# discovery/ecs_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_ecs_services(creds, region):
    """Discover ECS clusters, services, tasks, and related resources"""
    services = []
    try:
        client = boto3.client(
            'ecs',
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
        
        # ========== ECS CLUSTERS ==========
        clusters = client.list_clusters()
        for cluster_arn in clusters.get('clusterArns', []):
            try:
                cluster_details = client.describe_clusters(clusters=[cluster_arn])
                for cluster in cluster_details.get('clusters', []):
                    cluster_name = cluster['clusterName']
                    status = cluster.get('status', 'ACTIVE')
                    registered_container_instances = cluster.get('registeredContainerInstancesCount', 0)
                    running_tasks = cluster.get('runningTasksCount', 0)
                    pending_tasks = cluster.get('pendingTasksCount', 0)
                    active_services = cluster.get('activeServicesCount', 0)
                    
                    # ECS cluster itself is free, only resources are billed
                    services.append({
                        'service_id': 'ecs_cluster',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'cluster_arn': cluster_arn,
                            'cluster_name': cluster_name,
                            'status': status,
                            'registered_container_instances': registered_container_instances,
                            'running_tasks_count': running_tasks,
                            'pending_tasks_count': pending_tasks,
                            'active_services_count': active_services,
                            'statistics': cluster.get('statistics', []),
                            'tags': cluster.get('tags', []),
                            'capacity_providers': cluster.get('capacityProviders', []),
                            'default_capacity_provider_strategy': cluster.get('defaultCapacityProviderStrategy', [])
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
                    
                    # ========== ECS SERVICES ==========
                    services_list = client.list_services(cluster=cluster_name)
                    for service_arn in services_list.get('serviceArns', []):
                        try:
                            service_details = client.describe_services(cluster=cluster_name, services=[service_arn])
                            for service in service_details.get('services', []):
                                service_name = service['serviceName']
                                service_status = service.get('status', 'ACTIVE')
                                desired_count = service.get('desiredCount', 0)
                                running_count = service.get('runningCount', 0)
                                pending_count = service.get('pendingCount', 0)
                                
                                launch_type = service.get('launchType', 'EC2')
                                platform_version = service.get('platformVersion', 'LATEST')
                                
                                # Determine service ID based on launch type
                                if launch_type == 'FARGATE':
                                    # Fargate costs are tracked per task, not per service
                                    service_id = 'ecs_service_fargate'
                                    monthly_cost = 0.00  # Tasks are billed separately
                                else:
                                    service_id = 'ecs_service_ec2'
                                    monthly_cost = 0.00  # EC2 instances are billed separately
                                
                                services.append({
                                    'service_id': service_id,
                                    'resource_id': service_arn,
                                    'resource_name': service_name,
                                    'region': region,
                                    'service_type': 'Compute',
                                    'estimated_monthly_cost': monthly_cost,
                                    'details': {
                                        'service_arn': service_arn,
                                        'service_name': service_name,
                                        'cluster_arn': cluster_arn,
                                        'cluster_name': cluster_name,
                                        'status': service_status,
                                        'desired_count': desired_count,
                                        'running_count': running_count,
                                        'pending_count': pending_count,
                                        'launch_type': launch_type,
                                        'platform_version': platform_version,
                                        'task_definition': service.get('taskDefinition'),
                                        'deployment_configuration': service.get('deploymentConfiguration', {}),
                                        'load_balancers': service.get('loadBalancers', []),
                                        'service_registries': service.get('serviceRegistries', []),
                                        'network_configuration': service.get('networkConfiguration', {}),
                                        'health_check_grace_period_seconds': service.get('healthCheckGracePeriodSeconds'),
                                        'scheduling_strategy': service.get('schedulingStrategy', 'REPLICA'),
                                        'deployment_controller': service.get('deploymentController', {}),
                                        'tags': service.get('tags', []),
                                        'created_at': service.get('createdAt').isoformat() if service.get('createdAt') else None
                                    },
                                    'discovered_at': datetime.now(timezone.utc).isoformat()
                                })
                                
                                # ========== FARGATE TASKS ==========
                                if launch_type == 'FARGATE':
                                    tasks = client.list_tasks(cluster=cluster_name, serviceName=service_name)
                                    for task_arn in tasks.get('taskArns', []):
                                        task_details = client.describe_tasks(cluster=cluster_name, tasks=[task_arn])
                                        for task in task_details.get('tasks', []):
                                            task_def_arn = task.get('taskDefinitionArn')
                                            task_def_details = client.describe_task_definition(taskDefinition=task_def_arn)
                                            task_def = task_def_details.get('taskDefinition', {})
                                            
                                            # Calculate Fargate costs
                                            cpu = int(task_def.get('cpu', '256').replace(' vCPU', '')) if 'vCPU' in str(task_def.get('cpu', '256')) else int(task_def.get('cpu', 256))
                                            memory = int(task_def.get('memory', '512').replace(' MB', '')) if 'MB' in str(task_def.get('memory', '512')) else int(task_def.get('memory', 512))
                                            
                                            # Convert CPU to vCPU count
                                            cpu_vcpus = cpu / 1024 if cpu > 256 else 0.25 if cpu == 256 else 0.5 if cpu == 512 else 1
                                            
                                            # x86 pricing
                                            vcpu_hourly_cost = 0.04048
                                            gb_hourly_cost = 0.0044452
                                            
                                            # Check if ARM/Graviton (20% less)
                                            if task_def.get('runtimePlatform', {}).get('cpuArchitecture') == 'arm64':
                                                vcpu_hourly_cost *= 0.8
                                                gb_hourly_cost *= 0.8
                                            
                                            # Calculate monthly cost (assume 24/7 running)
                                            monthly_cost = (cpu_vcpus * vcpu_hourly_cost * 730) + (memory / 1024 * gb_hourly_cost * 730)
                                            
                                            services.append({
                                                'service_id': 'ecs_fargate_task',
                                                'resource_id': task_arn,
                                                'resource_name': f"{service_name}-{task.get('taskArn').split('/')[-1]}",
                                                'region': region,
                                                'service_type': 'Compute',
                                                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                                                'details': {
                                                    'task_arn': task_arn,
                                                    'task_definition_arn': task_def_arn,
                                                    'cluster_arn': cluster_arn,
                                                    'service_name': service_name,
                                                    'launch_type': 'FARGATE',
                                                    'cpu': cpu,
                                                    'memory': memory,
                                                    'cpu_vcpus': cpu_vcpus,
                                                    'memory_gb': memory / 1024,
                                                    'platform_version': task.get('platformVersion'),
                                                    'last_status': task.get('lastStatus'),
                                                    'desired_status': task.get('desiredStatus'),
                                                    'created_at': task.get('createdAt').isoformat() if task.get('createdAt') else None,
                                                    'started_at': task.get('startedAt').isoformat() if task.get('startedAt') else None,
                                                    'containers': task.get('containers', []),
                                                    'availability_zone': task.get('availabilityZone'),
                                                    'vpc_id': task.get('attachments', [{}])[0].get('details', [])[0].get('value') if task.get('attachments') else None
                                                },
                                                'discovered_at': datetime.now(timezone.utc).isoformat()
                                            })
                        except Exception as e:
                            print(f"Error describing ECS service {service_arn}: {str(e)}")
                    
                    # ========== ECS TASKS (EC2) ==========
                    tasks = client.list_tasks(cluster=cluster_name)
                    for task_arn in tasks.get('taskArns', []):
                        try:
                            task_details = client.describe_tasks(cluster=cluster_name, tasks=[task_arn])
                            for task in task_details.get('tasks', []):
                                if task.get('launchType') != 'FARGATE':
                                    services.append({
                                        'service_id': 'ecs_task_ec2',
                                        'resource_id': task_arn,
                                        'resource_name': f"task-{task.get('taskArn').split('/')[-1]}",
                                        'region': region,
                                        'service_type': 'Compute',
                                        'estimated_monthly_cost': 0.00,
                'count': 1,  # EC2 instances billed separately
                                        'details': {
                                            'task_arn': task_arn,
                                            'task_definition_arn': task.get('taskDefinitionArn'),
                                            'cluster_arn': cluster_arn,
                                            'launch_type': 'EC2',
                                            'last_status': task.get('lastStatus'),
                                            'desired_status': task.get('desiredStatus'),
                                            'container_instance_arn': task.get('containerInstanceArn'),
                                            'created_at': task.get('createdAt').isoformat() if task.get('createdAt') else None,
                                            'started_at': task.get('startedAt').isoformat() if task.get('startedAt') else None,
                                            'containers': task.get('containers', [])
                                        },
                                        'discovered_at': datetime.now(timezone.utc).isoformat()
                                    })
                        except Exception as e:
                            print(f"Error describing ECS task {task_arn}: {str(e)}")
                    
                    # ========== ECS CONTAINER INSTANCES ==========
                    container_instances = client.list_container_instances(cluster=cluster_name)
                    for instance_arn in container_instances.get('containerInstanceArns', []):
                        try:
                            instance_details = client.describe_container_instances(cluster=cluster_name, containerInstances=[instance_arn])
                            for instance in instance_details.get('containerInstances', []):
                                services.append({
                                    'service_id': 'ecs_container_instance',
                                    'resource_id': instance_arn,
                                    'resource_name': instance.get('ec2InstanceId', instance_arn.split('/')[-1]),
                                    'region': region,
                                    'service_type': 'Compute',
                                    'estimated_monthly_cost': 0.00,
                'count': 1,  # EC2 instances billed separately
                                    'details': {
                                        'container_instance_arn': instance_arn,
                                        'ec2_instance_id': instance.get('ec2InstanceId'),
                                        'status': instance.get('status'),
                                        'running_tasks_count': instance.get('runningTasksCount', 0),
                                        'pending_tasks_count': instance.get('pendingTasksCount', 0),
                                        'agent_connected': instance.get('agentConnected', False),
                                        'registered_resources': instance.get('registeredResources', []),
                                        'remaining_resources': instance.get('remainingResources', []),
                                        'attributes': instance.get('attributes', []),
                                        'tags': instance.get('tags', [])
                                    },
                                    'discovered_at': datetime.now(timezone.utc).isoformat()
                                })
                        except Exception as e:
                            print(f"Error describing container instance {instance_arn}: {str(e)}")
                            
            except Exception as e:
                print(f"Error describing ECS cluster {cluster_arn}: {str(e)}")
        
        # ========== ECS TASK DEFINITIONS ==========
        task_definitions = client.list_task_definitions()
        for task_def_arn in task_definitions.get('taskDefinitionArns', []):
            try:
                task_def_details = client.describe_task_definition(taskDefinition=task_def_arn)
                task_def = task_def_details.get('taskDefinition', {})
                
                services.append({
                    'service_id': 'ecs_task_definition',
                    'resource_id': task_def_arn,
                    'resource_name': f"{task_def.get('family')}:{task_def.get('revision')}",
                    'region': region,
                    'service_type': 'Compute',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'task_definition_arn': task_def_arn,
                        'family': task_def.get('family'),
                        'revision': task_def.get('revision'),
                        'status': task_def.get('status'),
                        'network_mode': task_def.get('networkMode'),
                        'container_definitions': task_def.get('containerDefinitions', []),
                        'cpu': task_def.get('cpu'),
                        'memory': task_def.get('memory'),
                        'requires_compatibilities': task_def.get('requiresCompatibilities', []),
                        'execution_role_arn': task_def.get('executionRoleArn'),
                        'task_role_arn': task_def.get('taskRoleArn'),
                        'runtime_platform': task_def.get('runtimePlatform', {}),
                        'registered_at': task_def.get('registeredAt').isoformat() if task_def.get('registeredAt') else None,
                        'tags': task_def_details.get('tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
            except Exception as e:
                print(f"Error describing task definition {task_def_arn}: {str(e)}")
        
        # ========== ECS CAPACITY PROVIDERS ==========
        try:
            capacity_providers = client.describe_capacity_providers()
            for cp in capacity_providers.get('capacityProviders', []):
                services.append({
                    'service_id': 'ecs_capacity_provider',
                    'resource_id': cp['capacityProviderArn'],
                    'resource_name': cp['name'],
                    'region': region,
                    'service_type': 'Compute',
                    'estimated_monthly_cost': 0.00,
                'count': 1,
                    'details': {
                        'capacity_provider_arn': cp['capacityProviderArn'],
                        'name': cp['name'],
                        'status': cp.get('status'),
                        'auto_scaling_group_provider': cp.get('autoScalingGroupProvider', {}),
                        'tags': cp.get('tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
    except Exception as e:
        print(f"Error discovering ECS services in {region}: {str(e)}")
    
    return services