# discovery/eks_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_eks_services(creds, region):
    """Discover EKS clusters and related resources"""
    services = []
    try:
        client = boto3.client(
            'eks',
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
        
        # ========== EKS CLUSTERS ==========
        clusters = client.list_clusters()
        for cluster_name in clusters.get('clusters', []):
            try:
                cluster = client.describe_cluster(name=cluster_name)
                cluster_info = cluster['cluster']
                
                # EKS control plane: $0.10 per hour
                hourly_cost = 0.10
                monthly_cost = hourly_cost * 730
                
                services.append({
                    'service_id': 'eks_control_plane',
                    'resource_id': cluster_info['arn'],
                    'resource_name': cluster_name,
                    'region': region,
                    'service_type': 'Compute',
                    'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                    'details': {
                        'cluster_name': cluster_name,
                        'cluster_arn': cluster_info['arn'],
                        'status': cluster_info.get('status'),
                        'version': cluster_info.get('version'),
                        'endpoint': cluster_info.get('endpoint'),
                        'role_arn': cluster_info.get('roleArn'),
                        'vpc_config': cluster_info.get('resourcesVpcConfig', {}),
                        'kubernetes_network_config': cluster_info.get('kubernetesNetworkConfig', {}),
                        'logging': cluster_info.get('logging', {}),
                        'identity': cluster_info.get('identity', {}),
                        'created_at': cluster_info.get('createdAt').isoformat() if cluster_info.get('createdAt') else None,
                        'platform_version': cluster_info.get('platformVersion'),
                        'tags': cluster_info.get('tags', {}),
                        'encryption_config': cluster_info.get('encryptionConfig', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
                
                # ========== EKS NODE GROUPS ==========
                nodegroups = client.list_nodegroups(clusterName=cluster_name)
                for nodegroup_name in nodegroups.get('nodegroups', []):
                    try:
                        ng = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
                        nodegroup = ng['nodegroup']
                        
                        # Node groups are free, nodes are billed separately (EC2/Fargate)
                        services.append({
                            'service_id': 'eks_managed_node_group',
                            'resource_id': nodegroup['nodegroupArn'],
                            'resource_name': nodegroup_name,
                            'region': region,
                            'service_type': 'Compute',
                            'estimated_monthly_cost': 0.00,
                'count': 1,
                            'details': {
                                'nodegroup_name': nodegroup_name,
                                'nodegroup_arn': nodegroup['nodegroupArn'],
                                'cluster_name': cluster_name,
                                'status': nodegroup.get('status'),
                                'instance_types': nodegroup.get('instanceTypes', []),
                                'subnets': nodegroup.get('subnets', []),
                                'ami_type': nodegroup.get('amiType'),
                                'node_role': nodegroup.get('nodeRole'),
                                'scaling_config': nodegroup.get('scalingConfig', {}),
                                'disk_size': nodegroup.get('diskSize'),
                                'capacity_type': nodegroup.get('capacityType', 'ON_DEMAND'),
                                'release_version': nodegroup.get('releaseVersion'),
                                'version': nodegroup.get('version'),
                                'created_at': nodegroup.get('createdAt').isoformat() if nodegroup.get('createdAt') else None,
                                'tags': nodegroup.get('tags', {}),
                                'health': nodegroup.get('health', {}),
                                'resources': nodegroup.get('resources', {})
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                        
                        # ========== EKS FARGATE PROFILES ==========
                        fargate_profiles = client.list_fargate_profiles(clusterName=cluster_name)
                        for fargate_name in fargate_profiles.get('fargateProfileNames', []):
                            try:
                                fp = client.describe_fargate_profile(
                                    clusterName=cluster_name,
                                    fargateProfileName=fargate_name
                                )
                                fargate = fp['fargateProfile']
                                
                                services.append({
                                    'service_id': 'eks_fargate_profile',
                                    'resource_id': fargate['fargateProfileArn'],
                                    'resource_name': fargate_name,
                                    'region': region,
                                    'service_type': 'Compute',
                                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Pods are billed separately
                                    'details': {
                                        'fargate_profile_name': fargate_name,
                                        'fargate_profile_arn': fargate['fargateProfileArn'],
                                        'cluster_name': cluster_name,
                                        'status': fargate.get('status'),
                                        'pod_execution_role_arn': fargate.get('podExecutionRoleArn'),
                                        'subnets': fargate.get('subnets', []),
                                        'selectors': fargate.get('selectors', []),
                                        'created_at': fargate.get('createdAt').isoformat() if fargate.get('createdAt') else None,
                                        'tags': fargate.get('tags', {})
                                    },
                                    'discovered_at': datetime.now(timezone.utc).isoformat()
                                })
                            except:
                                pass
                                
                    except Exception as e:
                        print(f"Error describing nodegroup {nodegroup_name}: {str(e)}")
                
                # ========== EKS ADD-ONS ==========
                try:
                    addons = client.list_addons(clusterName=cluster_name)
                    for addon_name in addons.get('addons', []):
                        try:
                            addon = client.describe_addon(clusterName=cluster_name, addonName=addon_name)
                            addon_info = addon['addon']
                            
                            services.append({
                                'service_id': 'eks_add_on',
                                'resource_id': addon_info['addonArn'],
                                'resource_name': addon_name,
                                'region': region,
                                'service_type': 'Compute',
                                'estimated_monthly_cost': 0.00,
                'count': 1,
                                'details': {
                                    'addon_name': addon_name,
                                    'addon_arn': addon_info['addonArn'],
                                    'cluster_name': cluster_name,
                                    'status': addon_info.get('status'),
                                    'addon_version': addon_info.get('addonVersion'),
                                    'service_account_role_arn': addon_info.get('serviceAccountRoleArn'),
                                    'health': addon_info.get('health', {}),
                                    'created_at': addon_info.get('createdAt').isoformat() if addon_info.get('createdAt') else None,
                                    'modified_at': addon_info.get('modifiedAt').isoformat() if addon_info.get('modifiedAt') else None,
                                    'tags': addon_info.get('tags', {})
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                        except:
                            pass
                except:
                    pass
                    
            except Exception as e:
                print(f"Error describing EKS cluster {cluster_name}: {str(e)}")
        
        # ========== EKS IDENTITY PROVIDERS ==========
        for cluster_name in clusters.get('clusters', []):
            try:
                providers = client.list_identity_provider_configs(clusterName=cluster_name)
                for provider in providers.get('identityProviderConfigs', []):
                    provider_name = provider['name']
                    provider_type = provider['type']
                    
                    services.append({
                        'service_id': 'eks_identity_provider',
                        'resource_id': f"{cluster_name}/{provider_name}",
                        'resource_name': provider_name,
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': 0.00,
                'count': 1,
                        'details': {
                            'cluster_name': cluster_name,
                            'provider_name': provider_name,
                            'provider_type': provider_type,
                            'provider_arn': provider.get('providerArn')
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
        # ========== EKS CONTROL PLANE LOGGING ==========
        for cluster_name in clusters.get('clusters', []):
            try:
                cluster = client.describe_cluster(name=cluster_name)
                cluster_info = cluster['cluster']
                
                logging = cluster_info.get('logging', {}).get('clusterLogging', [])
                enabled_logs = []
                for log_setup in logging:
                    if log_setup.get('enabled', False):
                        enabled_logs.extend(log_setup.get('types', []))
                
                if enabled_logs:
                    # CloudWatch logs cost - assume 1GB per month
                    monthly_cost = 0.80  # $0.80 per GB ingested
                    
                    services.append({
                        'service_id': 'eks_control_plane_logging',
                        'resource_id': f"{cluster_info['arn']}/logging",
                        'resource_name': f"{cluster_name} Control Plane Logs",
                        'region': region,
                        'service_type': 'Compute',
                        'estimated_monthly_cost': monthly_cost,
                        'details': {
                            'cluster_name': cluster_name,
                            'enabled_log_types': enabled_logs,
                            'cloudwatch_log_group': f"/aws/eks/{cluster_name}/cluster"
                        },
                        'discovered_at': datetime.now(timezone.utc).isoformat()
                    })
            except:
                pass
        
    except Exception as e:
        print(f"Error discovering EKS services in {region}: {str(e)}")
    
    return services