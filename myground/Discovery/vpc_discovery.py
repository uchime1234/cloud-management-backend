# discovery/vpc_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_vpc_services(creds, region):
    """Discover all VPC-related services and components"""
    services = []
    try:
        client = boto3.client(
            'ec2',
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
        
        # ========== VPCS ==========
        vpcs = client.describe_vpcs()
        for vpc in vpcs.get('Vpcs', []):
            services.append({
                'service_id': 'vpc',
                'resource_id': vpc['VpcId'],
                'resource_name': next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), vpc['VpcId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'cidr_block': vpc.get('CidrBlock'),
                    'is_default': vpc.get('IsDefault', False),
                    'state': vpc.get('State'),
                    'tags': vpc.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== SUBNETS ==========
        subnets = client.describe_subnets()
        for subnet in subnets.get('Subnets', []):
            services.append({
                'service_id': 'subnet',
                'resource_id': subnet['SubnetId'],
                'resource_name': next((tag['Value'] for tag in subnet.get('Tags', []) if tag['Key'] == 'Name'), subnet['SubnetId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'vpc_id': subnet.get('VpcId'),
                    'cidr_block': subnet.get('CidrBlock'),
                    'availability_zone': subnet.get('AvailabilityZone'),
                    'available_ip_count': subnet.get('AvailableIpAddressCount'),
                    'map_public_ip_on_launch': subnet.get('MapPublicIpOnLaunch', False),
                    'state': subnet.get('State'),
                    'tags': subnet.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== INTERNET GATEWAYS ==========
        igws = client.describe_internet_gateways()
        for igw in igws.get('InternetGateways', []):
            attachments = igw.get('Attachments', [])
            services.append({
                'service_id': 'internet_gateway',
                'resource_id': igw['InternetGatewayId'],
                'resource_name': next((tag['Value'] for tag in igw.get('Tags', []) if tag['Key'] == 'Name'), igw['InternetGatewayId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'attachments': attachments,
                    'vpc_ids': [att['VpcId'] for att in attachments],
                    'tags': igw.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== NAT GATEWAYS ==========
        nat_gateways = client.describe_nat_gateways()
        for nat in nat_gateways.get('NatGateways', []):
            hourly_cost = 0.045  # $0.045 per hour
            monthly_cost = hourly_cost * 730  # Approximate monthly
            data_processed_cost = 0.045 * 100  # Assume 100GB data processed as example
            
            services.append({
                'service_id': 'nat_gateway',
                'resource_id': nat['NatGatewayId'],
                'resource_name': next((tag['Value'] for tag in nat.get('Tags', []) if tag['Key'] == 'Name'), nat['NatGatewayId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost + data_processed_cost, 2),
                'count': 1,
                'details': {
                    'vpc_id': nat.get('VpcId'),
                    'subnet_id': nat.get('SubnetId'),
                    'state': nat.get('State'),
                    'connectivity_type': nat.get('ConnectivityType', 'public'),
                    'nat_gateway_addresses': nat.get('NatGatewayAddresses', []),
                    'create_time': nat.get('CreateTime').isoformat() if nat.get('CreateTime') else None,
                    'delete_time': nat.get('DeleteTime').isoformat() if nat.get('DeleteTime') else None,
                    'tags': nat.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== VPC ENDPOINTS ==========
        endpoints = client.describe_vpc_endpoints()
        for endpoint in endpoints.get('VpcEndpoints', []):
            hourly_cost = 0.01  # $0.01 per hour
            monthly_cost = hourly_cost * 730
            data_processed_cost = 0.01 * 100  # Assume 100GB data processed
            
            services.append({
                'service_id': 'vpc_endpoint' if endpoint.get('VpcEndpointType') != 'Gateway' else 'vpc_endpoint_gateway',
                'resource_id': endpoint['VpcEndpointId'],
                'resource_name': next((tag['Value'] for tag in endpoint.get('Tags', []) if tag['Key'] == 'Name'), endpoint['VpcEndpointId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost + data_processed_cost, 2),
                'count': 1,
                'details': {
                    'vpc_id': endpoint.get('VpcId'),
                    'service_name': endpoint.get('ServiceName'),
                    'state': endpoint.get('State'),
                    'endpoint_type': endpoint.get('VpcEndpointType'),
                    'subnet_ids': endpoint.get('SubnetIds', []),
                    'security_group_ids': endpoint.get('Groups', []),
                    'private_dns_enabled': endpoint.get('PrivateDnsEnabled', False),
                    'requester_managed': endpoint.get('RequesterManaged', False),
                    'creation_timestamp': endpoint.get('CreationTimestamp').isoformat() if endpoint.get('CreationTimestamp') else None,
                    'tags': endpoint.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== VPC PEERING CONNECTIONS ==========
        peerings = client.describe_vpc_peering_connections()
        for peering in peerings.get('VpcPeeringConnections', []):
            services.append({
                'service_id': 'vpc_peering',
                'resource_id': peering['VpcPeeringConnectionId'],
                'resource_name': next((tag['Value'] for tag in peering.get('Tags', []) if tag['Key'] == 'Name'), peering['VpcPeeringConnectionId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost based on data transfer
                'details': {
                    'requester_vpc': peering.get('RequesterVpcInfo'),
                    'accepter_vpc': peering.get('AccepterVpcInfo'),
                    'status': peering.get('Status', {}),
                    'expiration_time': peering.get('ExpirationTime').isoformat() if peering.get('ExpirationTime') else None,
                    'tags': peering.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== TRANSIT GATEWAYS ==========
        tgws = client.describe_transit_gateways()
        for tgw in tgws.get('TransitGateways', []):
            hourly_cost = 0.05
            monthly_cost = hourly_cost * 730
            
            services.append({
                'service_id': 'transit_gateway',
                'resource_id': tgw['TransitGatewayId'],
                'resource_name': next((tag['Value'] for tag in tgw.get('Tags', []) if tag['Key'] == 'Name'), tgw['TransitGatewayId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'amazon_side_asn': tgw.get('Options', {}).get('AmazonSideAsn'),
                    'auto_accept_shared_attachments': tgw.get('Options', {}).get('AutoAcceptSharedAttachments'),
                    'default_route_table_association': tgw.get('Options', {}).get('DefaultRouteTableAssociation'),
                    'default_route_table_propagation': tgw.get('Options', {}).get('DefaultRouteTablePropagation'),
                    'vpn_ecmp_support': tgw.get('Options', {}).get('VpnEcmpSupport'),
                    'dns_support': tgw.get('Options', {}).get('DnsSupport'),
                    'state': tgw.get('State'),
                    'creation_time': tgw.get('CreationTime').isoformat() if tgw.get('CreationTime') else None,
                    'tags': tgw.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
            # ========== TRANSIT GATEWAY ATTACHMENTS ==========
            attachments = client.describe_transit_gateway_attachments(
                Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw['TransitGatewayId']]}]
            )
            for attachment in attachments.get('TransitGatewayAttachments', []):
                attachment_hourly_cost = 0.05
                attachment_monthly_cost = attachment_hourly_cost * 730
                
                services.append({
                    'service_id': f"transit_gateway_attachment_{attachment.get('ResourceType', 'unknown')}",
                    'resource_id': attachment['TransitGatewayAttachmentId'],
                    'resource_name': attachment['TransitGatewayAttachmentId'],
                    'region': region,
                    'service_type': 'Networking',
                    'estimated_monthly_cost': round(attachment_monthly_cost, 2),
                    'count': 1,
                    'details': {
                        'transit_gateway_id': attachment.get('TransitGatewayId'),
                        'resource_type': attachment.get('ResourceType'),
                        'resource_id': attachment.get('ResourceId'),
                        'state': attachment.get('State'),
                        'tags': attachment.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        
        # ========== VPN CONNECTIONS ==========
        vpn_connections = client.describe_vpn_connections()
        for vpn in vpn_connections.get('VpnConnections', []):
            hourly_cost = 0.05
            monthly_cost = hourly_cost * 730
            data_processed_cost = 0.09 * 100  # Assume 100GB data transfer
            
            services.append({
                'service_id': 'vpn_connection',
                'resource_id': vpn['VpnConnectionId'],
                'resource_name': next((tag['Value'] for tag in vpn.get('Tags', []) if tag['Key'] == 'Name'), vpn['VpnConnectionId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost + data_processed_cost, 2),
                'count': 1,
                'details': {
                    'customer_gateway_id': vpn.get('CustomerGatewayId'),
                    'transit_gateway_id': vpn.get('TransitGatewayId'),
                    'vpn_gateway_id': vpn.get('VpnGatewayId'),
                    'state': vpn.get('State'),
                    'type': vpn.get('Type'),
                    'category': vpn.get('Category'),
                    'options': vpn.get('Options', {}),
                    'static_routes': vpn.get('Routes', []),
                    'tags': vpn.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== CLIENT VPN ENDPOINTS ==========
        try:
            client_vpns = client.describe_client_vpn_endpoints()
            for cvpn in client_vpns.get('ClientVpnEndpoints', []):
                hourly_cost = 0.10
                monthly_cost = hourly_cost * 730
                data_processed_cost = 0.05 * 100
                
                services.append({
                    'service_id': 'client_vpn_endpoint',
                    'resource_id': cvpn['ClientVpnEndpointId'],
                    'resource_name': next((tag['Value'] for tag in cvpn.get('Tags', []) if tag['Key'] == 'Name'), cvpn['ClientVpnEndpointId']),
                    'region': region,
                    'service_type': 'Networking',
                    'estimated_monthly_cost': round(monthly_cost + data_processed_cost, 2),
                'count': 1,
                    'details': {
                        'description': cvpn.get('Description'),
                        'dns_servers': cvpn.get('DnsServers', []),
                        'vpc_id': cvpn.get('VpcId'),
                        'subnet_ids': cvpn.get('AssociatedTargetNetworks', []),
                        'transport_protocol': cvpn.get('TransportProtocol'),
                        'vpn_port': cvpn.get('VpnPort'),
                        'status': cvpn.get('Status'),
                        'connection_log_options': cvpn.get('ConnectionLogOptions', {}),
                        'tags': cvpn.get('Tags', [])
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass  # Client VPN not available in all regions
        
        # ========== ELASTIC IPS ==========
        addresses = client.describe_addresses()
        for address in addresses.get('Addresses', []):
            # Only charge for unattached EIPs
            is_attached = 'InstanceId' in address or 'NetworkInterfaceId' in address
            hourly_cost = 0.005 if not is_attached else 0.00
            monthly_cost = hourly_cost * 730
            
            services.append({
                'service_id': 'elastic_ip',
                'resource_id': address.get('AllocationId', address['PublicIp']),
                'resource_name': address['PublicIp'],
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'public_ip': address.get('PublicIp'),
                    'private_ip_address': address.get('PrivateIpAddress'),
                    'allocation_id': address.get('AllocationId'),
                    'association_id': address.get('AssociationId'),
                    'domain': address.get('Domain'),
                    'instance_id': address.get('InstanceId'),
                    'network_interface_id': address.get('NetworkInterfaceId'),
                    'network_interface_owner_id': address.get('NetworkInterfaceOwnerId'),
                    'public_ipv4_pool': address.get('PublicIpv4Pool'),
                    'tags': address.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== NETWORK INTERFACES ==========
        enis = client.describe_network_interfaces()
        for eni in enis.get('NetworkInterfaces', []):
            # Check if it's an enhanced networking interface
            is_enhanced = eni.get('InterfaceType') in ['efa', 'trunk']
            service_id = 'eni_enhanced' if is_enhanced else 'eni'
            hourly_cost = 0.012 if is_enhanced else 0.00
            monthly_cost = hourly_cost * 730
            
            services.append({
                'service_id': service_id,
                'resource_id': eni['NetworkInterfaceId'],
                'resource_name': eni['NetworkInterfaceId'],
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'description': eni.get('Description'),
                    'vpc_id': eni.get('VpcId'),
                    'subnet_id': eni.get('SubnetId'),
                    'availability_zone': eni.get('AvailabilityZone'),
                    'interface_type': eni.get('InterfaceType'),
                    'private_ip_address': eni.get('PrivateIpAddress'),
                    'private_ip_addresses': eni.get('PrivateIpAddresses', []),
                    'ipv6_addresses': eni.get('Ipv6Addresses', []),
                    'security_groups': eni.get('Groups', []),
                    'attachment': eni.get('Attachment', {}),
                    'requester_managed': eni.get('RequesterManaged', False),
                    'source_dest_check': eni.get('SourceDestCheck', True),
                    'tags': eni.get('TagSet', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== NETWORK ACLS ==========
        nacls = client.describe_network_acls()
        for nacl in nacls.get('NetworkAcls', []):
            services.append({
                'service_id': 'network_acl',
                'resource_id': nacl['NetworkAclId'],
                'resource_name': next((tag['Value'] for tag in nacl.get('Tags', []) if tag['Key'] == 'Name'), nacl['NetworkAclId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'vpc_id': nacl.get('VpcId'),
                    'is_default': nacl.get('IsDefault', False),
                    'entries': nacl.get('Entries', []),
                    'associations': nacl.get('Associations', []),
                    'tags': nacl.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== SECURITY GROUPS ==========
        sgs = client.describe_security_groups()
        for sg in sgs.get('SecurityGroups', []):
            services.append({
                'service_id': 'security_group',
                'resource_id': sg['GroupId'],
                'resource_name': sg['GroupName'],
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'group_name': sg.get('GroupName'),
                    'description': sg.get('Description'),
                    'vpc_id': sg.get('VpcId'),
                    'inbound_rules': sg.get('IpPermissions', []),
                    'outbound_rules': sg.get('IpPermissionsEgress', []),
                    'tags': sg.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== ROUTE TABLES ==========
        route_tables = client.describe_route_tables()
        for rt in route_tables.get('RouteTables', []):
            services.append({
                'service_id': 'route_table',
                'resource_id': rt['RouteTableId'],
                'resource_name': next((tag['Value'] for tag in rt.get('Tags', []) if tag['Key'] == 'Name'), rt['RouteTableId']),
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': 0.00,
                'count': 1,
                'details': {
                    'vpc_id': rt.get('VpcId'),
                    'routes': rt.get('Routes', []),
                    'associations': rt.get('Associations', []),
                    'propagating_vgws': rt.get('PropagatingVgws', []),
                    'tags': rt.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
        
        # ========== VPC FLOW LOGS ==========
        flow_logs = client.describe_flow_logs()
        for flow_log in flow_logs.get('FlowLogs', []):
            # Cost based on data ingested
            estimated_gb_per_month = 10  # Assume 10GB per month
            monthly_cost = 0.50 * estimated_gb_per_month
            
            services.append({
                'service_id': 'flow_logs',
                'resource_id': flow_log['FlowLogId'],
                'resource_name': flow_log['FlowLogId'],
                'region': region,
                'service_type': 'Networking',
                'estimated_monthly_cost': round(monthly_cost, 2),
                'count': 1,
                'details': {
                    'resource_id': flow_log.get('ResourceId'),
                    'traffic_type': flow_log.get('TrafficType'),
                    'log_destination_type': flow_log.get('LogDestinationType'),
                    'log_destination': flow_log.get('LogDestination'),
                    'log_group_name': flow_log.get('LogGroupName'),
                    'delivery_logs_status': flow_log.get('DeliverLogsStatus'),
                    'max_aggregation_interval': flow_log.get('MaxAggregationInterval'),
                    'tags': flow_log.get('Tags', [])
                },
                'discovered_at': datetime.now(timezone.utc).isoformat()
            })
            
    except Exception as e:
        print(f"Error discovering VPC services in {region}: {str(e)}")
    
    return services