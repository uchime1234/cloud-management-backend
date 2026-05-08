# discovery/waf_discovery.py
import boto3
from datetime import datetime
from datetime import timezone
# and then using:
timezone.utc

def discover_waf_services(creds, region):
    """Discover WAF v2 web ACLs, rule groups, and IPSets"""
    services = []
    try:
        # WAF v2
        client = boto3.client(
            'wafv2',
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
        
        # ========== WEB ACLS ==========
        for scope in ['REGIONAL', 'CLOUDFRONT']:
            try:
                web_acls = client.list_web_acls(Scope=scope)
                for acl in web_acls.get('WebACLs', []):
                    acl_name = acl['Name']
                    acl_id = acl['Id']
                    acl_arn = acl['ARN']
                    
                    # Get detailed info
                    try:
                        details = client.get_web_acl(Name=acl_name, Id=acl_id, Scope=scope)
                        web_acl = details['WebACL']
                        
                        # WAF pricing: $5 per web ACL per month
                        monthly_base_cost = 5.00
                        
                        # $1 per rule per month
                        rule_count = len(web_acl.get('Rules', []))
                        monthly_rule_cost = rule_count * 1.00
                        
                        # Bot Control: $10 per ACL per month
                        has_bot_control = any(
                            rule.get('Name', '').startswith('AWS-AWSBotControl') or
                            'BotControl' in rule.get('Name', '')
                            for rule in web_acl.get('Rules', [])
                        )
                        bot_control_cost = 10.00 if has_bot_control else 0.00
                        
                        total_monthly_cost = monthly_base_cost + monthly_rule_cost + bot_control_cost
                        
                        services.append({
                            'service_id': 'waf_acl',
                            'resource_id': acl_arn,
                            'resource_name': acl_name,
                            'region': region if scope == 'REGIONAL' else 'global',
                            'service_type': 'Security',
                            'estimated_monthly_cost': round(total_monthly_cost, 2),
                'count': 1,
                            'details': {
                                'web_acl_id': acl_id,
                                'web_acl_arn': acl_arn,
                                'name': acl_name,
                                'scope': scope,
                                'description': web_acl.get('Description'),
                                'capacity': web_acl.get('Capacity'),
                                'rules': [
                                    {
                                        'name': rule.get('Name'),
                                        'priority': rule.get('Priority'),
                                        'action': rule.get('Action', {}),
                                        'statement': rule.get('Statement', {}),
                                        'visibility_config': rule.get('VisibilityConfig', {})
                                    }
                                    for rule in web_acl.get('Rules', [])
                                ],
                                'default_action': web_acl.get('DefaultAction', {}),
                                'visibility_config': web_acl.get('VisibilityConfig', {}),
                                'association_count': get_web_acl_associations(client, acl_arn, scope),
                                'tags': get_waf_tags(client, acl_arn)
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                        
                        # ========== CAPTCHA CONFIG ==========
                        captcha_config = web_acl.get('CaptchaConfig', {})
                        if captcha_config:
                            services.append({
                                'service_id': 'waf_captcha',
                                'resource_id': f"{acl_arn}/captcha",
                                'resource_name': f"{acl_name} CAPTCHA",
                                'region': region if scope == 'REGIONAL' else 'global',
                                'service_type': 'Security',
                                'estimated_monthly_cost': 0.00,
                'count': 1,  # $0.40 per 1000 requests
                                'details': {
                                    'web_acl_arn': acl_arn,
                                    'immunity_time_property': captcha_config.get('ImmunityTimeProperty', {})
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                        
                    except Exception as e:
                        print(f"Error describing WAF ACL {acl_name}: {str(e)}")
            except:
                pass
        
        # ========== RULE GROUPS ==========
        for scope in ['REGIONAL', 'CLOUDFRONT']:
            try:
                rule_groups = client.list_rule_groups(Scope=scope)
                for rg in rule_groups.get('RuleGroups', []):
                    rg_name = rg['Name']
                    rg_id = rg['Id']
                    rg_arn = rg['ARN']
                    
                    try:
                        details = client.get_rule_group(Name=rg_name, Id=rg_id, Scope=scope)
                        rule_group = details['RuleGroup']
                        
                        # $1 per rule per month, minimum $5 per rule group
                        rule_count = len(rule_group.get('Rules', []))
                        monthly_cost = max(5.00, rule_count * 1.00)
                        
                        services.append({
                            'service_id': 'waf_rule_group',
                            'resource_id': rg_arn,
                            'resource_name': rg_name,
                            'region': region if scope == 'REGIONAL' else 'global',
                            'service_type': 'Security',
                            'estimated_monthly_cost': monthly_cost,
                            'details': {
                                'rule_group_id': rg_id,
                                'rule_group_arn': rg_arn,
                                'name': rg_name,
                                'scope': scope,
                                'description': rule_group.get('Description'),
                                'capacity': rule_group.get('Capacity'),
                                'rules': [
                                    {
                                        'name': rule.get('Name'),
                                        'priority': rule.get('Priority'),
                                        'action': rule.get('Action', {}),
                                        'statement': rule.get('Statement', {})
                                    }
                                    for rule in rule_group.get('Rules', [])
                                ],
                                'visibility_config': rule_group.get('VisibilityConfig', {}),
                                'tags': get_waf_tags(client, rg_arn)
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                    except:
                        pass
            except:
                pass
        
        # ========== IP SETS ==========
        for scope in ['REGIONAL', 'CLOUDFRONT']:
            try:
                ip_sets = client.list_ip_sets(Scope=scope)
                for ip_set in ip_sets.get('IPSets', []):
                    ip_set_name = ip_set['Name']
                    ip_set_id = ip_set['Id']
                    ip_set_arn = ip_set['ARN']
                    
                    try:
                        details = client.get_ip_set(Name=ip_set_name, Id=ip_set_id, Scope=scope)
                        ip_set_details = details['IPSet']
                        
                        # $1 per IP set per month
                        monthly_cost = 1.00
                        
                        services.append({
                            'service_id': 'waf_ip_set',
                            'resource_id': ip_set_arn,
                            'resource_name': ip_set_name,
                            'region': region if scope == 'REGIONAL' else 'global',
                            'service_type': 'Security',
                            'estimated_monthly_cost': monthly_cost,
                            'details': {
                                'ip_set_id': ip_set_id,
                                'ip_set_arn': ip_set_arn,
                                'name': ip_set_name,
                                'scope': scope,
                                'description': ip_set_details.get('Description'),
                                'ip_address_version': ip_set_details.get('IPAddressVersion'),
                                'addresses': ip_set_details.get('Addresses', [])[:10],  # First 10 only
                                'address_count': len(ip_set_details.get('Addresses', [])),
                                'tags': get_waf_tags(client, ip_set_arn)
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                    except:
                        pass
            except:
                pass
        
        # ========== REGEX PATTERN SETS ==========
        for scope in ['REGIONAL', 'CLOUDFRONT']:
            try:
                regex_sets = client.list_regex_pattern_sets(Scope=scope)
                for regex_set in regex_sets.get('RegexPatternSets', []):
                    regex_name = regex_set['Name']
                    regex_id = regex_set['Id']
                    regex_arn = regex_set['ARN']
                    
                    try:
                        details = client.get_regex_pattern_set(Name=regex_name, Id=regex_id, Scope=scope)
                        regex_details = details['RegexPatternSet']
                        
                        # $1 per regex set per month
                        monthly_cost = 1.00
                        
                        services.append({
                            'service_id': 'waf_regex_set',
                            'resource_id': regex_arn,
                            'resource_name': regex_name,
                            'region': region if scope == 'REGIONAL' else 'global',
                            'service_type': 'Security',
                            'estimated_monthly_cost': monthly_cost,
                            'details': {
                                'regex_pattern_set_id': regex_id,
                                'regex_pattern_set_arn': regex_arn,
                                'name': regex_name,
                                'scope': scope,
                                'description': regex_details.get('Description'),
                                'regular_expressions': regex_details.get('RegularExpressionList', [])[:10],  # First 10 only
                                'regex_count': len(regex_details.get('RegularExpressionList', [])),
                                'tags': get_waf_tags(client, regex_arn)
                            },
                            'discovered_at': datetime.now(timezone.utc).isoformat()
                        })
                    except:
                        pass
            except:
                pass
        
        # ========== MANAGED RULE GROUPS ==========
        try:
            managed_rule_groups = client.list_available_managed_rule_groups(Scope='REGIONAL')
            for mrg in managed_rule_groups.get('ManagedRuleGroups', []):
                services.append({
                    'service_id': 'waf_managed_rule_group',
                    'resource_id': mrg.get('VendorName', 'AWS') + '/' + mrg['Name'],
                    'resource_name': mrg['Name'],
                    'region': region,
                    'service_type': 'Security',
                    'estimated_monthly_cost': 0.00,
                'count': 1,  # Cost when used in ACL
                    'details': {
                        'vendor_name': mrg.get('VendorName'),
                        'name': mrg['Name'],
                        'description': mrg.get('Description'),
                        'versioning_supported': mrg.get('VersioningSupported', False)
                    },
                    'discovered_at': datetime.now(timezone.utc).isoformat()
                })
        except:
            pass
        
        # ========== WAF LOGGING CONFIGURATIONS ==========
        for scope in ['REGIONAL', 'CLOUDFRONT']:
            try:
                web_acls = client.list_web_acls(Scope=scope)
                for acl in web_acls.get('WebACLs', []):
                    try:
                        logging = client.get_logging_configuration(ResourceArn=acl['ARN'])
                        if 'LoggingConfiguration' in logging:
                            log_config = logging['LoggingConfiguration']
                            
                            services.append({
                                'service_id': 'waf_logging',
                                'resource_id': f"{acl['ARN']}/logging",
                                'resource_name': f"{acl['Name']} Logging",
                                'region': region if scope == 'REGIONAL' else 'global',
                                'service_type': 'Security',
                                'estimated_monthly_cost': 0.00,
                'count': 1,  # $1 per GB
                                'details': {
                                    'web_acl_arn': acl['ARN'],
                                    'log_destination_configs': log_config.get('LogDestinationConfigs', []),
                                    'redacted_fields': log_config.get('RedactedFields', []),
                                    'logging_filter': log_config.get('LoggingFilter', {}),
                                    'managed_by_firewall_manager': log_config.get('ManagedByFirewallManager', False)
                                },
                                'discovered_at': datetime.now(timezone.utc).isoformat()
                            })
                    except:
                        pass
            except:
                pass
        
    except Exception as e:
        print(f"Error discovering WAF services in {region}: {str(e)}")
    
    return services

def get_waf_tags(client, resource_arn):
    """Get tags for WAF resource"""
    try:
        response = client.list_tags_for_resource(ResourceARN=resource_arn)
        return response.get('TagInfoForResource', {}).get('TagList', [])
    except:
        return []

def get_web_acl_associations(client, web_acl_arn, scope):
    """Get number of associations for a Web ACL"""
    try:
        response = client.list_resources_for_web_acl(WebACLArn=web_acl_arn, ResourceType='APPLICATION_LOAD_BALANCER')
        return len(response.get('ResourceArns', []))
    except:
        return 0