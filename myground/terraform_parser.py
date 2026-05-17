# terraform_parser.py
import re
import json
from decimal import Decimal

# Complete AWS Service Pricing (hourly rates)
AWS_PRICING = {
    # ============================================================
    # COMPUTE SERVICES
    # ============================================================
    'aws_instance': {
        't2.nano': 0.0058,
        't2.micro': 0.0116,
        't2.small': 0.023,
        't2.medium': 0.0464,
        't2.large': 0.0928,
        't3.nano': 0.0052,
        't3.micro': 0.0104,
        't3.small': 0.0208,
        't3.medium': 0.0416,
        't3.large': 0.0832,
        't3.xlarge': 0.1664,
        't3.2xlarge': 0.3328,
        't4g.nano': 0.0042,
        't4g.micro': 0.0084,
        't4g.small': 0.0168,
        't4g.medium': 0.0336,
        't4g.large': 0.0672,
        'm5.large': 0.096,
        'm5.xlarge': 0.192,
        'm5.2xlarge': 0.384,
        'm5.4xlarge': 0.768,
        'm5.8xlarge': 1.536,
        'm5.12xlarge': 2.304,
        'm5.16xlarge': 3.072,
        'm5.24xlarge': 4.608,
        'm5d.large': 0.113,
        'm5d.xlarge': 0.226,
        'm5d.2xlarge': 0.452,
        'c5.large': 0.085,
        'c5.xlarge': 0.17,
        'c5.2xlarge': 0.34,
        'c5.4xlarge': 0.68,
        'c5.9xlarge': 1.53,
        'c5.12xlarge': 2.04,
        'c5.18xlarge': 3.06,
        'c5.24xlarge': 4.08,
        'c5d.large': 0.096,
        'c5d.xlarge': 0.192,
        'c5d.2xlarge': 0.384,
        'r5.large': 0.126,
        'r5.xlarge': 0.252,
        'r5.2xlarge': 0.504,
        'r5.4xlarge': 1.008,
        'r5.8xlarge': 2.016,
        'r5.12xlarge': 3.024,
        'r5.16xlarge': 4.032,
        'r5.24xlarge': 6.048,
        'r5d.large': 0.144,
        'r5d.xlarge': 0.288,
        'r5d.2xlarge': 0.576,
        'i3.large': 0.156,
        'i3.xlarge': 0.312,
        'i3.2xlarge': 0.624,
        'i3.4xlarge': 1.248,
        'i3.8xlarge': 2.496,
        'i3.16xlarge': 4.992,
        'g4dn.xlarge': 0.526,
        'g4dn.2xlarge': 0.752,
        'g4dn.4xlarge': 1.204,
        'g4dn.8xlarge': 2.176,
        'g4dn.12xlarge': 3.912,
        'g4dn.16xlarge': 5.216,
        'p3.2xlarge': 3.06,
        'p3.8xlarge': 12.24,
        'p3.16xlarge': 24.48,
        'default': 0.05
    },
    'aws_launch_template': {'base': 0.00},  # Free, instances priced separately
    'aws_launch_configuration': {'base': 0.00},  # Free
    'aws_autoscaling_group': {'base': 0.00},  # Free
    
    'aws_lambda_function': {
        'base': 0.0000166667,  # per GB-second
        'default_memory': 128,
        'request_cost': 0.0000002  # per 1 million requests
    },
    'aws_lambda_layer_version': {'base': 0.00},
    'aws_lambda_permission': {'base': 0.00},
    
    'aws_ecs_cluster': {'base': 0.00},  # Free
    'aws_ecs_service': {'base': 0.00},  # Free
    'aws_ecs_task_definition': {'base': 0.00},  # Free
    'aws_ecs_capacity_provider': {'base': 0.00},  # Free
    
    'aws_eks_cluster': 0.10,  # per hour
    'aws_eks_node_group': 0.00,  # Nodes priced separately
    
    'aws_batch_compute_environment': 0.00,
    'aws_batch_job_definition': 0.00,
    'aws_batch_job_queue': 0.00,
    
    'aws_elastic_beanstalk_application': 0.00,
    'aws_elastic_beanstalk_environment': 0.00,  # Resources priced separately
    
    # ============================================================
    # STORAGE SERVICES
    # ============================================================
    'aws_s3_bucket': {
        'standard': 0.023,  # per GB-month
        'standard_ia': 0.0125,
        'onezone_ia': 0.01,
        'intelligent_tiering': 0.023,
        'glacier': 0.004,
        'glacier_deep_archive': 0.00099,
        'default': 0.023
    },
    'aws_s3_bucket_lifecycle_configuration': 0.00,
    'aws_s3_bucket_policy': 0.00,
    'aws_s3_bucket_public_access_block': 0.00,
    'aws_s3_bucket_versioning': 0.00,
    'aws_s3_bucket_server_side_encryption_configuration': 0.00,
    
    'aws_ebs_volume': {
        'gp2': 0.10,  # per GB-month
        'gp3': 0.08,
        'io1': 0.125,
        'io2': 0.125,
        'st1': 0.045,
        'sc1': 0.025,
        'default': 0.10,
        'iops_price': 0.065  # per provisioned IOPS-month for io1/io2
    },
    'aws_ebs_snapshot': 0.05,  # per GB-month
    'aws_ebs_snapshot_copy': 0.05,
    'aws_ebs_encryption_by_default': 0.00,
    
    'aws_efs_file_system': 0.30,  # per GB-month
    'aws_efs_access_point': 0.00,
    'aws_efs_mount_target': 0.00,
    'aws_efs_backup_policy': 0.00,
    
    'aws_fsx_lustre_file_system': 0.24,  # per GB-month
    'aws_fsx_windows_file_system': 0.32,  # per GB-month
    'aws_fsx_ontap_file_system': 0.36,
    'aws_fsx_openzfs_file_system': 0.28,
    
    'aws_backup_plan': 0.00,
    'aws_backup_vault': 0.00,
    'aws_backup_selection': 0.00,
    
    'aws_storagegateway_gateway': 0.125,  # per hour
    'aws_storagegateway_cache': 0.00,
    'aws_storagegateway_upload_buffer': 0.00,
    'aws_storagegateway_working_storage': 0.00,
    
    # ============================================================
    # DATABASE SERVICES
    # ============================================================
    'aws_db_instance': {
        'db.t3.micro': 0.017,
        'db.t3.small': 0.034,
        'db.t3.medium': 0.068,
        'db.t3.large': 0.136,
        'db.t4g.micro': 0.014,
        'db.t4g.small': 0.028,
        'db.t4g.medium': 0.056,
        'db.m5.large': 0.18,
        'db.m5.xlarge': 0.36,
        'db.m5.2xlarge': 0.72,
        'db.m5.4xlarge': 1.44,
        'db.m5.8xlarge': 2.88,
        'db.m5.12xlarge': 4.32,
        'db.m5.16xlarge': 5.76,
        'db.m5.24xlarge': 8.64,
        'db.r5.large': 0.24,
        'db.r5.xlarge': 0.48,
        'db.r5.2xlarge': 0.96,
        'db.r5.4xlarge': 1.92,
        'db.r5.8xlarge': 3.84,
        'db.r5.12xlarge': 5.76,
        'db.r5.16xlarge': 7.68,
        'db.r5.24xlarge': 11.52,
        'db.x2g.large': 0.336,
        'db.x2g.xlarge': 0.672,
        'db.x2g.2xlarge': 1.344,
        'db.x2g.4xlarge': 2.688,
        'db.x2g.8xlarge': 5.376,
        'default': 0.10,
        'storage_price': 0.115,  # per GB-month for gp2
        'backup_price': 0.095,  # per GB-month
        'multi_az_surcharge': 2.0  # Multi-AZ doubles the cost
    },
    'aws_db_subnet_group': 0.00,
    'aws_db_parameter_group': 0.00,
    'aws_db_option_group': 0.00,
    
    'aws_dynamodb_table': {
        'wcu': 0.00065,  # per hour
        'rcu': 0.00013,  # per hour
        'storage': 0.25,  # per GB-month
        'dax': 0.36  # per hour for DAX
    },
    'aws_dynamodb_global_table': 0.00,
    'aws_dynamodb_kinesis_streaming_destination': 0.00,
    
    'aws_elasticache_cluster': {
        'cache.t3.micro': 0.017,
        'cache.t3.small': 0.034,
        'cache.t3.medium': 0.068,
        'cache.m5.large': 0.132,
        'cache.m5.xlarge': 0.264,
        'cache.m5.2xlarge': 0.528,
        'cache.r5.large': 0.18,
        'cache.r5.xlarge': 0.36,
        'cache.r5.2xlarge': 0.72,
        'default': 0.10
    },
    'aws_elasticache_replication_group': 0.00,
    'aws_elasticache_parameter_group': 0.00,
    'aws_elasticache_subnet_group': 0.00,
    
    'aws_redshift_cluster': {
        'dc2.large': 0.25,  # per hour
        'dc2.8xlarge': 2.00,
        'ra3.xlplus': 1.50,
        'ra3.4xlarge': 3.00,
        'ra3.16xlarge': 12.00,
        'default': 0.25,
        'storage_price': 0.024  # per GB-month
    },
    'aws_redshift_subnet_group': 0.00,
    'aws_redshift_parameter_group': 0.00,
    
    'aws_rds_cluster': {
        'aurora': 0.10,  # per hour base
        'aurora_serverless': 0.06,  # per ACU-hour
        'storage_price': 0.10  # per GB-month
    },
    'aws_rds_global_cluster': 0.00,
    
    'aws_docdb_cluster': 0.10,
    'aws_docdb_cluster_instance': 0.10,
    
    'aws_neptune_cluster': 0.10,
    'aws_neptune_cluster_instance': 0.10,
    
    'aws_elasticsearch_domain': {
        't3.small.elasticsearch': 0.032,
        't3.medium.elasticsearch': 0.064,
        'm5.large.elasticsearch': 0.096,
        'm5.xlarge.elasticsearch': 0.192,
        'r5.large.elasticsearch': 0.126,
        'r5.xlarge.elasticsearch': 0.252,
        'default': 0.10,
        'ebs_price': 0.10
    },
    
    'aws_timestreamwrite_database': 0.00,
    'aws_timestreamwrite_table': 0.00,
    
    'aws_keyspaces_table': 0.00,
    
    # ============================================================
    # NETWORKING & CONTENT DELIVERY
    # ============================================================
    'aws_vpc': 0.00,  # Free
    'aws_subnet': 0.00,
    'aws_route_table': 0.00,
    'aws_route': 0.00,
    'aws_network_acl': 0.00,
    'aws_security_group': 0.00,
    'aws_network_interface': 0.00,
    
    'aws_nat_gateway': 0.045,  # per hour
    'aws_vpc_endpoint': 0.01,  # per hour
    'aws_vpc_peering_connection': 0.00,  # Free
    'aws_vpc_peering_connection_accepter': 0.00,
    
    'aws_vpn_gateway': 0.00,  # Free
    'aws_customer_gateway': 0.00,
    'aws_vpn_connection': 0.05,  # per hour
    'aws_vpn_connection_route': 0.00,
    
    'aws_transit_gateway': 0.05,  # per hour
    'aws_transit_gateway_vpc_attachment': 0.05,  # per hour
    'aws_transit_gateway_route_table': 0.00,
    'aws_transit_gateway_route': 0.00,
    'aws_transit_gateway_peering_attachment': 0.05,
    
    'aws_egress_only_internet_gateway': 0.00,
    'aws_internet_gateway': 0.00,
    
    'aws_lb': {
        'application': 0.0225,  # per hour
        'network': 0.0225,
        'gateway': 0.0225,
        'classic': 0.025,
        'default': 0.0225,
        'lcu_price': 0.008  # per LCU-hour
    },
    'aws_alb': 0.0225,
    'aws_elb': 0.025,
    'aws_lb_target_group': 0.00,
    'aws_lb_listener': 0.00,
    'aws_lb_listener_rule': 0.00,
    
    'aws_cloudfront_distribution': 0.00,  # Pay for usage
    'aws_cloudfront_origin_access_identity': 0.00,
    'aws_cloudfront_function': 0.00,
    'aws_cloudfront_response_headers_policy': 0.00,
    'cloudfront_distribution_data_transfer': 0.085,  # per GB
    'cloudfront_http_requests': 0.0075,  # per 10,000 requests
    'cloudfront_https_requests': 0.0100,  # per 10,000 requests
    
    'aws_route53_zone': 0.50,  # per month
    'aws_route53_record': 0.00,
    'aws_route53_health_check': 0.50,  # per month
    'aws_route53_resolver_endpoint': 0.40,  # per hour
    'route53_query_cost': 0.40,  # per million queries
    
    'aws_api_gateway_rest_api': 0.00,  # Pay for usage
    'aws_api_gateway_stage': 0.00,
    'aws_api_gateway_resource': 0.00,
    'aws_api_gateway_method': 0.00,
    'aws_api_gateway_integration': 0.00,
    'aws_api_gateway_deployment': 0.00,
    'aws_api_gateway_authorizer': 0.00,
    'aws_api_gateway_usage_plan': 0.00,
    'aws_api_gateway_api_key': 0.00,
    'api_gateway_rest_cost': 3.50,  # per million requests
    'api_gateway_http_cost': 1.00,  # per million requests
    'api_gateway_websocket_cost': 0.25,  # per million messages
    
    'aws_apigatewayv2_api': 1.00,  # per million requests
    'aws_apigatewayv2_stage': 0.00,
    'aws_apigatewayv2_integration': 0.00,
    'aws_apigatewayv2_route': 0.00,
    
    'aws_appmesh_mesh': 0.00,
    'aws_appmesh_virtual_service': 0.00,
    'aws_appmesh_virtual_node': 0.00,
    'aws_appmesh_virtual_router': 0.00,
    'aws_appmesh_virtual_gateway': 0.00,
    
    'aws_cloud_map_namespace': 0.00,
    'aws_cloud_map_service': 0.00,
    
    'aws_globalaccelerator_accelerator': 0.025,  # per hour
    'aws_globalaccelerator_listener': 0.00,
    'aws_globalaccelerator_endpoint_group': 0.00,
    
    # ============================================================
    # SECURITY, IDENTITY & COMPLIANCE
    # ============================================================
    'aws_iam_user': 0.00,  # Free
    'aws_iam_role': 0.00,
    'aws_iam_policy': 0.00,
    'aws_iam_group': 0.00,
    'aws_iam_instance_profile': 0.00,
    'aws_iam_service_linked_role': 0.00,
    'iam_access_key': 0.00,
    
    'aws_kms_key': 1.00,  # per month
    'aws_kms_alias': 0.00,
    'kms_request_cost': 0.03,  # per 10,000 requests
    
    'aws_secretsmanager_secret': 0.40,  # per month
    'secretsmanager_request_cost': 0.05,  # per 10,000 requests
    
    'aws_cognito_user_pool': 0.00,  # Free tier
    'aws_cognito_user_pool_client': 0.00,
    'aws_cognito_user_pool_domain': 0.00,
    'cognito_mau_cost': 0.0055,  # per monthly active user
    
    'aws_waf_web_acl': 5.00,  # per month
    'aws_waf_rule': 1.00,  # per month
    'aws_waf_ip_set': 0.00,
    'aws_waf_regex_pattern_set': 0.00,
    'waf_request_cost': 0.60,  # per million requests
    
    'aws_wafv2_web_acl': 5.00,
    'aws_wafv2_rule_group': 1.00,
    'aws_wafv2_ip_set': 0.00,
    'aws_wafv2_regex_pattern_set': 0.00,
    
    'aws_shield_protection': 0.00,  # Advanced Shield is $3000/month
    'aws_shield_protection_group': 0.00,
    
    'aws_guardduty_detector': 3.00,  # per month
    'aws_guardduty_member': 0.00,
    'guardduty_cloudtrail': 2.00,  # per month
    'guardduty_s3': 1.00,  # per month
    
    'aws_inspector_assessment_target': 0.00,
    'aws_inspector_assessment_template': 0.00,
    'inspector_run_cost': 0.10,  # per assessment run
    
    'aws_macie2_account': 10.00,  # per month
    'macie2_data_processed': 1.00,  # per GB
    
    # ============================================================
    # MONITORING & LOGGING
    # ============================================================
    'aws_cloudwatch_log_group': 0.00,
    'aws_cloudwatch_log_stream': 0.00,
    'aws_cloudwatch_log_metric_filter': 0.00,
    'aws_cloudwatch_log_destination': 0.00,
    'cloudwatch_log_ingestion': 0.50,  # per GB
    'cloudwatch_log_storage': 0.03,  # per GB-month
    
    'aws_cloudwatch_dashboard': 0.00,
    'aws_cloudwatch_metric_alarm': 0.10,  # per alarm-month
    'aws_cloudwatch_composite_alarm': 0.10,
    'aws_cloudwatch_event_bus': 0.00,
    'aws_cloudwatch_event_rule': 0.00,
    'aws_cloudwatch_event_target': 0.00,
    'cloudwatch_custom_metric': 0.30,  # per metric-month
    
    'aws_sns_topic': 0.00,
    'aws_sns_topic_subscription': 0.00,
    'sns_requests': 0.0000005,  # per request
    'sns_http_notifications': 0.60,  # per million deliveries
    
    'aws_sqs_queue': 0.00,
    'sqs_requests': 0.0000004,  # per request
    
    'aws_kinesis_stream': 0.015,  # per shard-hour
    'aws_kinesis_stream_consumer': 0.015,
    'kinesis_put_payload': 0.014,  # per GB
    'kinesis_extended_retention': 0.10,  # per GB-month for 7-365 days
    
    'aws_kinesis_analytics_application': 0.11,  # per KPU-hour
    'aws_kinesis_firehose_delivery_stream': 0.015,  # per hour
    'firehose_data_ingestion': 0.035,  # per GB
    
    'aws_cloudtrail': 0.00,
    'aws_cloudtrail_event_data_store': 0.00,
    'cloudtrail_management_events': 2.00,  # per 100,000 events
    'cloudtrail_data_events': 0.10,  # per 100,000 events
    
    'aws_xray_sampling_rule': 0.00,
    'xray_trace_storage': 0.50,  # per million traces stored
    'xray_trace_retrieval': 0.50,  # per million traces retrieved
    
    # ============================================================
    # MESSAGING & NOTIFICATIONS
    # ============================================================
    'aws_sqs_queue': 0.00,
    'sqs_standard_requests': 0.0000004,
    'sqs_fifo_requests': 0.0000005,
    
    'aws_sns_topic': 0.00,
    'sns_standard_requests': 0.0000005,
    'sns_fifo_requests': 0.0000005,
    
    'aws_mq_broker': {
        'mq.t3.micro': 0.06,
        'mq.t3.small': 0.12,
        'mq.m5.large': 0.24,
        'mq.m5.xlarge': 0.48,
        'default': 0.06
    },
    
    # ============================================================
    # ANALYTICS
    # ============================================================
    'aws_athena_database': 0.00,
    'aws_athena_workgroup': 0.00,
    'athena_query_cost': 5.00,  # per TB of data scanned
    
    'aws_glue_catalog_database': 0.00,
    'aws_glue_catalog_table': 0.00,
    'aws_glue_job': 0.44,  # per DPU-hour
    'aws_glue_crawler': 0.44,  # per DPU-hour
    'glue_data_catalog': 1.00,  # per million requests
    
    'aws_emr_cluster': {
        'm5.xlarge': 0.192,
        'm5.2xlarge': 0.384,
        'c5.xlarge': 0.17,
        'c5.2xlarge': 0.34,
        'r5.xlarge': 0.252,
        'default': 0.10,
        'emr_upcharge': 0.15  # per EC2 hour
    },
    'aws_emr_security_configuration': 0.00,
    
    'aws_quicksight_user': 3.00,  # per month
    'aws_quicksight_group': 0.00,
    'quicksight_reader': 3.00,
    'quicksight_author': 18.00,
    'quicksight_admin': 24.00,
    
    'aws_msk_cluster': {
        'kafka.m5.large': 0.144,
        'kafka.m5.xlarge': 0.288,
        'kafka.m5.2xlarge': 0.576,
        'kafka.m5.4xlarge': 1.152,
        'kafka.m5.8xlarge': 2.304,
        'kafka.m5.12xlarge': 3.456,
        'kafka.m5.16xlarge': 4.608,
        'kafka.m5.24xlarge': 6.912,
        'storage_price': 0.10  # per GB-month
    },
    
    # ============================================================
    # CONTAINERS
    # ============================================================
    'aws_ecr_repository': 0.00,  # Pay for storage
    'ecr_storage': 0.10,  # per GB-month
    
    'aws_ecs_cluster': 0.00,
    'aws_ecs_service': 0.00,
    'aws_ecs_task_definition': 0.00,
    
    'aws_eks_cluster': 0.10,
    'aws_eks_addon': 0.00,
    'aws_eks_fargate_profile': 0.00,
    
    'aws_eks_node_group': 0.00,  # EC2 instances priced separately
    
    # ============================================================
    # MACHINE LEARNING
    # ============================================================
    'aws_sagemaker_notebook_instance': {
        'ml.t3.medium': 0.05,
        'ml.t3.large': 0.10,
        'ml.m5.large': 0.115,
        'ml.m5.xlarge': 0.23,
        'ml.p3.2xlarge': 3.06,
        'ml.p3.8xlarge': 12.24,
        'default': 0.05
    },
    'aws_sagemaker_endpoint': 0.10,  # per variant-hour
    'aws_sagemaker_endpoint_configuration': 0.00,
    'aws_sagemaker_model': 0.00,
    'aws_sagemaker_code_repository': 0.00,
    'aws_sagemaker_image': 0.00,
    
    'aws_sagemaker_domain': 0.00,
    'aws_sagemaker_user_profile': 0.00,
    
    'aws_sagemaker_feature_group': 0.00,
    
    'aws_rekognition_project': 0.00,
    'rekognition_image_analysis': 0.001,  # per image
    
    'aws_comprehend_entity_recognizer': 0.00,
    'comprehend_native_document': 0.0001,  # per document
    
    'aws_translate': 0.00,
    'translate_text': 0.000015,  # per character
    
    # ============================================================
    # DEVELOPMENT TOOLS
    # ============================================================
    'aws_codecommit_repository': 0.00,  # 5 users free
    'codecommit_git_requests': 0.001,  # per 10 requests
    
    'aws_codepipeline': 1.00,  # per active pipeline-month
    'aws_codepipeline_webhook': 0.00,
    
    'aws_codebuild_project': 0.00,
    'codebuild_build': 0.005,  # per build minute
    
    'aws_codedeploy_app': 0.00,
    'aws_codedeploy_deployment_config': 0.00,
    'aws_codedeploy_deployment_group': 0.00,
    
    'aws_codeartifact_domain': 0.00,
    'aws_codeartifact_repository': 0.00,
    'codeartifact_storage': 0.10,  # per GB-month
    
    'aws_codestar_connections_connection': 0.00,
    'aws_codestar_connections_host': 0.00,
    
    'aws_cloud9_environment_ec2': 0.00,  # EC2 priced separately
    
    # ============================================================
    # MIGRATION & TRANSFER
    # ============================================================
    'aws_dms_replication_instance': {
        'dms.t3.micro': 0.05,
        'dms.t3.small': 0.10,
        'dms.c5.large': 0.15,
        'dms.c5.xlarge': 0.30,
        'default': 0.05
    },
    'aws_dms_replication_task': 0.00,
    'aws_dms_replication_subnet_group': 0.00,
    'aws_dms_endpoint': 0.00,
    
    'aws_datasync_agent': 0.00,
    'aws_datasync_task': 0.00,
    'datasync_scan': 0.005,  # per GB scanned
    'datasync_transfer': 0.0125,  # per GB
    
    'aws_transfer_server': 0.30,  # per hour
    'aws_transfer_user': 0.00,
    'aws_transfer_ssh_key': 0.00,
    
    # ============================================================
    # COST MANAGEMENT
    # ============================================================
    'aws_cur_report_definition': 0.00,
    'cur_data_delivery': 0.00,  # Free for first 100,000 objects
    
    'aws_budgets_budget': 0.00,  # Free for 1 budget
    'additional_budget': 0.02,  # per day
    
    'aws_ce_cost_category': 0.00,
    
    # ============================================================
    # SERVERLESS
    # ============================================================
    'aws_appsync_graphql_api': 0.00,
    'appsync_queries': 4.00,  # per million queries
    'appsync_data_transfer': 0.00,
    
    'aws_stepfunctions_state_machine': 0.00,
    'stepfunctions_execution': 0.025,  # per 1,000 executions
    'stepfunctions_transition': 0.000025,  # per transition
    
    'aws_events_rule': 0.00,
    'events_invocation': 1.00,  # per million invocations
}

class TerraformCostEstimator:
    def __init__(self):
        self.resources = []
        self.total_hourly_cost = 0
        self.total_monthly_cost = 0
    
    def parse_terraform_content(self, content, filename):
        """Parse Terraform content and extract resources"""
        resources = []
        
        # Pattern to match resource blocks
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
        
        matches = re.findall(resource_pattern, content, re.DOTALL)
        
        for match in matches:
            resource_type = match[0]
            resource_name = match[1]
            resource_body = match[2]
            
            # Extract configuration
            config = self._parse_config(resource_body)
            
            resources.append({
                'type': resource_type,
                'name': resource_name,
                'config': config,
                'file': filename
            })
        
        return resources
    
    def _parse_config(self, body):
        """Parse resource configuration block"""
        config = {}
        
        # Match key = "value" patterns
        string_pattern = r'(\w+)\s*=\s*"([^"]*)"'
        string_matches = re.findall(string_pattern, body)
        for key, value in string_matches:
            config[key] = value
        
        # Match key = number patterns
        num_pattern = r'(\w+)\s*=\s*(\d+(?:\.\d+)?)'
        num_matches = re.findall(num_pattern, body)
        for key, value in num_matches:
            if '.' in value:
                config[key] = float(value)
            else:
                config[key] = int(value)
        
        # Match key = boolean patterns
        bool_pattern = r'(\w+)\s*=\s*(true|false)'
        bool_matches = re.findall(bool_pattern, body, re.IGNORECASE)
        for key, value in bool_matches:
            config[key] = value.lower() == 'true'
        
        # Match key = list patterns
        list_pattern = r'(\w+)\s*=\s*\[([^\]]*)\]'
        list_matches = re.findall(list_pattern, body, re.DOTALL)
        for key, value in list_matches:
            items = [item.strip().strip('"') for item in value.split(',') if item.strip()]
            config[key] = items
        
        # Match key = map/object patterns
        map_pattern = r'(\w+)\s*=\s*\{(.*?)\}'
        map_matches = re.findall(map_pattern, body, re.DOTALL)
        for key, value in map_matches:
            config[key] = {'dynamic': True, 'raw': value[:100]}  # Truncated for display
        
        return config
    
    def estimate_resource_cost(self, resource):
        """Estimate cost for a single resource"""
        resource_type = resource['type']
        config = resource['config']
        
        hourly_cost = 0
        monthly_cost = 0
        
        # Look up pricing
        pricing = AWS_PRICING.get(resource_type)
        
        if pricing is None:
            return {'hourly_cost': 0, 'monthly_cost': 0, 'currency': 'USD', 'note': 'Pricing not available'}
        
        # Handle dictionary pricing (multiple options)
        if isinstance(pricing, dict):
            # Check if it's a simple numeric value (like aws_eks_cluster)
            if 'base' in pricing and len(pricing) == 1:
                hourly_cost = pricing['base']
                monthly_cost = hourly_cost * 730
            
            # Check for instance type based pricing
            elif resource_type in ['aws_instance', 'aws_db_instance', 'aws_elasticache_cluster', 
                                   'aws_redshift_cluster', 'aws_elasticsearch_domain', 'aws_mq_broker',
                                   'aws_emr_cluster', 'aws_sagemaker_notebook_instance', 'aws_dms_replication_instance',
                                   'aws_msk_cluster']:
                instance_type = config.get('instance_type', config.get('instance_class', 'default'))
                hourly_cost = pricing.get(instance_type, pricing.get('default', 0.10))
                monthly_cost = hourly_cost * 730
                
                # Add storage costs if applicable
                if 'storage_price' in pricing:
                    allocated_storage = config.get('allocated_storage', 20)
                    monthly_cost += allocated_storage * pricing['storage_price']
                
                # Add Multi-AZ surcharge
                if config.get('multi_az', False) and 'multi_az_surcharge' in pricing:
                    monthly_cost *= pricing['multi_az_surcharge']
            
            # S3 bucket pricing
            elif resource_type == 'aws_s3_bucket':
                storage_class = config.get('storage_class', 'standard').lower()
                price_per_gb = pricing.get(storage_class, pricing.get('default', 0.023))
                estimated_size_gb = int(config.get('estimated_size_gb', 100))
                monthly_cost = estimated_size_gb * price_per_gb
                hourly_cost = monthly_cost / 730
            
            # EBS volume pricing
            elif resource_type == 'aws_ebs_volume':
                size_gb = int(config.get('size', 10))
                volume_type = config.get('type', 'gp2')
                price_per_gb = pricing.get(volume_type, pricing.get('default', 0.10))
                monthly_cost = size_gb * price_per_gb
                
                # Add IOPS cost for io1/io2
                if volume_type in ['io1', 'io2'] and 'iops_price' in pricing:
                    iops = int(config.get('iops', 100))
                    monthly_cost += iops * pricing['iops_price']
                
                hourly_cost = monthly_cost / 730
            
            # Lambda pricing
            elif resource_type == 'aws_lambda_function':
                memory = config.get('memory_size', pricing.get('default_memory', 128))
                # Assume 1 million invocations per month for estimation
                compute_cost = (memory / 1024) * pricing.get('base', 0.0000166667) * 1000000
                request_cost = pricing.get('request_cost', 0.0000002) * 1000000
                monthly_cost = compute_cost + request_cost
                hourly_cost = monthly_cost / 730
            
            # EFS pricing
            elif resource_type == 'aws_efs_file_system':
                estimated_size_gb = int(config.get('estimated_size_gb', 100))
                monthly_cost = estimated_size_gb * pricing
                hourly_cost = monthly_cost / 730
            
            # NAT Gateway pricing
            elif resource_type == 'aws_nat_gateway':
                hourly_cost = pricing
                monthly_cost = hourly_cost * 730
            
            # Load balancer pricing
            elif resource_type in ['aws_lb', 'aws_alb', 'aws_elb']:
                lb_type = config.get('load_balancer_type', 'application')
                hourly_cost = pricing.get(lb_type, pricing.get('default', 0.0225))
                monthly_cost = hourly_cost * 730
                
                # Add LCU cost for ALB/NLB
                if 'lcu_price' in pricing:
                    estimated_lcus = config.get('estimated_lcus', 2)
                    monthly_cost += estimated_lcus * pricing['lcu_price'] * 730
            
            # API Gateway pricing
            # terraform_parser.py - Update the API Gateway pricing section

            elif resource_type in ['aws_api_gateway_rest_api', 'aws_apigatewayv2_api']:
                # Check if it's HTTP API (v2) or REST API (v1)
                is_http_api = resource_type == 'aws_apigatewayv2_api'
                
                # Get estimated requests from config or use realistic default
                estimated_requests = config.get('estimated_requests_per_month', 1000000)  # Default 1M
                
                # Apply free tier
                free_tier = 1000000  # 1 million requests free
                billable_requests = max(0, estimated_requests - free_tier)
                
                if is_http_api:
                    # HTTP API: $1.00 per million requests after free tier
                    monthly_cost = (billable_requests / 1000000) * 1.00
                else:
                    # REST API: $3.50 per million requests after free tier
                    monthly_cost = (billable_requests / 1000000) * 3.50
                
                # Additional: Data transfer (~$0.09 per GB)
                # Assuming 1KB per request average
                data_transfer_gb = (estimated_requests * 0.001) / 1024  # Convert KB to GB
                data_cost = data_transfer_gb * 0.09
                
                monthly_cost += data_cost
                hourly_cost = monthly_cost / 730
                        
                # Route53 pricing
            elif resource_type == 'aws_route53_zone':
                monthly_cost = pricing
                hourly_cost = monthly_cost / 730
        
            # CloudFront pricing
            elif resource_type == 'aws_cloudfront_distribution':
                # Assume 100 GB data transfer and 100,000 requests
                data_transfer_cost = 100 * pricing.get('cloudfront_distribution_data_transfer', 0.085)
                request_cost = 0.01 * pricing.get('cloudfront_http_requests', 0.0075)
                monthly_cost = data_transfer_cost + request_cost
                hourly_cost = monthly_cost / 730
            
            # EKS pricing
            elif resource_type == 'aws_eks_cluster':
                hourly_cost = pricing
                monthly_cost = hourly_cost * 730
            
            # RDS/Aurora cluster pricing
            elif resource_type == 'aws_rds_cluster':
                engine = config.get('engine', 'aurora')
                if engine == 'aurora_serverless':
                    estimated_acus = config.get('estimated_acus', 1)
                    hourly_cost = pricing.get('aurora_serverless', 0.06) * estimated_acus
                else:
                    hourly_cost = pricing.get('aurora', 0.10)
                monthly_cost = hourly_cost * 730
                
                if 'storage_price' in pricing:
                    allocated_storage = config.get('allocated_storage', 100)
                    monthly_cost += allocated_storage * pricing['storage_price']
            
            # Default handling for other services
            else:
                # Try to get a numeric value
                if isinstance(pricing, (int, float)):
                    hourly_cost = pricing
                    monthly_cost = hourly_cost * 730
                else:
                    hourly_cost = 0
                    monthly_cost = 0
        
        # Handle simple numeric pricing
        elif isinstance(pricing, (int, float)):
            hourly_cost = pricing
            monthly_cost = hourly_cost * 730
        
        return {
            'hourly_cost': round(hourly_cost, 4),
            'monthly_cost': round(monthly_cost, 2),
            'currency': 'USD'
        }
    
    def analyze_repository(self, repo, github_service):
        """Analyze a GitHub repository for Terraform files"""
        owner, repo_name = repo.repo_full_name.split('/')
        
        # Get repository contents
        contents = github_service.get_repo_contents(owner, repo_name)
        
        terraform_files = []
        
        # Recursively find .tf files
        def find_tf_files(items, path=""):
            if not items:
                return
            for item in items:
                if item.get('type') == 'file' and item.get('name', '').endswith('.tf'):
                    # Get file content
                    file_content = github_service.get_file_content(owner, repo_name, item.get('path', ''))
                    if file_content:
                        terraform_files.append({
                            'path': item.get('path'),
                            'name': item.get('name'),
                            'content': file_content
                        })
                elif item.get('type') == 'dir':
                    sub_contents = github_service.get_repo_contents(owner, repo_name, item.get('path', ''))
                    if sub_contents:
                        find_tf_files(sub_contents, item.get('path', ''))
        
        if contents:
            find_tf_files(contents)
        
        # Parse Terraform files and estimate costs
        all_resources = []
        total_hourly = 0
        total_monthly = 0
        
        for tf_file in terraform_files:
            resources = self.parse_terraform_content(tf_file['content'], tf_file['path'])
            
            for resource in resources:
                cost = self.estimate_resource_cost(resource)
                resource['estimated_cost'] = cost
                all_resources.append(resource)
                total_hourly += cost['hourly_cost']
                total_monthly += cost['monthly_cost']
        
        return {
            'repository_name': repo.repo_full_name,
            'repository_id': repo.id,
            'terraform_files': len(terraform_files),
            'resources_found': len(all_resources),
            'resources': all_resources,
            'total_hourly_cost': round(total_hourly, 2),
            'total_monthly_cost': round(total_monthly, 2),
            'currency': 'USD'
        }