# urls.py - Add these new endpoints

from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    
    # MFA endpoints
    path('mfa/setup-token/', views.mfa_setup_init_token, name='mfa_setup_token'),
    path('mfa/enable-token/', views.mfa_enable_token, name='mfa_enable_token'),
    path('mfa/setup/', views.mfa_setup_init, name='mfa_setup'),
    path('mfa/enable/', views.mfa_enable, name='mfa_enable'),
    path('mfa/verify/', views.mfa_verify, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable, name='mfa_disable'),
    path('mfa/status/', views.mfa_status, name='mfa_status'),
    path('mfa/regenerate-backup/', views.regenerate_backup_codes, name='regenerate_backup'),
    
    # Password reset
    path('password-reset/request/', views.password_reset_request, name='password_reset_request'),
    path('password-reset/verify/', views.password_reset_verify, name='password_reset_verify'),
    path('password-reset/confirm/', views.password_reset_confirm, name='password_reset_confirm'),
    
    # AWS endpoints
    path('aws/setup/', views.generate_external_id, name='aws_generate_external_id'),
    path('aws/connect/', views.connect_aws_account, name='aws_connect'),
    path('aws/accounts/', views.list_aws_accounts, name='aws_list_accounts'),
    path('aws/accounts/<int:account_db_id>/disconnect/', views.disconnect_aws_account, name='aws_disconnect'),
    path('aws/accounts/<int:account_db_id>/dashboard-data/', views.get_cost_dashboard_data, name='aws_dashboard_data'),
    path('aws/accounts/<int:account_db_id>/clear-cache/', views.clear_cost_cache, name='aws_clear_cache'),
    path('aws/accounts/<int:account_db_id>/cache-status/', views.get_cache_status, name='aws_cache_status'),
    path('aws/accounts/<int:account_db_id>/ai-analysis/', views.generate_ai_cost_analysis, name='generate_ai_analysis'),
    path('aws/accounts/<int:account_db_id>/cached-analysis/', views.get_cached_ai_analysis, name='get_cached_analysis'),
    path('aws/accounts/<int:account_db_id>/low-level-costs/', views.get_low_level_cost_breakdown, name='low_level_costs'),
    path('accounts/login/', views.login_user, name='login'),  # This uses your existing view
    path('accounts/logout/', views.logout_user, name='logout'), 
    # NEW: Enhanced AWS analytics endpoints
    path('aws/accounts/<int:account_db_id>/analytics/', views.get_cost_analytics, name='cost_analytics'),
    path('aws/accounts/<int:account_db_id>/sync/', views.sync_aws_data, name='sync_aws_data'),
    path('aws/accounts/<int:account_db_id>/clear-data/', views.clear_aws_data, name='clear_aws_data'),
    
    # Low-level services endpoints
    path('api/aws/accounts/<int:account_id>/low-level-services-fast/', views.get_low_level_services_fast, name='low_level_services_fast'),
    path('api/aws/accounts/<int:account_id>/low-level-services-refresh/', views.refresh_low_level_services, name='low_level_services_refresh'),
    path('api/aws/accounts/<int:account_id>/low-level-services-summary/', views.get_low_level_services_summary, name='low_level_services_summary'),
    
    # Resources endpoints
    path('resources/<int:account_id>/resource_summary/', views.get_resource_summary, name='resource_summary'),
    path('resources/<int:account_id>/paid-resources/', views.get_paid_resources, name='paid_resources'),
    path('resources/<int:account_id>/cost-analysis/', views.get_cost_analysis, name='cost_analysis'),
    
    # GitHub endpoints
    path('github/auth-url/', views.github_auth_url, name='github_auth_url'),
    path('github/callback/', views.github_callback, name='github_callback'),
    path('github/repos/', views.list_github_repos, name='list_github_repos'),
    path('github/connect-legacy/', views.connect_github_repo_legacy, name='connect_github_repo_legacy'),
    path('github/connect/', views.connect_github_repo, name='connect_github_repo'),
    path('github/connected/', views.list_connected_repos, name='list_connected_repos'),
    path('github/repos/<int:repo_id>/disconnect/', views.disconnect_github_repo, name='disconnect_github_repo'),
    path('github/repos/<int:repo_id>/deployments/', views.list_deployments, name='list_deployments'),
    path('github/webhook/', views.github_webhook, name='github_webhook'),
    path('github/status/', views.github_status, name='github_status'),
    #path('github/scan/start/', views.start_github_scan, name='start_github_scan'),
   # path('github/scan/status/<str:scan_id>/', views.get_scan_status, name='get_scan_status'),
    path('github/test-terraform/<str:owner>/<str:repo>/', views.test_terraform_detection, name='test_terraform'),
    path('github/scan/start-manual/', views.start_github_scan_manual, name='start_github_scan_manual'),
    #path('github/scan/status/<str:scan_id>/', views.get_scan_status, name='get_scan_status'),
    # Cost spike and deployment correlation
    # In urls.py, add:
    path('github/analyze-terraform-costs/', views.analyze_terraform_costs, name='analyze_terraform_costs'),
    path('github/scan/status/<str:scan_id>/', views.get_scan_status_manual, name='get_scan_status_manual'),
    path('aws/accounts/<int:account_db_id>/cost-spikes/', views.list_cost_spikes, name='cost_spikes'),
    path('aws/accounts/<int:account_db_id>/deployment-correlation/', views.get_deployment_correlation, name='deployment_correlation'),
    path('aws/accounts/<int:account_db_id>/forecast/', views.get_cost_forecast, name='cost_forecast'),
    path('aws/accounts/<int:account_db_id>/forecast/service/<str:service_name>/', views.get_service_forecast_detail, name='service_forecast_detail'),
    

# Storage Optimization URLs
# Add these to your urlpatterns in urls.py

# Storage Optimization Views (Simple)
path('storage-scan/ebs/<int:account_id>/', views.scan_ebs_volumes_view, name='scan_ebs'),
path('storage-scan/elastic-ips/<int:account_id>/', views.scan_elastic_ips_view, name='scan_elastic_ips'),
path('storage-scan/rds/<int:account_id>/', views.scan_rds_instances_view, name='scan_rds'),
path('storage-scan/snapshots/<int:account_id>/', views.scan_snapshots_view, name='scan_snapshots'),
path('storage-scan/unattached-ebs/<int:account_id>/', views.scan_unattached_ebs_volumes, name='scan_unattached_ebs'),
path('storage-scan/duplicate-snapshots/<int:account_id>/', views.scan_duplicate_snapshots, name='scan_duplicate_snapshots'),
path('storage-scan/idle-rds/<int:account_id>/', views.scan_idle_rds_instances, name='scan_idle_rds'),
path('storage-scan/unused-amis/<int:account_id>/', views.scan_unused_amis, name='scan_unused_amis'),
path('storage-scan/complete/<int:account_id>/', views.run_complete_storage_scan, name='scan_complete'),
path('storage/findings/<int:account_id>/', views.get_storage_findings, name='storage_findings'),
path('storage/dismiss/<str:finding_id>/', views.dismiss_storage_finding, name='dismiss_finding'),

################ Idle Resources ############################
# Idle Ec2 endpoint
path('idle-ec2/scan/<int:account_id>/', views.scan_idle_ec2_instances, name='scan_idle_ec2'),
path('idle-ec2/list/<int:account_id>/', views.get_idle_ec2_instances, name='list_idle_ec2'),
# Idle Auto Scaling Group endpoints
path('idle-asg/scan/<int:account_id>/', views.scan_idle_asg, name='scan_idle_asg'),
path('idle-asg/list/<int:account_id>/', views.get_idle_asg, name='list_idle_asg'),
path('idle-asg/resolve/<int:asg_id>/', views.resolve_idle_asg, name='resolve_idle_asg'),
# Idle Load Balancer endpoints
path('idle-lb/scan/<int:account_id>/', views.scan_idle_load_balancers, name='scan_idle_lb'),
path('idle-lb/list/<int:account_id>/', views.get_idle_load_balancers, name='list_idle_lb'),
path('idle-lb/resolve/<int:lb_id>/', views.resolve_idle_lb, name='resolve_idle_lb'),
# Idle Lambda endpoints
path('idle-lambda/scan/<int:account_id>/', views.scan_idle_lambda_functions, name='scan_idle_lambda'),
path('idle-lambda/list/<int:account_id>/', views.get_idle_lambda_functions, name='list_idle_lambda'),
path('idle-lambda/resolve/<int:lambda_id>/', views.resolve_idle_lambda, name='resolve_idle_lambda'),

# Scan all idle resources
path('idle-resources/scan/<int:account_id>/', views.scan_all_idle_resources, name='scan_all_idle'),

# Idle ECS endpoints
path('idle-ecs/scan/<int:account_id>/', views.scan_idle_ecs_services, name='scan_idle_ecs'),
path('idle-ecs/list/<int:account_id>/', views.get_idle_ecs_services, name='list_idle_ecs'),
path('idle-ecs/resolve/<int:service_id>/', views.resolve_idle_ecs_service, name='resolve_idle_ecs'),

# Idle NAT Gateway endpoints
path('idle-nat/scan/<int:account_id>/', views.scan_idle_nat_gateways, name='scan_idle_nat'),
path('idle-nat/list/<int:account_id>/', views.get_idle_nat_gateways, name='list_idle_nat'),
path('idle-nat/resolve/<int:nat_id>/', views.resolve_idle_nat_gateway, name='resolve_idle_nat'),

# Idle VPC Endpoint endpoints
path('idle-vpce/scan/<int:account_id>/', views.scan_idle_vpc_endpoints, name='scan_idle_vpce'),
path('idle-vpce/list/<int:account_id>/', views.get_idle_vpc_endpoints, name='list_idle_vpce'),
path('idle-vpce/resolve/<int:endpoint_id>/', views.resolve_idle_vpc_endpoint, name='resolve_idle_vpce'),

# Scan all idle resources
path('idle-resources/advanced-scan/<int:account_id>/', views.scan_all_idle_resources_advanced, name='scan_all_idle_advanced'),
path('idle-resources/clear/<int:account_id>/', views.clear_idle_results_cache, name='clear_idle_cache'),

path('aws/accounts/<int:account_db_id>/ai-low-level-recommendations/', views.generate_low_level_ai_recommendations, name='ai_low_level_recommendations'),
path('aws/accounts/<int:account_db_id>/ai-low-level-recommendations-cached/', views.get_low_level_ai_recommendations_cached, name='ai_low_level_recommendations_cached'),
path('storage-clear/<int:account_id>/', views.clear_storage_cache, name='clear_storage_cache'),


# Add to urlpatterns
path('aws/accounts/<int:account_db_id>/service-breakdown-db/', views.get_service_breakdown_from_db, name='service_breakdown_db'),
path('idle-resources/clear/<int:account_id>/', views.clear_idle_results_cache, name='clear_idle_cache'),
]
