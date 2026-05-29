from django.urls import path
from . import views

urlpatterns = [
    path('iam/scan/<int:account_id>/', views.scan_iam_security_view, name='scan_iam'),
    path('iam/findings/<int:account_id>/', views.get_iam_findings, name='get_iam_findings'),
    path('iam/clear/<int:account_id>/', views.clear_iam_findings, name='clear_iam_findings'),

   # path('iam/resolve/<int:finding_id>/', views.resolve_iam_finding, name='resolve_iam_finding'),
    path('exposure/scan/<int:account_id>/', views.scan_public_exposure_view, name='scan_public_exposure'),
    path('exposure/findings/<int:account_id>/', views.get_public_exposure_findings, name='get_public_exposure_findings'),
    path('exposure/clear/<int:account_id>/', views.clear_public_exposure_findings, name='clear_public_exposure_findings'),
    path('exposure/resolve/<int:finding_id>/', views.resolve_public_exposure_finding, name='resolve_public_exposure_finding'),
        # Security Group Analyzer URLs
    
    path('security-groups/scan/<int:account_id>/', views.scan_security_groups, name='scan_security_groups'),
    path('security-groups/list/<int:account_id>/', views.get_security_groups_list, name='get_security_groups_list'),
    path('security-groups/detail/<int:account_id>/<str:sg_id>/', views.get_security_group_detail_view, name='get_security_group_detail'),
    path('security-groups/clear/<int:account_id>/', views.clear_security_groups_cache, name='clear_security_groups_cache'),

       # Encryption Checker URLs
    path('encryption/scan/<int:account_id>/', views.scan_encryption_status_view, name='scan_encryption'),
    path('encryption/summary/<int:account_id>/', views.get_encryption_summary_view, name='encryption_summary'),
    path('encryption/findings/<int:account_id>/', views.get_encryption_findings_view, name='encryption_findings'),
    path('encryption/clear/<int:account_id>/', views.clear_encryption_cache, name='clear_encryption_cache'),
     path('encryption/action/create/<int:account_id>/', views.create_encryption_action, name='create_encryption_action'),
    path('encryption/action/status/<int:account_id>/<int:action_id>/', views.get_encryption_action_status, name='encryption_action_status'),
    
    # AI Recommendation URLs
    path('encryption/recommendations/generate/<int:account_id>/', views.generate_encryption_recommendations, name='generate_encryption_recommendations'),
    path('encryption/recommendations/list/<int:account_id>/', views.get_encryption_recommendations, name='get_encryption_recommendations'),
]