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
]