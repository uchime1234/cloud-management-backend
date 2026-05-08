from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
import logging

from myground.models import AWSAccount
from .models import IAMFinding, IAMSecurityReport
from .serlizers import IAMFindingSerializer
from .iam_scanner import scan_iam_security

logger = logging.getLogger(__name__)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_iam_security_view(request, account_id):
    """
    Scan IAM security for an AWS account
    Automatically generates and caches AI recommendations
    """
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        force_refresh = request.query_params.get('force_refresh', 'false').lower() == 'true'
        
        # Check for cached results (forever until deleted)
        if not force_refresh:
            cached_findings = IAMFinding.objects.filter(
                aws_account=account,
                is_resolved=False
            )
            
            cached_report = IAMSecurityReport.objects.filter(aws_account=account).first()
            
            if cached_findings.exists() and cached_report:
                serializer = IAMFindingSerializer(cached_findings, many=True)
                return Response({
                    'success': True,
                    'cached': True,
                    'total_findings': cached_findings.count(),
                    'findings': serializer.data,
                    'ai_recommendations': cached_report.ai_recommendations,
                    'report_summary': {
                        'critical': cached_report.critical_count,
                        'high': cached_report.high_count,
                        'medium': cached_report.medium_count,
                        'low': cached_report.low_count,
                        'generated_at': cached_report.created_at
                    }
                }, status=200)
        
        # Delete old findings and report for this account
        IAMFinding.objects.filter(aws_account=account).delete()
        IAMSecurityReport.objects.filter(aws_account=account).delete()
        
        # Run fresh scan (this now includes AI recommendations automatically)
        scan_result = scan_iam_security(
            account.role_arn, 
            str(account.external_id),
            account.account_alias or account.account_id
        )
        
        if scan_result.get('error'):
            return Response({
                'success': False,
                'error': scan_result['error']
            }, status=500)
        
        # Save findings to database
        saved_findings = []
        for finding_data in scan_result['findings']:
            finding = IAMFinding.objects.create(
                user=request.user,
                aws_account=account,
                finding_type=finding_data['finding_type'],
                severity=finding_data['severity'],
                resource_name=finding_data['resource_name'],
                title=finding_data['title'],
                description=finding_data['description'],
                recommendation=finding_data['recommendation'],
                metadata=finding_data.get('metadata', {})
            )
            saved_findings.append(finding)
        
        # Count by severity
        critical_count = len([f for f in scan_result['findings'] if f['severity'] == 'critical'])
        high_count = len([f for f in scan_result['findings'] if f['severity'] == 'high'])
        medium_count = len([f for f in scan_result['findings'] if f['severity'] == 'medium'])
        low_count = len([f for f in scan_result['findings'] if f['severity'] == 'low'])
        
        # Save AI recommendations report
        report = IAMSecurityReport.objects.create(
            user=request.user,
            aws_account=account,
            ai_recommendations=scan_result['ai_recommendations'],
            total_findings=len(saved_findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count
        )
        
        serializer = IAMFindingSerializer(saved_findings, many=True)
        
        return Response({
            'success': True,
            'cached': False,
            'total_findings': len(saved_findings),
            'findings': serializer.data,
            'ai_recommendations': scan_result['ai_recommendations'],
            'report_summary': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'generated_at': report.created_at
            }
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error scanning IAM security: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_iam_findings(request, account_id):
    """Get cached IAM findings and AI recommendations from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        findings = IAMFinding.objects.filter(
            aws_account=account,
            is_resolved=False
        ).order_by('-severity', '-detected_at')
        
        report = IAMSecurityReport.objects.filter(aws_account=account).first()
        
        # Count by severity
        critical = findings.filter(severity='critical').count()
        high = findings.filter(severity='high').count()
        medium = findings.filter(severity='medium').count()
        low = findings.filter(severity='low').count()
        
        serializer = IAMFindingSerializer(findings, many=True)
        
        return Response({
            'success': True,
            'cached': True,
            'total_findings': findings.count(),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'findings': serializer.data,
            'ai_recommendations': report.ai_recommendations if report else None,
            'report_summary': {
                'generated_at': report.created_at if report else None
            }
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_iam_findings(request, account_id):
    """Clear all cached IAM findings and AI recommendations"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        findings_deleted, _ = IAMFinding.objects.filter(aws_account=account).delete()
        report_deleted, _ = IAMSecurityReport.objects.filter(aws_account=account).delete()
        
        return Response({
            'success': True,
            'message': f'Cleared {findings_deleted} findings and AI recommendations',
            'findings_deleted': findings_deleted,
            'report_deleted': report_deleted
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)