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


# Add to security/views.py

from .models import PublicExposureFinding, PublicExposureReport
from .serlizers import PublicExposureFindingSerializer, PublicExposureReportSerializer
from .Public_exposure_scanner import scan_public_exposures, generate_public_exposure_ai_analysis


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_public_exposure_view(request, account_id):
    """
    Scan for public exposures in AWS account
    """
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        force_refresh = request.query_params.get('force_refresh', 'false').lower() == 'true'
        
        # Check for cached results
        if not force_refresh:
            cached_findings = PublicExposureFinding.objects.filter(
                aws_account=account,
                is_resolved=False
            )
            cached_report = PublicExposureReport.objects.filter(aws_account=account).first()
            
            if cached_findings.exists() and cached_report:
                serializer = PublicExposureFindingSerializer(cached_findings, many=True)
                return Response({
                    'success': True,
                    'cached': True,
                    'total_findings': cached_findings.count(),
                    'findings': serializer.data,
                    'ai_analysis': cached_report.ai_analysis,
                    'report_summary': {
                        'critical': cached_report.critical_count,
                        'high': cached_report.high_count,
                        'medium': cached_report.medium_count,
                        'low': cached_report.low_count,
                        'generated_at': cached_report.created_at
                    }
                }, status=200)
        
        # Delete old findings
        PublicExposureFinding.objects.filter(aws_account=account).delete()
        PublicExposureReport.objects.filter(aws_account=account).delete()
        
        # Run fresh scan
        scan_result = scan_public_exposures(
            account.role_arn,
            str(account.external_id),
            'us-east-1'
        )
        
        if scan_result.get('error'):
            return Response({
                'success': False,
                'error': scan_result['error']
            }, status=500)
        
        # Save findings to database
        saved_findings = []
        for finding_data in scan_result['findings']:
            finding = PublicExposureFinding.objects.create(
                user=request.user,
                aws_account=account,
                exposure_type=finding_data.get('finding_type', 'public_ec2'),
                severity=finding_data.get('severity', 'MEDIUM'),
                resource_name=finding_data.get('instance_name') or 
                             finding_data.get('bucket_name') or 
                             finding_data.get('lb_name') or 
                             finding_data.get('security_group_name') or
                             finding_data.get('api_name') or
                             finding_data.get('resource_name', 'Unknown'),
                resource_id=finding_data.get('instance_id') or 
                           finding_data.get('bucket_name') or
                           finding_data.get('api_id') or '',
                region=finding_data.get('region', ''),
                public_ip=finding_data.get('public_ip', ''),
                port=finding_data.get('port'),
                protocol=finding_data.get('protocol', ''),
                cidr=finding_data.get('cidr', ''),
                security_group_name=finding_data.get('security_group_name', ''),
                security_group_id=finding_data.get('security_group_id', ''),
                details=finding_data,
                title=finding_data.get('title', generate_title(finding_data)),
                description=finding_data.get('description', generate_description(finding_data)),
                recommendation=finding_data.get('recommendation', generate_recommendation(finding_data)),
                is_resolved=False
            )
            saved_findings.append(finding)
        
        # Count by severity
        critical_count = len([f for f in scan_result['findings'] if f.get('severity') == 'CRITICAL'])
        high_count = len([f for f in scan_result['findings'] if f.get('severity') == 'HIGH'])
        medium_count = len([f for f in scan_result['findings'] if f.get('severity') == 'MEDIUM'])
        low_count = len([f for f in scan_result['findings'] if f.get('severity') == 'LOW'])
        
        # Generate AI analysis
        ai_analysis = generate_public_exposure_ai_analysis(
            scan_result['findings'],
            account.account_alias or account.account_id
        )
        
        # Save report
        report = PublicExposureReport.objects.create(
            user=request.user,
            aws_account=account,
            ai_analysis=ai_analysis,
            total_findings=len(saved_findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count
        )
        
        serializer = PublicExposureFindingSerializer(saved_findings, many=True)
        
        return Response({
            'success': True,
            'cached': False,
            'total_findings': len(saved_findings),
            'findings': serializer.data,
            'ai_analysis': ai_analysis,
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
        logger.error(f"Error scanning public exposures: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_public_exposure_findings(request, account_id):
    """Get cached public exposure findings"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        findings = PublicExposureFinding.objects.filter(
            aws_account=account,
            is_resolved=False
        ).order_by('-severity', '-detected_at')
        
        report = PublicExposureReport.objects.filter(aws_account=account).first()
        
        critical = findings.filter(severity='CRITICAL').count()
        high = findings.filter(severity='HIGH').count()
        medium = findings.filter(severity='MEDIUM').count()
        low = findings.filter(severity='LOW').count()
        
        serializer = PublicExposureFindingSerializer(findings, many=True)
        
        return Response({
            'success': True,
            'cached': True,
            'total_findings': findings.count(),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'findings': serializer.data,
            'ai_analysis': report.ai_analysis if report else None,
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
def clear_public_exposure_findings(request, account_id):
    """Clear all public exposure findings"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        findings_deleted, _ = PublicExposureFinding.objects.filter(aws_account=account).delete()
        report_deleted, _ = PublicExposureReport.objects.filter(aws_account=account).delete()
        
        return Response({
            'success': True,
            'message': f'Cleared {findings_deleted} public exposure findings',
            'findings_deleted': findings_deleted,
            'report_deleted': report_deleted
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_public_exposure_finding(request, finding_id):
    """Mark a finding as resolved"""
    try:
        finding = PublicExposureFinding.objects.get(id=finding_id, user=request.user)
        finding.is_resolved = True
        finding.save()
        
        return Response({
            'success': True,
            'message': 'Finding marked as resolved'
        }, status=200)
        
    except PublicExposureFinding.DoesNotExist:
        return Response({'error': 'Finding not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


def generate_title(finding):
    """Generate title for finding based on type"""
    finding_type = finding.get('finding_type', '')
    resource = finding.get('instance_name') or finding.get('bucket_name') or finding.get('lb_name') or 'Resource'
    
    titles = {
        'public_ec2': f'EC2 instance "{resource}" is publicly accessible',
        'open_sg_rule': f'Security group "{finding.get("security_group_name", resource)}" has open rule from anywhere',
        'public_rds': f'RDS instance "{resource}" is publicly accessible',
        'public_s3': f'S3 bucket "{resource}" has public access',
        'public_lb': f'Load Balancer "{resource}" is internet-facing',
        'public_eks': f'EKS cluster "{resource}" has public API endpoint',
        'public_redis': f'Redis cluster "{resource}" is publicly accessible',
        'public_opensearch': f'OpenSearch domain "{resource}" is publicly accessible',
        'public_api': f'API Gateway "{resource}" has no authentication',
        'missing_waf': f'"{resource}" has no WAF protection'
    }
    
    return titles.get(finding_type, f'Public exposure found in "{resource}"')


def generate_description(finding):
    """Generate description for finding"""
    finding_type = finding.get('finding_type', '')
    resource = finding.get('instance_name') or finding.get('bucket_name') or finding.get('lb_name') or 'Resource'
    public_ip = finding.get('public_ip', '')
    port = finding.get('port', '')
    protocol = finding.get('protocol', 'tcp')
    cidr = finding.get('cidr', '0.0.0.0/0')
    
    descriptions = {
        'public_ec2': f'EC2 instance "{resource}" has public IP {public_ip} and can be accessed from the internet. This exposes your instance to potential attacks including brute force, DoS, and vulnerability exploitation.',
        'open_sg_rule': f'Security group allows {protocol}:{port} access from {cidr}. This means anyone on the internet can attempt to connect to resources using this security group.',
        'public_rds': f'RDS instance "{resource}" is configured as publicly accessible on port {port}. Your database can be accessed directly from the internet, making it vulnerable to data breaches.',
        'public_s3': f'S3 bucket "{resource}" allows public access. Anyone with the bucket URL can read or write data, potentially exposing sensitive information.',
        'public_lb': f'Load Balancer "{resource}" is internet-facing and accessible from anywhere. Without proper WAF protection, it is vulnerable to DDoS and application attacks.',
        'public_eks': f'EKS cluster "{resource}" has public API endpoint enabled. The Kubernetes API server is exposed to the internet, a critical security risk.',
        'public_redis': f'Redis cluster "{resource}" is publicly accessible on port {port}. Redis has no built-in authentication and is frequently targeted by attackers for data theft.',
        'public_opensearch': f'OpenSearch domain "{resource}" has public access enabled. Your search data and analytics could be exposed to unauthorized users.',
        'public_api': f'API Gateway "{resource}" has no authentication or authorizer configured. Anyone can invoke your API endpoints without credentials.',
        'missing_waf': f'"{resource}" has no Web Application Firewall (WAF) attached. This leaves it unprotected against common web exploits like SQL injection and XSS.'
    }
    
    return descriptions.get(finding_type, f'Public exposure detected in {resource}')


def generate_recommendation(finding):
    """Generate recommendation for fixing the finding"""
    finding_type = finding.get('finding_type', '')
    
    recommendations = {
        'public_ec2': 'Remove the public IP by using a private subnet with NAT gateway, or restrict security group rules to specific IP ranges (not 0.0.0.0/0). Use AWS Systems Manager Session Manager for secure access.',
        'open_sg_rule': 'Restrict security group rules to specific IP ranges or VPC CIDRs. Use security group referencing instead of IP ranges when possible. Enable AWS WAF for web traffic.',
        'public_rds': 'Set PubliclyAccessible=false in RDS configuration. Move RDS to private subnets and access via bastion host or VPC peering.',
        'public_s3': 'Enable "Block all public access" on the S3 bucket. Review and remove public bucket policies and ACLs. Use pre-signed URLs for temporary access.',
        'public_lb': 'Consider making the load balancer internal. If it must be public, attach AWS WAF and enable AWS Shield Advanced. Implement strict security group rules.',
        'public_eks': 'Disable public endpoint access. Use VPC endpoint for private API server access. Enable AWS PrivateLink for secure connectivity.',
        'public_redis': 'Move Redis to private subnets and use VPC peering or VPN for access. Enable encryption at rest and in transit. Use Redis AUTH if possible.',
        'public_opensearch': 'Disable public access and use VPC. Configure fine-grained access control. Enable encryption and IP-based restrictions.',
        'public_api': 'Add Cognito authorizer, API keys, or IAM authentication. Implement rate limiting and usage plans. Enable WAF for API protection.',
        'missing_waf': 'Attach AWS WAF Web ACL to the resource. Configure rules for common threats like SQL injection, XSS, and rate limiting.'
    }
    
    return recommendations.get(finding_type, 'Review and restrict public access to this resource following AWS security best practices.')

# Add to security/views.py

from .security_group_analyzer import scan_all_security_groups, get_cached_security_groups, get_security_group_detail

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_security_groups(request, account_id):
    """Trigger security group scan"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        force_refresh = request.query_params.get('force_refresh', 'false').lower() == 'true'
        
        # Check for cached results
        if not force_refresh:
            cached_results = get_cached_security_groups(account)
            if cached_results.get('total_security_groups', 0) > 0:
                return Response(cached_results, status=200)
        
        # Run scan
        result = scan_all_security_groups(account, force_refresh)
        
        if result.get('error'):
            return Response({'error': result['error']}, status=500)
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error scanning security groups: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_security_groups_list(request, account_id):
    """Get cached security groups list"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        result = get_cached_security_groups(account)
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_security_group_detail_view(request, account_id, sg_id):
    """Get detailed analysis for a specific security group"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        result = get_security_group_detail(account, sg_id)
        
        if result.get('error'):
            return Response({'error': result['error']}, status=404)
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_security_groups_cache(request, account_id):
    """Clear cached security group analysis"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import SecurityGroupAnalysis, SecurityGroupAnalysisCache
        
        deleted_count, _ = SecurityGroupAnalysis.objects.filter(aws_account=account).delete()
        SecurityGroupAnalysisCache.objects.filter(aws_account=account).delete()
        
        return Response({
            'success': True,
            'message': f'Cleared {deleted_count} security group analyses',
            'deleted_count': deleted_count
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# Add to security/views.py

from .encryption_checker import scan_encryption_status, get_cached_encryption_summary, get_encryption_findings

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_encryption_status_view(request, account_id):
    """Trigger encryption status scan"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        force_refresh = request.query_params.get('force_refresh', 'false').lower() == 'true'
        
        # Check for cached results
        if not force_refresh:
            cached_results = get_cached_encryption_summary(account)
            if cached_results.get('success') and cached_results.get('cached'):
                return Response(cached_results, status=200)
        
        # Run scan
        result = scan_encryption_status(account, force_refresh)
        
        if result.get('error'):
            return Response({'error': result['error']}, status=500)
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error scanning encryption: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_encryption_summary_view(request, account_id):
    """Get cached encryption summary"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        result = get_cached_encryption_summary(account)
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_encryption_findings_view(request, account_id):
    """Get encryption findings"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        severity_filter = request.query_params.get('severity', 'all')
        
        result = get_encryption_findings(account, severity_filter)
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_encryption_cache(request, account_id):
    """Clear encryption scan cache"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import EncryptionFinding, EncryptionSummary, EncryptionScanCache
        
        findings_deleted, _ = EncryptionFinding.objects.filter(aws_account=account).delete()
        summary_deleted, _ = EncryptionSummary.objects.filter(aws_account=account).delete()
        cache_deleted, _ = EncryptionScanCache.objects.filter(aws_account=account).delete()
        
        return Response({
            'success': True,
            'message': f'Cleared {findings_deleted} encryption findings',
            'findings_deleted': findings_deleted,
            'summary_deleted': summary_deleted
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# Add to security/views.py

from .encryption_actions import execute_encryption_action
from .encryption_ai_recommendations import generate_recommendations_for_all_resources
from .models import EncryptionAction, EncryptionRecommendation


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def create_encryption_action(request, account_id):
    """Create a new encryption action (one-click fix)"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        resource_type = request.data.get('resource_type')
        resource_id = request.data.get('resource_id')
        resource_name = request.data.get('resource_name', '')
        region = request.data.get('region', '')
        action_type = request.data.get('action_type')
        action_params = request.data.get('action_params', {})
        
        # Add account_id to action_params for constructing ARNs
        action_params['account_id'] = account.account_id
        
        action = EncryptionAction.objects.create(
            user=request.user,
            aws_account=account,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            region=region,
            action_type=action_type,
            action_params=action_params,
            status='pending'
        )
        
        # Execute asynchronously (simplified - in production use Celery)
        import threading
        thread = threading.Thread(target=execute_encryption_action, args=(action.id,))
        thread.start()
        
        return Response({
            'success': True,
            'action_id': action.id,
            'message': 'Encryption action started',
            'status': 'pending'
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_encryption_action_status(request, account_id, action_id):
    """Get status of an encryption action"""
    try:
        action = EncryptionAction.objects.get(id=action_id, aws_account__user=request.user)
        
        return Response({
            'success': True,
            'action': {
                'id': action.id,
                'status': action.status,
                'status_message': action.status_message,
                'requires_migration': action.requires_migration,
                'migration_workflow': action.migration_workflow,
                'result_details': action.result_details,
                'created_at': action.created_at.isoformat(),
                'completed_at': action.completed_at.isoformat() if action.completed_at else None
            }
        }, status=200)
        
    except EncryptionAction.DoesNotExist:
        return Response({'error': 'Action not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def generate_encryption_recommendations(request, account_id):
    """Generate AI recommendations for all encryption findings"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        # Get all unencrypted findings
        from .models import EncryptionFinding
        findings = EncryptionFinding.objects.filter(
            aws_account=account,
            is_encrypted=False
        ).values()
        
        recommendations = generate_recommendations_for_all_resources(account, list(findings))
        
        return Response({
            'success': True,
            'recommendations_count': len(recommendations),
            'recommendations': [
                {
                    'id': r.id,
                    'resource_name': r.resource_name,
                    'resource_type': r.resource_type,
                    'recommendation_title': r.recommendation_title,
                    'recommendation_description': r.recommendation_description,
                    'recommendation_reason': r.recommendation_reason,
                    'risk_reduction': r.risk_reduction,
                    'compliance_benefit': r.compliance_benefit,
                    'estimated_time': r.estimated_time,
                    'difficulty': r.difficulty,
                    'one_click_available': r.one_click_available,
                    'one_click_action_type': r.one_click_action_type,
                    'migration_required': r.migration_required,
                    'migration_steps': r.migration_steps
                }
                for r in recommendations
            ]
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_encryption_recommendations(request, account_id):
    """Get cached AI recommendations for encryption findings"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        recommendations = EncryptionRecommendation.objects.filter(
            aws_account=account
        ).order_by('-generated_at')
        
        return Response({
            'success': True,
            'cached': True,
            'recommendations': [
                {
                    'id': r.id,
                    'resource_name': r.resource_name,
                    'resource_type': r.resource_type,
                    'resource_id': r.resource_id,
                    'is_encrypted': r.is_encrypted,
                    'current_encryption_type': r.current_encryption_type,
                    'recommendation_title': r.recommendation_title,
                    'recommendation_description': r.recommendation_description,
                    'recommendation_reason': r.recommendation_reason,
                    'risk_reduction': r.risk_reduction,
                    'compliance_benefit': r.compliance_benefit,
                    'estimated_time': r.estimated_time,
                    'difficulty': r.difficulty,
                    'one_click_available': r.one_click_available,
                    'one_click_action_type': r.one_click_action_type,
                    'migration_required': r.migration_required,
                    'migration_steps': r.migration_steps,
                    'generated_at': r.generated_at.isoformat()
                }
                for r in recommendations
            ]
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)