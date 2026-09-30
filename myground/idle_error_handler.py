# myground/idle_error_handler.py
"""
Central handler for AWS errors during idle resource scanning.

Every detector wraps its AWS calls in `handle_aws_error()`.
If the call fails with a permission error, we:
  1. Record an IdleScanError row (upserted per account+detector+permission)
  2. Return an error dict the detector can attach to its response
  3. Never crash the whole scan — partial results beat no results
"""

import logging
from botocore.exceptions import ClientError

from .models import IdleScanError

logger = logging.getLogger(__name__)


# Which AWS actions map to which detector + human-readable label
DETECTOR_PERMISSIONS = {
    'ec2': {
        'actions': [
            'ec2:DescribeInstances',
            'ec2:DescribeInstanceStatus',
            'ec2:DescribeVolumes',
            'ec2:DescribeAddresses',
            'ec2:DescribeSnapshots',
        ],
        'label': 'EC2 & EBS',
    },
    'nat_gateway': {
        'actions': ['ec2:DescribeNatGateways'],
        'label': 'NAT Gateways',
    },
    'vpc_endpoint': {
        'actions': ['ec2:DescribeVpcEndpoints'],
        'label': 'VPC Endpoints',
    },
    'load_balancer': {
        'actions': [
            'elasticloadbalancing:DescribeLoadBalancers',
            'elasticloadbalancing:DescribeTargetGroups',
            'elasticloadbalancing:DescribeTargetHealth',
        ],
        'label': 'Load Balancers',
    },
    'autoscaling': {
        'actions': [
            'autoscaling:DescribeAutoScalingGroups',
            'autoscaling:DescribeScalingActivities',
        ],
        'label': 'Auto Scaling Groups',
    },
    'lambda': {
        'actions': ['lambda:ListFunctions'],
        'label': 'Lambda',
    },
    'ecs': {
        'actions': [
            'ecs:ListClusters',
            'ecs:ListServices',
            'ecs:DescribeServices',
            'ecs:DescribeTaskDefinition',
        ],
        'label': 'ECS / Fargate',
    },
    'api_gateway': {
        'actions': [
            'apigateway:GET',
            'apigatewayv2:GetApis',
        ],
        'label': 'API Gateway',
    },
    'cloudwatch': {
        'actions': [
            'cloudwatch:DescribeAlarms',
            'cloudwatch:ListDashboards',
            'cloudwatch:DescribeInsightRules',
            'logs:DescribeLogGroups',
            'logs:DescribeLogStreams',
            'logs:DescribeMetricFilters',
        ],
        'label': 'CloudWatch',
    },
    'rds': {
        'actions': ['rds:DescribeDBInstances'],
        'label': 'RDS',
    },
    'elastic_ip': {
        'actions': ['ec2:DescribeAddresses'],
        'label': 'Elastic IPs',
    },
    'snapshot': {
        'actions': ['ec2:DescribeSnapshots'],
        'label': 'Snapshots',
    },
    'cloudwatch_metrics': {
        # CloudWatch metric reads often fail separately from describe calls
        'actions': ['cloudwatch:GetMetricStatistics'],
        'label': 'CloudWatch Metrics',
    },
}


def build_iam_snippet(detector: str) -> str:
    """Return a copy-pasteable IAM policy for a detector's required actions."""
    info = DETECTOR_PERMISSIONS.get(detector)
    if not info:
        return ''

    actions = info['actions']
    actions_json = ',\n        '.join(f'"{a}"' for a in actions)

    return (
        '{\n'
        '    "Version": "2012-10-17",\n'
        '    "Statement": [\n'
        '        {\n'
        '            "Effect": "Allow",\n'
        '            "Action": [\n'
        f'        {actions_json}\n'
        '            ],\n'
        '            "Resource": "*"\n'
        '        }\n'
        '    ]\n'
        '}'
    )


def _extract_permission_from_error(error_code: str, error_message: str) -> str:
    """
    Try to guess the missing AWS permission from the error message.
    AWS error messages usually contain the action name, e.g.
    'User: arn:aws:sts::... is not authorized to perform: ec2:DescribeNatGateways'
    """
    if not error_message:
        return ''

    # Look for the "is not authorized to perform: X" pattern
    marker = 'not authorized to perform: '
    idx = error_message.find(marker)
    if idx != -1:
        after = error_message[idx + len(marker):]
        # Take until whitespace
        permission = after.split()[0].strip()
        # Strip any trailing 'because' etc
        permission = permission.rstrip(',.')
        return permission

    return ''


def handle_aws_error(aws_account, detector: str, exception: Exception) -> dict:
    """
    Process an AWS exception. Saves an IdleScanError row if it's a permission issue.
    Returns a dict the detector can include in its response:
        {'detector': ..., 'code': ..., 'message': ..., 'permission': ...}
    """
    user = aws_account.user

    if isinstance(exception, ClientError):
        err = exception.response.get('Error', {}) or {}
        error_code = err.get('Code', 'Unknown')
        error_message = err.get('Message', str(exception))
    else:
        error_code = type(exception).__name__
        error_message = str(exception)

    # Only track the interesting ones
    permission_errors = {
        'AccessDenied',
        'AccessDeniedException',
        'UnauthorizedOperation',
        'AuthorizationError',
        'SubscriptionRequiredException',
    }

    is_permission = error_code in permission_errors
    is_throttle = error_code in {'Throttling', 'ThrottlingException', 'RequestLimitExceeded', 'TooManyRequestsException'}
    is_network = error_code in {'EndpointConnectionError', 'ConnectTimeoutError', 'ReadTimeoutError'}

    missing_permission = _extract_permission_from_error(error_code, error_message)

    # Only persist permission errors (skip transient throttling / network)
    if is_permission:
        iam_snippet = build_iam_snippet(detector)

        try:
            IdleScanError.objects.update_or_create(
                aws_account=aws_account,
                detector=detector,
                missing_permission=missing_permission or f'{detector}:unknown',
                defaults={
                    'user': user,
                    'error_code': error_code,
                    'error_message': error_message,
                    'required_iam_action': iam_snippet,
                },
            )
            logger.warning(
                f"🔒 Permission error on {detector}: {missing_permission or error_code}"
            )
        except Exception as e:
            logger.error(f"Failed to save IdleScanError: {e}")
    elif is_throttle:
        logger.warning(f"⏳ Throttled on {detector}: {error_message[:100]}")
    elif is_network:
        logger.warning(f"🌐 Network error on {detector}: {error_message[:100]}")
    else:
        logger.error(f"❌ {detector} failed: {error_code} — {error_message[:200]}")

    return {
        'detector': detector,
        'code': error_code,
        'message': error_message[:500],
        'permission': missing_permission,
        'is_permission_error': is_permission,
    }


def clear_detector_errors(aws_account, detector: str):
    """
    Called after a successful scan of a detector — clears any prior
    permission errors for that detector (user must have fixed them).
    """
    deleted, _ = IdleScanError.objects.filter(
        aws_account=aws_account, detector=detector
    ).delete()
    if deleted:
        logger.info(f"✅ Cleared {deleted} prior errors for {detector}")


def get_scan_errors(aws_account) -> list:
    """Return all current (non-acknowledged) errors for the frontend."""
    qs = IdleScanError.objects.filter(
        aws_account=aws_account, is_acknowledged=False
    ).order_by('detector')

    return [
        {
            'id': e.id,
            'detector': e.detector,
            'label': DETECTOR_PERMISSIONS.get(e.detector, {}).get('label', e.detector),
            'error_code': e.error_code,
            'error_message': e.error_message,
            'missing_permission': e.missing_permission,
            'required_iam_action': e.required_iam_action,
            'detected_at': e.detected_at.isoformat(),
        }
        for e in qs
    ]