# myground/service_breakdown_service.py
"""
Service & Resource Breakdown
Uses the Discovery/* modules to scan all AWS resources in a single region,
runs per-resource AI verdicts on scannable resources, and produces one
AI-generated summary per scan.

Caching:
- Every ResourceAIAnalysis row carries `region_scanned`.
- Per-resource results are cached per (account, region).
- BreakdownSummary is cached per (account, region).
- Nothing expires automatically. Clear cache deletes rows for one region.
"""

import boto3
from datetime import datetime, date, timezone as dt_timezone
from decimal import Decimal
import requests
import json
import logging
import time

from django.conf import settings
from django.utils import timezone as django_timezone
from django.db import transaction

from .models import AWSAccount, ResourceAIAnalysis, BreakdownSummary

logger = logging.getLogger(__name__)


# ============================================================
# JSON-SAFETY HELPERS
# ============================================================
# Discovery modules sometimes stuff raw datetime/date/Decimal objects
# into 'on_since', 'details', 'tags'. Django's JSONField encoder can't
# handle those, so we deep-sanitize every payload before saving.

def _json_safe(value):
    """
    Recursively convert a value into something Django's JSONField can store.
    Handles datetime, date, Decimal, sets, tuples, nested dicts/lists.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        # Make timezone-aware UTC then ISO
        try:
            if value.tzinfo is None:
                value = value.replace(tzinfo=dt_timezone.utc)
            return value.isoformat()
        except Exception:
            return str(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    # Fallback: stringify unknown types (e.g. boto3 response objects)
    return str(value)


def _safe_datetime(value):
    """Return a real datetime object or None, from a datetime/str/None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt_timezone.utc)
        return value
    if isinstance(value, str):
        try:
            # Try ISO 8601
            from datetime import datetime as _dt
            v = value.replace('Z', '+00:00')
            parsed = _dt.fromisoformat(v)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt_timezone.utc)
            return parsed
        except Exception:
            return None
    return None


# ============================================================
# DISCOVERY MODULE REGISTRY
# ============================================================

def _get_discovery_scanners():
    """
    Returns a list of (service_label, callable) tuples.
    The callable accepts (creds, region) and returns a list of resource dicts.
    """
    scanners = []

    def _safe_import(module_path, func_name, label):
        try:
            module = __import__(module_path, fromlist=[func_name])
            fn = getattr(module, func_name)
            scanners.append((label, fn))
        except Exception as e:
            logger.warning(f"Discovery module {module_path}.{func_name} unavailable: {e}")

    _safe_import('myground.Discovery.ec2_discovery',        'discover_ec2_services',        'EC2')
    _safe_import('myground.Discovery.rds_discovery',        'discover_rds_services',        'RDS')
    _safe_import('myground.Discovery.s3_discovery',         'discover_s3_services',         'S3')
    _safe_import('myground.Discovery.lambda_discovery',     'discover_lambda_services',     'Lambda')
    _safe_import('myground.Discovery.dynamodb_discovery',   'discover_dynamodb_services',   'DynamoDB')
    _safe_import('myground.Discovery.ecs_discovery',        'discover_ecs_services',        'ECS')
    _safe_import('myground.Discovery.eks_discovery',        'discover_eks_services',        'EKS')
    _safe_import('myground.Discovery.elb_discovery',        'discover_elb_services',        'ELB')
    _safe_import('myground.Discovery.vpc_discovery',        'discover_vpc_services',        'VPC')
    _safe_import('myground.Discovery.route53_discovery',    'discover_route53_services',    'Route53')
    _safe_import('myground.Discovery.cloudfront_discovery', 'discover_cloudfront_distributions', 'CloudFront')
    _safe_import('myground.Discovery.waf_discovery',        'discover_waf_services',        'WAF')
    _safe_import('myground.Discovery.shield_discovery',     'discover_shield_services',     'Shield')
    _safe_import('myground.Discovery.kms_discovery',        'discover_kms_services',        'KMS')
    _safe_import('myground.Discovery.sns_discovery',        'discover_sns_services',        'SNS')
    _safe_import('myground.Discovery.sqs_discovery',        'discover_sqs_services',        'SQS')
    _safe_import('myground.Discovery.ssm_discovery',        'discover_ssm_services',        'SSM')
    _safe_import('myground.Discovery.stepfunctions_discovery', 'discover_stepfunctions_services', 'StepFunctions')
    _safe_import('myground.Discovery.eventbridge_discovery','discover_eventbridge_services','EventBridge')
    _safe_import('myground.Discovery.cloudwatch_discovery', 'discover_cloudwatch_services', 'CloudWatch')
    _safe_import('myground.Discovery.cloudtrail_discovery', 'discover_cloudtrail_services', 'CloudTrail')
    _safe_import('myground.Discovery.apigateway_discovery', 'discover_apigateway_services', 'APIGateway')
    _safe_import('myground.Discovery.dms_discovery',        'discover_dms_services',        'DMS')
    _safe_import('myground.Discovery.guardduty_discovery',  'discover_guardduty_services',  'GuardDuty')
    _safe_import('myground.Discovery.cloudformation_discovery', 'discover_cloudformation_services', 'CloudFormation')

    return scanners


# ============================================================
# ASSUME ROLE
# ============================================================

def assume_role(aws_account):
    sts = boto3.client(
        'sts',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION,
    )
    response = sts.assume_role(
        RoleArn=aws_account.role_arn,
        RoleSessionName='ServiceBreakdown',
        ExternalId=str(aws_account.external_id),
    )
    return response['Credentials']


# ============================================================
# NORMALIZE A DISCOVERY RESOURCE INTO OUR SHAPE
# ============================================================

def _to_decimal(value, default=0):
    try:
        if value is None:
            return Decimal(str(default))
        return Decimal(str(value))
    except Exception:
        return Decimal(str(default))


def _normalize_discovery_resource(raw, service_label, region):
    """
    Discovery modules return dicts shaped like:
        { 'service_id', 'resource_id', 'resource_name', 'region',
          'estimated_monthly_cost', 'count', 'details', 'service_type' }
    Convert that into the fields our model + AI prompt expect.
    Everything that goes into JSONField is passed through _json_safe().
    """
    raw = raw or {}
    resource_id = str(raw.get('resource_id') or raw.get('service_id') or 'unknown')
    resource_name = str(raw.get('resource_name') or resource_id)
    region_value = raw.get('region') or region or 'global'

    cost_raw = raw.get('estimated_monthly_cost', 0)
    monthly_cost = _to_decimal(cost_raw, 0)

    service_category = raw.get('service_type') or service_label

    # Sanitize everything that will hit a JSONField or a DateTimeField
    on_since = _safe_datetime(raw.get('on_since'))
    last_checked = _safe_datetime(raw.get('last_checked')) or datetime.now(dt_timezone.utc)
    safe_details = _json_safe(raw.get('details') or {})
    safe_tags = _json_safe(raw.get('tags') if isinstance(raw.get('tags'), dict) else {})

    return {
        'service_category': service_category,
        'service_name': service_label,
        'resource_id': resource_id,
        'resource_name': resource_name,
        'resource_type': str(raw.get('resource_type') or raw.get('service_id') or 'Unknown'),
        'region': region_value,
        'region_scanned': region,
        'tags': safe_tags,
        'status': raw.get('status') or 'ON',
        'on_since': on_since,
        'last_checked': last_checked,
        'cpu_avg': float(raw.get('cpu_avg') or 0.0),
        'network_in_mb': float(raw.get('network_in_mb') or 0.0),
        'network_out_mb': float(raw.get('network_out_mb') or 0.0),
        'disk_read_mb': float(raw.get('disk_read_mb') or 0.0),
        'disk_write_mb': float(raw.get('disk_write_mb') or 0.0),
        'monthly_cost': monthly_cost,
        'resource_details': safe_details,
    }


# ============================================================
# SCAN ONE REGION
# ============================================================

def scan_region(creds, region):
    """
    Runs every discovery module against a single region and returns
    a list of normalized resource dicts.
    """
    scanners = _get_discovery_scanners()
    all_resources = []

    for label, fn in scanners:
        started = time.time()
        try:
            raw_list = fn(creds, region) or []
            for raw in raw_list:
                all_resources.append(_normalize_discovery_resource(raw, label, region))
            logger.info(f"✅ {label} in {region}: {len(raw_list)} resources ({time.time()-started:.1f}s)")
        except Exception as e:
            logger.warning(f"❌ {label} in {region} failed: {e}")

    return all_resources


# ============================================================
# AI — PER-RESOURCE VERDICT
# ============================================================

AI_PROMPT_TEMPLATE = """You are a Senior AWS FinOps Expert analyzing a single cloud resource.

RESOURCE DETAILS:
- Service: {service_name} ({service_category})
- Resource ID: {resource_id}
- Type: {resource_type}
- Region: {region}
- Status: {status}
- CPU Average (7 days): {cpu_avg}%
- Monthly Cost: ${monthly_cost}
- Tags: {tags}
- Extra: {extra}

YOUR TASK:
Pick ONE verdict:
- LEAVE_IT (healthy)
- MONITOR_IT (not enough data)
- SCHEDULE_IT (only used at certain hours)
- DOWNSIZE_IT (over-provisioned)
- STOP_IT (idle, stop to save money)
- TERMINATE_IT (unused, delete permanently)

Respond ONLY with valid JSON in this exact format:
{{
    "verdict": "STOP_IT",
    "short_reason": "One sentence (max 100 chars).",
    "detailed_explanation": "4-6 sentences referencing the actual numbers above.",
    "savings_monthly": 11.20,
    "savings_yearly": 134.40,
    "risk": "LOW",
    "steps": ["Step 1", "Step 2", "Step 3"],
    "alternatives": ["Alt 1", "Alt 2"],
    "time_to_fix": "5 minutes",
    "one_click_available": true,
    "priority": 8
}}

Rules:
- savings_monthly = 0 if verdict is LEAVE_IT or MONITOR_IT
- savings_yearly = savings_monthly * 12
- risk: ZERO, LOW, MEDIUM, HIGH
- priority: 1-10
- one_click_available: true only for STOP_IT, SCHEDULE_IT, TERMINATE_IT
"""


def get_ai_verdict(resource_data):
    try:
        prompt = AI_PROMPT_TEMPLATE.format(**resource_data)

        headers = {
            'Authorization': f'Bearer {settings.GROQ_API_KEY}',
            'Content-Type': 'application/json',
        }
        payload = {
            'model': 'llama-3.3-70b-versatile',
            'messages': [
                {'role': 'system', 'content': 'You are a Senior AWS FinOps Expert. Respond ONLY with valid JSON.'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.4,
            'max_tokens': 900,
            'response_format': {'type': 'json_object'},
        }

        response = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers, json=payload, timeout=30,
        )
        if response.status_code == 200:
            result = response.json()
            content = result['choices'][0]['message']['content']
            return json.loads(content)
        logger.error(f"Groq error: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"AI verdict error: {e}")
    return None


def fallback_verdict(resource_data):
    """Used when AI is skipped or fails."""
    cpu = resource_data.get('cpu_avg', 0)
    status = resource_data.get('status', 'UNKNOWN')
    cost = float(resource_data.get('monthly_cost', 0))

    if status == 'STOPPED':
        return {
            'verdict': 'TERMINATE_IT',
            'short_reason': 'Resource is stopped — likely forgotten.',
            'detailed_explanation': 'This resource is stopped but still exists. If it is not needed, terminating removes it permanently.',
            'savings_monthly': 0, 'savings_yearly': 0,
            'risk': 'LOW',
            'steps': ['Verify no snapshots needed', 'Terminate the resource'],
            'alternatives': ['Keep it stopped for 30 more days'],
            'time_to_fix': '2 minutes', 'one_click_available': True, 'priority': 4,
        }
    if cpu < 5 and cost > 5 and status == 'ON':
        return {
            'verdict': 'STOP_IT',
            'short_reason': f'CPU average is {cpu}% — resource is idle.',
            'detailed_explanation': f'This resource runs at only {cpu}% average CPU but costs ${cost}/month. Stopping it removes that cost with no impact on real work.',
            'savings_monthly': round(cost, 2), 'savings_yearly': round(cost * 12, 2),
            'risk': 'LOW',
            'steps': ['Take a snapshot', 'Stop the instance', 'Monitor 7 days'],
            'alternatives': ['Downsize for partial savings'],
            'time_to_fix': '5 minutes', 'one_click_available': True, 'priority': 7,
        }
    return {
        'verdict': 'MONITOR_IT',
        'short_reason': 'Not enough data for a confident recommendation.',
        'detailed_explanation': 'We need more usage history. Monitor for another 7 days to gather metrics before deciding.',
        'savings_monthly': 0, 'savings_yearly': 0,
        'risk': 'ZERO', 'steps': ['Check back in 7 days'],
        'alternatives': [],
        'time_to_fix': 'N/A', 'one_click_available': False, 'priority': 1,
    }


# ============================================================
# AI — SCAN SUMMARY
# ============================================================

def get_scan_summary(region, total_resources, total_cost, total_savings, top_findings):
    """One AI call per scan that produces a plain-English summary."""
    try:
        findings_text = '\n'.join(
            f"- {f['title']} → {f['verdict']} (cost ${f['cost']}/mo, save ${f['savings']}/mo)"
            for f in top_findings[:12]
        ) or 'No actionable findings.'

        prompt = f"""You are a Senior AWS FinOps Expert summarizing a completed scan.

SCAN RESULTS — REGION: {region}
- Total resources scanned: {total_resources}
- Total monthly cost: ${total_cost}
- Total potential monthly savings: ${total_savings}

TOP FINDINGS (highest savings first):
{findings_text}

Write a concise, friendly summary for the user. Structure:

**What we found** — 2-3 sentences on the overall state of their account.
**Biggest wins** — 3 bullets, one per top finding, with the dollar amount.
**What to do next** — 1 short paragraph telling them exactly what to click first.

Rules:
- Speak directly to the user ("you", "your account").
- Be specific — quote real dollar amounts from the data above.
- Max 220 words total.
- No markdown headers except the three bold labels above.
"""
        headers = {
            'Authorization': f'Bearer {settings.GROQ_API_KEY}',
            'Content-Type': 'application/json',
        }
        payload = {
            'model': 'llama-3.3-70b-versatile',
            'messages': [
                {'role': 'system', 'content': 'You are a Senior AWS FinOps Expert. Be specific and concise.'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.6,
            'max_tokens': 600,
        }
        r = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers, json=payload, timeout=45,
        )
        if r.status_code == 200:
            return r.json()['choices'][0]['message']['content']
        logger.error(f"Groq summary error: {r.status_code} - {r.text}")
    except Exception as e:
        logger.error(f"AI summary error: {e}")
    return ''


# ============================================================
# SHOULD THIS RESOURCE GO TO GROQ?
# ============================================================

def _is_ai_scannable(r):
    """
    Only send resources that have something to analyze:
    - Cost > $0.50 OR
    - Non-ON status (stopped/unknown)
    Everything else is skipped and marked MONITOR_IT automatically.
    """
    try:
        cost = float(r.get('monthly_cost') or 0)
    except Exception:
        cost = 0.0
    if cost > 0.50:
        return True
    if r.get('status') in ('STOPPED', 'OFF', 'UNKNOWN'):
        return True
    return False


# ============================================================
# MAIN ENTRY — SCAN + AI + SAVE
# ============================================================

def generate_breakdown(aws_account, region='us-east-1', force_refresh=False):
    """
    Scan a single region for a single account.
    Cache per (account, region_scanned). No TTL.
    """

    # ---------- CACHE HIT ----------
    if not force_refresh:
        existing_qs = ResourceAIAnalysis.objects.filter(
            aws_account=aws_account,
            region_scanned=region,
        )
        if existing_qs.exists():
            logger.info(f"📦 Cache hit: {existing_qs.count()} resources in {region}")
            return build_response(aws_account, region, cached=True)

    # ---------- CACHE MISS ----------
    logger.info(f"🔄 Fresh scan: {aws_account.account_id} / {region}")
    scan_started = time.time()

    ResourceAIAnalysis.objects.filter(
        aws_account=aws_account, region_scanned=region,
    ).delete()
    BreakdownSummary.objects.filter(
        aws_account=aws_account, region_scanned=region,
    ).delete()

    try:
        creds = assume_role(aws_account)
    except Exception as e:
        logger.error(f"Role assumption failed: {e}")
        return {'error': f'Failed to assume role: {e}'}

    raw_resources = scan_region(creds, region)
    logger.info(f"📊 Discovered {len(raw_resources)} resources in {region}")

    ai_calls_made = 0
    ai_calls_skipped = 0
    saved_rows = []

    for r in raw_resources:
        if _is_ai_scannable(r):
            ai_input = {
                'service_name': r['service_name'],
                'service_category': r['service_category'],
                'resource_id': r['resource_id'],
                'resource_type': r['resource_type'],
                'region': r['region'],
                'status': r['status'],
                'cpu_avg': r['cpu_avg'],
                'monthly_cost': float(r['monthly_cost']),
                'tags': json.dumps(r['tags']),
                'extra': json.dumps(r.get('resource_details', {})),
            }
            verdict = get_ai_verdict(ai_input)
            if verdict:
                ai_calls_made += 1
            else:
                verdict = fallback_verdict(ai_input)
                ai_calls_skipped += 1
        else:
            ai_calls_skipped += 1
            verdict = {
                'verdict': 'MONITOR_IT',
                'short_reason': 'Cost is negligible — no action needed.',
                'detailed_explanation': '',
                'savings_monthly': 0, 'savings_yearly': 0,
                'risk': 'ZERO', 'steps': [], 'alternatives': [],
                'time_to_fix': 'N/A',
                'one_click_available': False, 'priority': 1,
            }

        saved_rows.append((r, verdict))

    # ---------- PERSIST ----------
    with transaction.atomic():
        for r, verdict in saved_rows:
            ResourceAIAnalysis.objects.create(
                user=aws_account.user,
                aws_account=aws_account,
                service_category=r['service_category'],
                service_name=r['service_name'],
                resource_id=r['resource_id'],
                resource_name=r['resource_name'],
                resource_type=r['resource_type'],
                region=r['region'],
                region_scanned=region,
                tags=_json_safe(r['tags']),
                status=r['status'],
                on_since=_safe_datetime(r['on_since']),
                last_checked=_safe_datetime(r['last_checked']),
                cpu_avg=r['cpu_avg'],
                network_in_mb=r['network_in_mb'],
                network_out_mb=r['network_out_mb'],
                disk_read_mb=r['disk_read_mb'],
                disk_write_mb=r['disk_write_mb'],
                monthly_cost=r['monthly_cost'],
                ai_verdict=verdict.get('verdict', 'MONITOR_IT'),
                ai_short_reason=verdict.get('short_reason', ''),
                ai_detailed_explanation=verdict.get('detailed_explanation', ''),
                ai_savings_monthly=_to_decimal(verdict.get('savings_monthly', 0)),
                ai_savings_yearly=_to_decimal(verdict.get('savings_yearly', 0)),
                ai_risk=verdict.get('risk', 'LOW'),
                ai_steps=_json_safe(verdict.get('steps', [])),
                ai_alternatives=_json_safe(verdict.get('alternatives', [])),
                ai_time_to_fix=verdict.get('time_to_fix', ''),
                ai_one_click_available=verdict.get('one_click_available', False),
                ai_priority=verdict.get('priority', 5),
                resource_details=_json_safe(r['resource_details']),
            )

    scan_duration = round(time.time() - scan_started, 1)

    total_cost = sum(float(r['monthly_cost']) for r, _ in saved_rows)
    total_savings = sum(float(v.get('savings_monthly', 0)) for _, v in saved_rows)

    sorted_by_savings = sorted(
        [
            {
                'title': f"{r['service_name']} · {r['resource_id']}",
                'verdict': v.get('verdict', 'MONITOR_IT'),
                'cost': round(float(r['monthly_cost']), 2),
                'savings': round(float(v.get('savings_monthly', 0)), 2),
            }
            for r, v in saved_rows
            if v.get('savings_monthly', 0) > 0
        ],
        key=lambda x: x['savings'],
        reverse=True,
    )

    summary_text = ''
    if saved_rows:
        summary_text = get_scan_summary(
            region=region,
            total_resources=len(saved_rows),
            total_cost=round(total_cost, 2),
            total_savings=round(total_savings, 2),
            top_findings=sorted_by_savings,
        )

    BreakdownSummary.objects.create(
        user=aws_account.user,
        aws_account=aws_account,
        region_scanned=region,
        total_resources=len(saved_rows),
        total_services=len({r['service_name'] for r, _ in saved_rows}),
        total_monthly_cost=_to_decimal(total_cost),
        total_savings_monthly=_to_decimal(total_savings),
        ai_summary=summary_text or '',
        ai_summary_data=_json_safe({'top_findings': sorted_by_savings[:12]}),
        scan_duration_seconds=scan_duration,
        ai_calls_made=ai_calls_made,
        ai_calls_skipped=ai_calls_skipped,
    )

    logger.info(f"✅ Scan complete in {scan_duration}s — AI calls: {ai_calls_made} made, {ai_calls_skipped} skipped")

    return build_response(aws_account, region, cached=False)


# ============================================================
# BUILD RESPONSE FROM DB
# ============================================================

def build_response(aws_account, region, cached=False):
    resources = ResourceAIAnalysis.objects.filter(
        aws_account=aws_account, region_scanned=region,
    )

    summary = BreakdownSummary.objects.filter(
        aws_account=aws_account, region_scanned=region,
    ).first()

    services_map = {}
    for r in resources:
        key = r.service_name
        if key not in services_map:
            services_map[key] = {
                'service_name': r.service_name,
                'service_category': r.service_category,
                'status': 'Active',
                'resource_count': 0,
                'monthly_cost': 0.0,
                'savings': 0.0,
                'resources': [],
            }

        services_map[key]['resource_count'] += 1
        services_map[key]['monthly_cost'] += float(r.monthly_cost)
        services_map[key]['savings'] += float(r.ai_savings_monthly)

        services_map[key]['resources'].append({
            'resource_id': r.resource_id,
            'resource_name': r.resource_name,
            'resource_type': r.resource_type,
            'region': r.region,
            'service_name': r.service_name,
            'service_category': r.service_category,
            'status': r.status,
            'on_since': r.on_since.isoformat() if r.on_since else None,
            'last_checked': r.last_checked.isoformat() if r.last_checked else None,
            'cpu_avg': r.cpu_avg,
            'monthly_cost': float(r.monthly_cost),
            'ai_verdict': r.ai_verdict,
            'ai_short_reason': r.ai_short_reason,
            'ai_detailed_explanation': r.ai_detailed_explanation,
            'ai_savings_monthly': float(r.ai_savings_monthly),
            'ai_savings_yearly': float(r.ai_savings_yearly),
            'ai_risk': r.ai_risk,
            'ai_steps': r.ai_steps,
            'ai_alternatives': r.ai_alternatives,
            'ai_time_to_fix': r.ai_time_to_fix,
            'ai_one_click_available': r.ai_one_click_available,
            'ai_priority': r.ai_priority,
            'tags': r.tags,
            'resource_details': r.resource_details,
        })

    for svc in services_map.values():
        idle = sum(1 for r in svc['resources'] if r['ai_verdict'] in ['STOP_IT', 'TERMINATE_IT'])
        if idle == svc['resource_count'] and svc['resource_count'] > 0:
            svc['status'] = 'Idle'
        elif idle > 0:
            svc['status'] = 'Partially Idle'
        else:
            svc['status'] = 'Active'
        svc['monthly_cost'] = round(svc['monthly_cost'], 2)
        svc['savings'] = round(svc['savings'], 2)

    services_list = sorted(services_map.values(), key=lambda x: x['monthly_cost'], reverse=True)
    all_resources_list = sorted(
        [r for s in services_list for r in s['resources']],
        key=lambda x: (-x['ai_priority'], -x['monthly_cost']),
    )

    total_cost = round(sum(s['monthly_cost'] for s in services_list), 2)
    total_savings = round(sum(s['savings'] for s in services_list), 2)

    return {
        'success': True,
        'cached': cached,
        'region': region,
        'total_services': len(services_list),
        'total_resources': len(all_resources_list),
        'total_monthly_cost': total_cost,
        'total_savings': total_savings,
        'services': services_list,
        'resources': all_resources_list,
        'summary': {
            'ai_summary': summary.ai_summary if summary else '',
            'top_findings': (summary.ai_summary_data or {}).get('top_findings', []) if summary else [],
            'scan_duration_seconds': summary.scan_duration_seconds if summary else None,
            'ai_calls_made': summary.ai_calls_made if summary else 0,
            'ai_calls_skipped': summary.ai_calls_skipped if summary else 0,
            'scanned_at': summary.scanned_at.isoformat() if summary else None,
        },
        'last_scan': django_timezone.now().isoformat(),
    }