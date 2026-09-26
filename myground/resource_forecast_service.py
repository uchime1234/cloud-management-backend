# myground/resource_forecast_service.py
"""
Resource Forecast Engine

Reads the current Service & Resource Breakdown cache (ResourceAIAnalysis)
for one account + region and produces:

    - Tomorrow cost       = sum(monthly_cost) * 12 / 365
    - Next month cost     = sum(monthly_cost)
    - Next 3 months cost  = sum(monthly_cost) * 3

Plus a short AI paragraph explaining what staying still costs the user.

Everything is cached in ResourceForecast per (account, region) forever.
Only explicit user action deletes a forecast.
"""

import json
import logging
import requests
from decimal import Decimal

from django.conf import settings

from .models import ResourceAIAnalysis, ResourceForecast

logger = logging.getLogger(__name__)

GROQ_MODEL = 'openai/gpt-oss-120b'


# ============================================================
# helpers
# ============================================================

def _to_decimal(v):
    try:
        return Decimal(str(v))
    except Exception:
        return Decimal('0')


def _build_top_resources(rows):
    """
    Returns a sorted list of dicts for the frontend bar list.
    Sorted highest cost first.
    """
    total_cost = sum(float(r.monthly_cost) for r in rows) or 1.0

    ranked = sorted(rows, key=lambda r: float(r.monthly_cost), reverse=True)

    return [
        {
            'resource_id': r.resource_id,
            'resource_name': r.resource_name,
            'service_name': r.service_name,
            'service_category': r.service_category,
            'resource_type': r.resource_type,
            'region': r.region,
            'monthly_cost': round(float(r.monthly_cost), 2),
            'percentage': round((float(r.monthly_cost) / total_cost) * 100, 2),
            'ai_verdict': r.ai_verdict,
            'ai_savings_monthly': round(float(r.ai_savings_monthly), 2),
        }
        for r in ranked
    ]


# ============================================================
# AI summary
# ============================================================

def _generate_summary(region, tomorrow, next_month, three_month, top_resources, resource_count):
    """
    One Groq call. Produces a 3-5 sentence paragraph.
    """
    top_lines = '\n'.join(
        f"- {r['service_name']} · {r['resource_id']} — ${r['monthly_cost']}/mo ({r['percentage']}%) — verdict {r['ai_verdict']}"
        for r in top_resources[:5]
    ) or 'No resources.'

    prompt = f"""You are a Senior AWS FinOps Expert. You are explaining a forecast to a user.

REGION: {region}
RESOURCES SCANNED: {resource_count}

PROJECTION (assuming nothing changes):
- Tomorrow: ${tomorrow}
- Next month: ${next_month}
- Next 3 months: ${three_month}

TOP 5 RESOURCES BY COST:
{top_lines}

Write a short paragraph (3-5 sentences max) that:
1. States the monthly baseline clearly.
2. Names the #1 cost driver by resource type/service.
3. Points out if any of the top resources already have a STOP_IT / TERMINATE_IT verdict — that means the user can act immediately.
4. Ends with one concrete next action.

Tone: direct, confident, no fluff. Speak to the user as "you" and "your account".
No markdown. No bullet lists. Just plain prose.
"""

    try:
        headers = {
            'Authorization': f'Bearer {settings.GROQ_API_KEY}',
            'Content-Type': 'application/json',
        }
        payload = {
            'model': GROQ_MODEL,
            'messages': [
                {'role': 'system', 'content': 'You are a Senior AWS FinOps Expert. Be direct and concise.'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.6,
            'max_tokens': 400,
        }
        r = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers, json=payload, timeout=30,
        )
        if r.status_code == 200:
            return r.json()['choices'][0]['message']['content'].strip()
        logger.error(f"Groq forecast summary error: {r.status_code} - {r.text}")
    except Exception as e:
        logger.error(f"Groq forecast summary exception: {e}")

    # Fallback summary if AI fails
    return (
        f"At current usage your {region} resources cost ${next_month} per month. "
        f"Across the next 3 months that's ${three_month} if nothing changes. "
        f"Review the top resource below to see where the biggest cost sits."
    )


# ============================================================
# MAIN ENTRY
# ============================================================

def generate_resource_forecast(aws_account, region, force_refresh=False):
    """
    Builds (or returns cached) a ResourceForecast for one account + region.
    """

    # ---------- CACHE HIT ----------
    if not force_refresh:
        cached = ResourceForecast.objects.filter(
            aws_account=aws_account, region_scanned=region
        ).first()
        if cached:
            logger.info(f"📦 Forecast cache hit for {region}")
            return _build_response(cached, cached=True)

    # ---------- CACHE MISS ----------
    rows = list(
        ResourceAIAnalysis.objects.filter(
            aws_account=aws_account, region_scanned=region
        )
    )

    if not rows:
        return {
            'error': 'no_resources',
            'message': (
                f'No resources have been scanned for region {region} yet. '
                f'Go to Service & Resource Breakdown, pick the region, and scan first.'
            ),
            'region': region,
        }

    total_monthly = sum(float(r.monthly_cost) for r in rows)
    tomorrow = round(total_monthly * 12 / 365, 2)
    next_month = round(total_monthly, 2)
    three_month = round(total_monthly * 3, 2)

    top_resources = _build_top_resources(rows)

    ai_summary = _generate_summary(
        region=region,
        tomorrow=tomorrow,
        next_month=next_month,
        three_month=three_month,
        top_resources=top_resources,
        resource_count=len(rows),
    )

    # Upsert
    forecast, _ = ResourceForecast.objects.update_or_create(
        aws_account=aws_account,
        region_scanned=region,
        defaults={
            'user': aws_account.user,
            'tomorrow_cost': _to_decimal(tomorrow),
            'next_month_cost': _to_decimal(next_month),
            'three_month_cost': _to_decimal(three_month),
            'total_monthly_cost': _to_decimal(next_month),
            'resource_count': len(rows),
            'top_resources': top_resources,
            'ai_summary': ai_summary,
        },
    )

    logger.info(f"✅ Forecast generated for {region} — ${next_month}/mo")
    return _build_response(forecast, cached=False)


def _build_response(forecast, cached=False):
    return {
        'success': True,
        'cached': cached,
        'region': forecast.region_scanned,
        'tomorrow_cost': float(forecast.tomorrow_cost),
        'next_month_cost': float(forecast.next_month_cost),
        'three_month_cost': float(forecast.three_month_cost),
        'total_monthly_cost': float(forecast.total_monthly_cost),
        'resource_count': forecast.resource_count,
        'top_resources': forecast.top_resources,
        'ai_summary': forecast.ai_summary,
        'scanned_at': forecast.scanned_at.isoformat(),
    }


def clear_resource_forecast(aws_account, region):
    deleted, _ = ResourceForecast.objects.filter(
        aws_account=aws_account, region_scanned=region
    ).delete()
    return deleted