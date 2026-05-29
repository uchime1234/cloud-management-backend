# security/encryption_ai_recommendations.py

import requests
from django.conf import settings
import logging
# Add these imports at the top of encryption_ai_recommendations.py

from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger(__name__)


def generate_encryption_recommendation(resource_data):
    """
    Generate AI-powered encryption recommendation for a resource
    """
    
    resource_type = resource_data.get('resource_type')
    resource_name = resource_data.get('resource_name')
    is_encrypted = resource_data.get('is_encrypted', False)
    encryption_type = resource_data.get('encryption_type', 'None')
    environment = resource_data.get('environment', 'unknown')
    contains_sensitive = resource_data.get('contains_sensitive', False)
    
    # Build context for AI
    context = f"""
Resource: {resource_type} - {resource_name}
Currently Encrypted: {is_encrypted}
Encryption Type: {encryption_type}
Environment: {environment}
Contains Sensitive Data: {contains_sensitive}
"""
    
    prompt = f"""As a Senior AWS Security Expert, provide a specific encryption recommendation for this resource.

{context}

Provide a response in this exact JSON format:
{{
    "recommendation_type": "one of: enable_encryption, upgrade_to_kms, use_customer_key, migrate_encrypted, already_secure, no_action_needed",
    "recommendation_title": "Short actionable title",
    "recommendation_description": "What to do (2-3 sentences)",
    "recommendation_reason": "Why this matters (2-3 sentences explaining the risk/benefit)",
    "risk_reduction": "Specific risk reduction percentage or description",
    "compliance_benefit": "Which compliance standards this helps with",
    "estimated_time": "Time estimate e.g., '5 minutes', '1 hour'",
    "difficulty": "easy/medium/hard",
    "one_click_available": true/false,
    "one_click_action_type": "If available: enable_bucket_encryption, enable_queue_encryption, enable_topic_encryption, enable_kms, etc.",
    "migration_required": true/false,
    "migration_steps": ["Step 1", "Step 2", "Step 3"] (if migration_required is true)
}}

For S3 buckets:
- If unencrypted: recommend enable_bucket_encryption with SSE-S3
- For production data: recommend KMS with customer-managed key
- For logs/backups: SSE-S3 is sufficient

For RDS databases:
- Direct encryption not possible for existing databases
- Recommend migrating via snapshot or read replica
- Provide migration steps

For EBS volumes:
- Recommend creating encrypted snapshot and new volume
- Provide replacement steps

For SQS/SNS:
- One-click enable encryption is available
- Use AWS managed KMS key by default

For Lambda functions with env vars:
- One-click enable KMS encryption is available

Be specific and actionable. Make the recommendation sound intelligent and professional."""
    
    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": "You are a Senior AWS Security Expert. Respond only with valid JSON. Be specific and actionable."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7,
        "max_tokens": 800,
        "response_format": {"type": "json_object"}
    }
    
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            import json
            return json.loads(result['choices'][0]['message']['content'])
        else:
            logger.error(f"Groq API error: {response.status_code}")
            return get_fallback_recommendation(resource_data)
            
    except Exception as e:
        logger.error(f"Error generating AI recommendation: {e}")
        return get_fallback_recommendation(resource_data)


def get_fallback_recommendation(resource_data):
    """Fallback recommendations if AI API fails"""
    
    resource_type = resource_data.get('resource_type')
    is_encrypted = resource_data.get('is_encrypted', False)
    
    fallbacks = {
        's3_bucket': {
            'recommendation_type': 'enable_encryption' if not is_encrypted else 'already_secure',
            'recommendation_title': 'Enable S3 Bucket Encryption' if not is_encrypted else 'Bucket is Already Encrypted',
            'recommendation_description': 'Enable server-side encryption to protect data at rest.' if not is_encrypted else 'This bucket already has encryption enabled.',
            'recommendation_reason': 'Unencrypted S3 buckets expose data to unauthorized access if compromised.' if not is_encrypted else 'No action needed - encryption is already configured.',
            'risk_reduction': 'Eliminates data exposure risk from stolen disks',
            'compliance_benefit': 'Helps meet SOC2, ISO27001 requirements',
            'estimated_time': '2 minutes',
            'difficulty': 'easy',
            'one_click_available': True,
            'one_click_action_type': 'enable_bucket_encryption',
            'migration_required': False,
            'migration_steps': []
        },
        'sqs_queue': {
            'recommendation_type': 'enable_encryption' if not is_encrypted else 'already_secure',
            'recommendation_title': 'Enable SQS Queue Encryption' if not is_encrypted else 'Queue is Already Encrypted',
            'recommendation_description': 'Enable KMS encryption for messages in transit and at rest.' if not is_encrypted else 'This queue already has encryption enabled.',
            'recommendation_reason': 'Unencrypted queues expose sensitive message data.' if not is_encrypted else 'No action needed.',
            'risk_reduction': 'Protects message content from unauthorized access',
            'compliance_benefit': 'Helps meet data protection requirements',
            'estimated_time': '2 minutes',
            'difficulty': 'easy',
            'one_click_available': True,
            'one_click_action_type': 'enable_queue_encryption',
            'migration_required': False,
            'migration_steps': []
        },
        'ec2_volume': {
            'recommendation_type': 'migrate_encrypted' if not is_encrypted else 'already_secure',
            'recommendation_title': 'Migrate to Encrypted EBS Volume' if not is_encrypted else 'Volume is Already Encrypted',
            'recommendation_description': 'Create an encrypted snapshot and replacement volume.' if not is_encrypted else 'This volume already has encryption enabled.',
            'recommendation_reason': 'Unencrypted EBS volumes expose all disk data if compromised.' if not is_encrypted else 'No action needed.',
            'risk_reduction': 'Protects all data stored on the volume',
            'compliance_benefit': 'Required for HIPAA, PCI compliance',
            'estimated_time': '15 minutes',
            'difficulty': 'medium',
            'one_click_available': True,
            'one_click_action_type': 'migrate_encrypted_snapshot',
            'migration_required': True,
            'migration_steps': [
                'Stop the EC2 instance',
                'Detach the original volume',
                'Attach the new encrypted volume',
                'Start the EC2 instance',
                'Verify data integrity'
            ]
        },
        'rds': {
            'recommendation_type': 'migrate_encrypted' if not is_encrypted else 'already_secure',
            'recommendation_title': 'Migrate to Encrypted RDS Instance' if not is_encrypted else 'Database is Already Encrypted',
            'recommendation_description': 'Create an encrypted snapshot and restore as new encrypted instance.' if not is_encrypted else 'This database already has encryption enabled.',
            'recommendation_reason': 'Unencrypted production databases are a critical security risk.' if not is_encrypted else 'No action needed.',
            'risk_reduction': 'Protects all database content from storage-level access',
            'compliance_benefit': 'Required for financial, healthcare, and government data',
            'estimated_time': '30-60 minutes',
            'difficulty': 'hard',
            'one_click_available': False,
            'one_click_action_type': '',
            'migration_required': True,
            'migration_steps': [
                'Take a final snapshot of the current instance',
                'Create an encrypted copy of the snapshot',
                'Restore a new encrypted instance from the encrypted snapshot',
                'Update application connection strings',
                'Verify data integrity',
                'Delete the original unencrypted instance'
            ]
        }
    }
    
    return fallbacks.get(resource_type, {
        'recommendation_type': 'enable_encryption' if not is_encrypted else 'already_secure',
        'recommendation_title': f'Enable Encryption on {resource_type}' if not is_encrypted else 'Resource is Encrypted',
        'recommendation_description': f'Enable encryption to protect this {resource_type}.' if not is_encrypted else 'This resource already has encryption enabled.',
        'recommendation_reason': 'Unencrypted resources increase data exposure risk.' if not is_encrypted else 'No action needed.',
        'risk_reduction': 'Significantly reduces data exposure risk',
        'compliance_benefit': 'Helps meet security compliance requirements',
        'estimated_time': '10 minutes',
        'difficulty': 'medium',
        'one_click_available': False,
        'one_click_action_type': '',
        'migration_required': not is_encrypted,
        'migration_steps': ['Review AWS documentation for encryption options'] if not is_encrypted else []
    })


def generate_recommendations_for_all_resources(aws_account, findings):
    """Generate AI recommendations for all resources"""
    from .models import EncryptionRecommendation
    
    recommendations = []
    
    for finding in findings:
        # Skip if already has a recent recommendation (less than 24 hours)
        existing = EncryptionRecommendation.objects.filter(
            aws_account=aws_account,
            resource_id=finding['resource_id'],
            generated_at__gte=timezone.now() - timedelta(hours=24)
        ).first()
        
        if existing:
            recommendations.append(existing)
            continue
        
        # Generate new recommendation
        ai_result = generate_encryption_recommendation(finding)
        
        if ai_result:
            rec = EncryptionRecommendation.objects.create(
                user_id=aws_account.user_id,
                aws_account=aws_account,
                resource_type=finding['resource_type'],
                resource_id=finding['resource_id'],
                resource_name=finding['resource_name'],
                region=finding.get('region', ''),
                is_encrypted=finding['is_encrypted'],
                current_encryption_type=finding.get('encryption_type', 'None'),
                recommendation_type=ai_result.get('recommendation_type', 'enable_encryption'),
                recommendation_title=ai_result.get('recommendation_title', ''),
                recommendation_description=ai_result.get('recommendation_description', ''),
                recommendation_reason=ai_result.get('recommendation_reason', ''),
                risk_reduction=ai_result.get('risk_reduction', ''),
                compliance_benefit=ai_result.get('compliance_benefit', ''),
                estimated_time=ai_result.get('estimated_time', ''),
                difficulty=ai_result.get('difficulty', 'medium'),
                one_click_available=ai_result.get('one_click_available', False),
                one_click_action_type=ai_result.get('one_click_action_type', ''),
                migration_required=ai_result.get('migration_required', False),
                migration_steps=ai_result.get('migration_steps', [])
            )
            recommendations.append(rec)
    
    return recommendations