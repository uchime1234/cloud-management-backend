from django.db import models
from django.conf import settings
from myground.models import AWSAccount
from django.contrib.postgres.fields import JSONField
from django.utils import timezone
import uuid

class IAMFinding(models.Model):
    FINDING_TYPES = [
        ('admin_user', 'Administrative User'),
        ('wildcard_role', 'Wildcard Role'),
        ('unused_user', 'Unused User'),
        ('old_key', 'Old Access Key'),
        ('multiple_keys', 'Multiple Active Keys'),
        ('no_mfa', 'No MFA Enabled'),
    ]
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='iam_findings'
    )
    aws_account = models.ForeignKey(
        AWSAccount,
        on_delete=models.CASCADE,
        related_name='iam_findings'
    )
    finding_type = models.CharField(max_length=50, choices=FINDING_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='low')
    resource_name = models.CharField(max_length=255, blank=True, help_text='Name of the IAM user/role')
    title = models.CharField(max_length=200)
    description = models.TextField()
    recommendation = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['aws_account', 'severity']),
            models.Index(fields=['aws_account', 'is_resolved']),
        ]
    
    def __str__(self):
        return f"{self.get_finding_type_display()} - {self.resource_name} ({self.severity})"


class IAMSecurityReport(models.Model):
    """Stores the AI-generated security report for each scan"""
    aws_account = models.OneToOneField(
        AWSAccount,
        on_delete=models.CASCADE,
        related_name='iam_security_report'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='iam_security_reports'
    )
    ai_recommendations = models.TextField()
    total_findings = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Security Report for {self.aws_account.account_alias} - {self.created_at.strftime('%Y-%m-%d')}"
    

# Add to security/models.py

class PublicExposureFinding(models.Model):
    """Stores public exposure findings from AWS resources"""
    
    EXPOSURE_TYPES = [
        ('public_ec2', 'Public EC2 Instance'),
        ('open_sg_rule', 'Open Security Group Rule'),
        ('public_rds', 'Public RDS Instance'),
        ('public_s3', 'Public S3 Bucket'),
        ('public_lb', 'Public Load Balancer'),
        ('public_eks', 'Public EKS Cluster'),
        ('public_redis', 'Public Redis/Cache Cluster'),
        ('public_opensearch', 'Public OpenSearch/Elasticsearch'),
        ('public_api', 'Public API Gateway'),
        ('missing_waf', 'Missing WAF Protection'),
    ]
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='public_exposure_findings'
    )
    
    aws_account = models.ForeignKey(
        'myground.AWSAccount',
        on_delete=models.CASCADE,
        related_name='public_exposure_findings'
    )
    
    exposure_type = models.CharField(max_length=50, choices=EXPOSURE_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    resource_name = models.CharField(max_length=500)
    resource_id = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=50, blank=True)
    
    # Specific fields for different exposure types
    public_ip = models.CharField(max_length=50, blank=True)
    port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, blank=True)
    cidr = models.CharField(max_length=50, blank=True)
    security_group_name = models.CharField(max_length=255, blank=True)
    security_group_id = models.CharField(max_length=100, blank=True)
    
    # Additional metadata
    details = models.JSONField(default=dict, blank=True)
    title = models.CharField(max_length=500)
    description = models.TextField()
    recommendation = models.TextField()
    
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-severity', '-detected_at']
        indexes = [
            models.Index(fields=['aws_account', 'severity']),
            models.Index(fields=['aws_account', 'exposure_type']),
            models.Index(fields=['aws_account', 'is_resolved']),
        ]
    
    def __str__(self):
        return f"{self.get_exposure_type_display()} - {self.resource_name} ({self.severity})"


class PublicExposureReport(models.Model):
    """Stores AI-generated public exposure risk analysis"""
    
    aws_account = models.OneToOneField(
        'myground.AWSAccount',
        on_delete=models.CASCADE,
        related_name='public_exposure_report'
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='public_exposure_reports'
    )
    
    ai_analysis = models.TextField()
    total_findings = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Public Exposure Report for {self.aws_account.account_alias} - {self.created_at.strftime('%Y-%m-%d')}"


# Add to security/models.py

from django.db import models
from django.conf import settings
from django.utils import timezone

class SecurityGroupAnalysis(models.Model):
    """Main model for security group analysis results"""
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('orphaned', 'Orphaned'),
        ('deleted', 'Deleted'),
    ]
    
    # Basic info
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sg_analyses')
    aws_account = models.ForeignKey('myground.AWSAccount', on_delete=models.CASCADE, related_name='sg_analyses')
    
    # Security Group details
    sg_id = models.CharField(max_length=100)
    sg_name = models.CharField(max_length=500)
    sg_description = models.TextField(blank=True)
    vpc_id = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=50)
    
    # Attached resources
    attached_resources = models.JSONField(default=list)  # List of EC2, LB, RDS, etc.
    is_orphaned = models.BooleanField(default=False)
    
    # Scoring
    health_score = models.IntegerField(default=100)  # 0-100
    risk_score = models.IntegerField(default=0)  # 0-100
    overall_severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='LOW')
    
    # Risk findings
    risk_findings = models.JSONField(default=list)
    open_world_rules = models.JSONField(default=list)
    exposed_ports = models.JSONField(default=list)
    dangerous_protocols = models.JSONField(default=list)
    unrestricted_inbound = models.BooleanField(default=False)
    unrestricted_outbound = models.BooleanField(default=False)
    
    # Duplicate detection
    duplicate_candidates = models.JSONField(default=list)
    is_duplicate = models.BooleanField(default=False)
    
    # Traffic insights
    traffic_insights = models.JSONField(default=dict)
    
    # Change history
    change_history = models.JSONField(default=list)
    
    # AI Recommendation
    ai_recommendation = models.TextField(blank=True)
    ai_recommendation_structured = models.JSONField(default=dict)
    
    # Metadata
    last_analyzed_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_stale = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-last_analyzed_at']
        unique_together = ['aws_account', 'sg_id']
        indexes = [
            models.Index(fields=['aws_account', 'overall_severity']),
            models.Index(fields=['aws_account', 'is_orphaned']),
            models.Index(fields=['last_analyzed_at']),
        ]
    
    def __str__(self):
        return f"{self.sg_name} ({self.sg_id}) - {self.overall_severity}"


class SecurityGroupChangeLog(models.Model):
    """Track individual rule changes for security groups"""
    
    CHANGE_TYPES = [
        ('rule_added', 'Rule Added'),
        ('rule_removed', 'Rule Removed'),
        ('rule_modified', 'Rule Modified'),
    ]
    
    security_group = models.ForeignKey(SecurityGroupAnalysis, on_delete=models.CASCADE, related_name='change_logs')
    
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPES)
    changed_by = models.CharField(max_length=255, blank=True)  # IAM user/role
    changed_at = models.DateTimeField()
    
    before_value = models.JSONField(default=dict, blank=True)
    after_value = models.JSONField(default=dict, blank=True)
    description = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-changed_at']


class SecurityGroupAnalysisCache(models.Model):
    """Cache control for security group analysis"""
    
    aws_account = models.OneToOneField('myground.AWSAccount', on_delete=models.CASCADE, related_name='sg_cache')
    last_full_scan = models.DateTimeField(null=True, blank=True)
    scan_in_progress = models.BooleanField(default=False)
    total_security_groups = models.IntegerField(default=0)
    analyzed_count = models.IntegerField(default=0)
    cache_version = models.IntegerField(default=1)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Cache for {self.aws_account.account_alias}"


# Add to security/models.py

class EncryptionFinding(models.Model):
    """Stores encryption status for AWS resources"""
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    RESOURCE_TYPES = [
        ('ec2_volume', 'EC2 Volume'),
        ('ebs_snapshot', 'EBS Snapshot'),
        ('ami', 'AMI'),
        ('rds', 'RDS Instance'),
        ('aurora', 'Aurora Cluster'),
        ('redshift', 'Redshift Cluster'),
        ('s3_bucket', 'S3 Bucket'),
        ('s3_object', 'S3 Object'),
        ('eks_secret', 'EKS Secret'),
        ('ecs_task', 'ECS Task Definition'),
        ('sqs_queue', 'SQS Queue'),
        ('sns_topic', 'SNS Topic'),
        ('cloudwatch_log_group', 'CloudWatch Log Group'),
        ('secretsmanager_secret', 'Secrets Manager Secret'),
        ('efs_filesystem', 'EFS File System'),
        ('elasticache_cluster', 'ElastiCache Cluster'),
        ('dynamodb_table', 'DynamoDB Table'),
        ('lambda_function', 'Lambda Function'),
        ('kinesis_stream', 'Kinesis Stream'),
        ('efs_backup', 'EFS Backup'),
        ('rds_backup', 'RDS Backup'),
        ('redshift_backup', 'Redshift Backup'),
        ('ebs_backup', 'EBS Backup'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='encryption_findings')
    aws_account = models.ForeignKey('myground.AWSAccount', on_delete=models.CASCADE, related_name='encryption_findings')
    
    # Resource identification
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPES)
    resource_id = models.CharField(max_length=500)
    resource_name = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=50, blank=True)
    
    # Encryption status
    is_encrypted = models.BooleanField(default=False)
    encryption_type = models.CharField(max_length=100, blank=True)  # AES-256, KMS, SSE-S3, etc.
    kms_key_id = models.CharField(max_length=500, blank=True)
    is_customer_managed_key = models.BooleanField(default=False)
    
    # Risk assessment
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    risk_score = models.IntegerField(default=0)  # 0-100
    business_risk = models.TextField(blank=True)
    
    # Resource context
    environment = models.CharField(max_length=50, blank=True)  # production, staging, development
    contains_pii = models.BooleanField(default=False)
    contains_pci = models.BooleanField(default=False)
    contains_phi = models.BooleanField(default=False)
    
    # Metadata
    size_gb = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    last_modified = models.DateTimeField(null=True, blank=True)
    
    # Fixes
    fix_recommendation = models.TextField()
    fix_difficulty = models.CharField(max_length=20, choices=[
        ('easy', 'Easy (< 5 minutes)'),
        ('medium', 'Medium (5-30 minutes)'),
        ('hard', 'Hard (> 30 minutes)')
    ], default='medium')
    
    # Metadata
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-severity', '-risk_score']
        indexes = [
            models.Index(fields=['aws_account', 'severity']),
            models.Index(fields=['aws_account', 'is_encrypted']),
            models.Index(fields=['resource_type', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.resource_type}: {self.resource_name} - {'Encrypted' if self.is_encrypted else 'NOT Encrypted'} ({self.severity})"


class EncryptionSummary(models.Model):
    """Cached encryption summary for dashboard"""
    
    aws_account = models.OneToOneField('myground.AWSAccount', on_delete=models.CASCADE, related_name='encryption_summary')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    
    # Coverage metrics
    total_resources = models.IntegerField(default=0)
    encrypted_resources = models.IntegerField(default=0)
    unencrypted_resources = models.IntegerField(default=0)
    encryption_coverage = models.IntegerField(default=0)  # percentage
    
    # Risk counts
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    
    # By resource type
    resource_breakdown = models.JSONField(default=dict)
    
    # KMS metrics
    total_kms_keys = models.IntegerField(default=0)
    customer_managed_keys = models.IntegerField(default=0)
    aws_managed_keys = models.IntegerField(default=0)
    
    # Recently encrypted (last 30 days)
    recently_encrypted = models.JSONField(default=list)
    
    # Metadata
    last_scan_at = models.DateTimeField(auto_now_add=True)
    scan_duration_seconds = models.FloatField(null=True, blank=True)
    
    class Meta:
        ordering = ['-last_scan_at']
    
    def __str__(self):
        return f"Encryption Summary for {self.aws_account.account_alias} - {self.encryption_coverage}%"


class EncryptionScanCache(models.Model):
    """Cache control for encryption scans"""
    
    aws_account = models.OneToOneField('myground.AWSAccount', on_delete=models.CASCADE, related_name='encryption_cache')
    last_full_scan = models.DateTimeField(null=True, blank=True)
    scan_in_progress = models.BooleanField(default=False)
    resources_scanned = models.IntegerField(default=0)
    total_resources = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Encryption cache for {self.aws_account.account_alias}"

# Add to security/models.py

class EncryptionAction(models.Model):
    """Track encryption actions taken by users"""
    
    ACTION_TYPES = [
        ('enable_sse', 'Enable SSE-S3'),
        ('enable_kms', 'Enable KMS Encryption'),
        ('enable_bucket_encryption', 'Enable Bucket Encryption'),
        ('enable_queue_encryption', 'Enable Queue Encryption'),
        ('enable_topic_encryption', 'Enable Topic Encryption'),
        ('enable_log_encryption', 'Enable Log Encryption'),
        ('enable_efs_encryption', 'Enable EFS Encryption'),
        ('migrate_encrypted_snapshot', 'Migrate via Encrypted Snapshot'),
        ('create_encrypted_copy', 'Create Encrypted Copy'),
        ('enable_default_encryption', 'Enable Default Encryption'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('requires_manual', 'Requires Manual Action'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='encryption_actions')
    aws_account = models.ForeignKey('myground.AWSAccount', on_delete=models.CASCADE, related_name='encryption_actions')
    
    # Target resource
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=500)
    resource_name = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=50, blank=True)
    
    # Action details
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    action_params = models.JSONField(default=dict)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    status_message = models.TextField(blank=True)
    
    # Results
    result_details = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # For resources requiring manual intervention
    requires_migration = models.BooleanField(default=False)
    migration_workflow = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action_type} on {self.resource_name} - {self.status}"


class EncryptionRecommendation(models.Model):
    """AI-generated encryption recommendations"""
    
    RECOMMENDATION_TYPES = [
        ('enable_encryption', 'Enable Encryption'),
        ('upgrade_to_kms', 'Upgrade to KMS'),
        ('use_customer_key', 'Use Customer-Managed Key'),
        ('migrate_encrypted', 'Migrate to Encrypted'),
        ('already_secure', 'Already Secure'),
        ('no_action_needed', 'No Action Needed'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='encryption_recommendations')
    aws_account = models.ForeignKey('myground.AWSAccount', on_delete=models.CASCADE, related_name='encryption_recommendations')
    
    # Target resource
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=500)
    resource_name = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=50, blank=True)
    
    # Current status
    is_encrypted = models.BooleanField(default=False)
    current_encryption_type = models.CharField(max_length=100, blank=True)
    
    # AI Recommendation
    recommendation_type = models.CharField(max_length=50, choices=RECOMMENDATION_TYPES)
    recommendation_title = models.CharField(max_length=500)
    recommendation_description = models.TextField()
    recommendation_reason = models.TextField()
    
    # Risk/benefit analysis
    risk_reduction = models.CharField(max_length=100, blank=True)  # e.g., "Eliminates 85% of data exposure risk"
    compliance_benefit = models.CharField(max_length=200, blank=True)  # e.g., "Helps meet SOC2, HIPAA requirements"
    
    # Technical details
    estimated_time = models.CharField(max_length=100, blank=True)
    difficulty = models.CharField(max_length=20, choices=[
        ('easy', 'Easy - Click to fix'),
        ('medium', 'Medium - Some manual steps'),
        ('hard', 'Hard - Requires migration')
    ], default='easy')
    
    # One-click action availability
    one_click_available = models.BooleanField(default=False)
    one_click_action_type = models.CharField(max_length=50, blank=True)
    
    # Migration workflow (if needed)
    migration_required = models.BooleanField(default=False)
    migration_steps = models.JSONField(default=list, blank=True)
    
    # Metadata
    generated_at = models.DateTimeField(auto_now_add=True)
    is_applied = models.BooleanField(default=False)
    applied_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-generated_at']
        unique_together = ['aws_account', 'resource_id']
    
    def __str__(self):
        return f"{self.resource_name}: {self.recommendation_title}"


# Add to security/models.py

class SecurityGroupAuditLog(models.Model):
    """Audit log for security group changes"""
    
    ACTION_CHOICES = [
        ('rule_added', 'Rule Added'),
        ('rule_removed', 'Rule Removed'),
        ('rule_modified', 'Rule Modified'),
        ('group_created', 'Group Created'),
        ('group_deleted', 'Group Deleted'),
        ('group_modified', 'Group Modified'),
    ]
    
    security_group = models.ForeignKey('SecurityGroupAnalysis', on_delete=models.CASCADE, related_name='audit_logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=255, blank=True)  # IAM user/role
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    summary = models.CharField(max_length=500)
    before = models.JSONField(default=dict, blank=True)
    after = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.security_group.security_group_name} - {self.action} at {self.timestamp}"