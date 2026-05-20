from django.db import models
from django.conf import settings
from myground.models import AWSAccount

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