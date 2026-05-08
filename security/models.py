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