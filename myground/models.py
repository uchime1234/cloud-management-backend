from django.db import models
from django.contrib.auth.models import User
import pyotp
import uuid
from django.utils import timezone
import uuid
from cryptography.fernet import Fernet
from django.conf import settings
import base64
import os

# Your existing VerificationCode model
class VerificationCode(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.email}"

# Your existing MFA models
class MFAConfiguration(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mfa_config')
    secret_key = models.CharField(max_length=32, unique=True)
    is_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"MFA Config for {self.user.username}"
    
    def get_totp_uri(self, issuer_name="Cloud Management"):
        totp = pyotp.TOTP(self.secret_key)
        return totp.provisioning_uri(
            name=self.user.email,
            issuer_name=issuer_name
        )
    
    def verify_code(self, code):
        totp = pyotp.TOTP(self.secret_key)
        return totp.verify(code)

class BackupCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='backup_codes')
    code = models.CharField(max_length=25, unique=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Backup code for {self.user.username}"

class MFALog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_logs')
    action = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']

# ============================================================
# ADD THESE TO YOUR EXISTING models.py
# ============================================================

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class AWSAccount(models.Model):
    """
    Stores a user's connected AWS account.
    Uses cross-account IAM Role assumption (secure, no long-term credentials stored).
    """
    
    STATUS_CHOICES = [
        ('pending', 'Pending Verification'),
        ('connected', 'Connected'),
        ('failed', 'Connection Failed'),
        ('disconnected', 'Disconnected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='aws_accounts')
    account_id = models.CharField(max_length=12, help_text="12-digit AWS Account ID")
    account_alias = models.CharField(max_length=100, blank=True, help_text="Friendly name for this account")
    role_arn = models.CharField(
        max_length=2048,
        help_text="ARN of the IAM role to assume, e.g. arn:aws:iam::123456789012:role/CostAnalyticsRole"
    )
    external_id = models.CharField(
        max_length=64,
        unique=True,
        default=uuid.uuid4,
        help_text="Unique external ID to prevent confused deputy attacks"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    connected_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'account_id')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} → AWS {self.account_id} ({self.status})"




class AWSCostCache(models.Model):
    """
    Caches AWS cost data to avoid repeated API calls to AWS
    """
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='cost_caches')
    
    # Cache metadata
    cache_key = models.CharField(max_length=100, unique=True)  # e.g., "90_days", "monthly", "7_days", "yesterday"
    cache_data = models.JSONField()  # Stores the actual cost data
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()  # When this cache should be considered stale
    
    class Meta:
        unique_together = ('aws_account', 'cache_key')  # One cache per account per key
        indexes = [
            models.Index(fields=['aws_account', 'cache_key']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.aws_account.account_alias} - {self.cache_key}"


class CostDriver(models.Model):
    """
    Stores cost driver explanations that companies find valuable
    """
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='cost_drivers')
    service_name = models.CharField(max_length=100)  # e.g., "EC2", "S3", "Data Transfer"
    driver_type = models.CharField(max_length=50, choices=[
        ('increase', 'Cost Increase'),
        ('decrease', 'Cost Decrease'),
        ('anomaly', 'Anomaly'),
        ('top', 'Top Driver'),
    ])
    
    # The valuable insights
    title = models.CharField(max_length=200)  # e.g., "EC2 compute hours increased by 40%"
    description = models.TextField()  # Detailed explanation
    impact_percentage = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    affected_region = models.CharField(max_length=50, blank=True)
    
    # Resource details
    resource_count = models.IntegerField(default=0)  # Number of resources affected
    sample_resources = models.JSONField(default=list)  # List of example resource IDs
    
    # Recommendations
    recommendation = models.TextField(blank=True)
    estimated_savings = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    # Metadata
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.aws_account.account_alias} - {self.title}"

# In models.py, add this if not already there
class AWSCostAnalysis(models.Model):
    """
    Stores AI-generated cost analysis and recommendations
    """
    # In models.py, update the ANALYSIS_TYPES
    ANALYSIS_TYPES = [
        ('ai_insights', 'AI Generated Insights'),
        ('ai_low_level', 'AI Low Level Recommendations'),  # Add this
        ('manual', 'Manual Analysis'),
    ]
    
    aws_account = models.ForeignKey('AWSAccount', on_delete=models.CASCADE, related_name='cost_analyses')
    analysis_type = models.CharField(max_length=20, choices=ANALYSIS_TYPES, default='ai_insights')
    analysis_data = models.JSONField(default=dict)
    analysis_result = models.TextField()
    cost_drivers_used = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['aws_account', 'analysis_type', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.aws_account.account_alias} - {self.analysis_type} - {self.created_at}"


class EncryptedTextField(models.TextField):
    def __init__(self, *args, **kwargs):
        self.cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        super().__init__(*args, **kwargs)
    
    def get_prep_value(self, value):
        if value:
            encrypted = self.cipher.encrypt(value.encode())
            return base64.b64encode(encrypted).decode()
        return value
    
    def from_db_value(self, value, expression, connection):
        if value:
            decrypted = self.cipher.decrypt(base64.b64decode(value.encode()))
            return decrypted.decode()
        return value



class GitHubUser(models.Model):
    """
    Stores a user's GitHub account connection (one per user)
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='github_connection')
    github_id = models.BigIntegerField(unique=True)
    github_username = models.CharField(max_length=255)
    access_token = EncryptedTextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username} → GitHub: {self.github_username}"

# models.py - Add these new models at the end of your file

# ============================================================
# LOW-LEVEL SERVICES MODELS
# ============================================================

class LowLevelServiceCategory(models.Model):
    """
    Category for low-level services (e.g., Networking, Compute, Storage)
    """
    key = models.CharField(max_length=100, unique=True)  # e.g., 'networking', 'compute'
    name = models.CharField(max_length=100)  # e.g., 'Networking & Content Delivery'
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True)  # Icon name for frontend
    order = models.IntegerField(default=0)  # Display order
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['order', 'name']
        verbose_name_plural = "Low Level Service Categories"
    
    def __str__(self):
        return self.name


class LowLevelServiceDefinition(models.Model):
    """
    Definition of a low-level service (e.g., NAT Gateway, EBS Volume)
    Contains pricing information and metadata
    """
    service_id = models.CharField(max_length=100, unique=True)  # e.g., 'nat_gateway'
    name = models.CharField(max_length=200)  # e.g., 'NAT Gateway'
    description = models.TextField(blank=True)
    category = models.ForeignKey(
        LowLevelServiceCategory, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='services'
    )
    
    # Pricing information
    unit = models.CharField(max_length=100, blank=True)  # e.g., 'per gateway-hour'
    price_per_hour = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    price_per_gb = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    price_per_gb_month = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    price_per_million = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    price_per_vcpu_hour = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    price_per_month = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    price_per_10k = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    
    # Additional metadata
    aws_service_code = models.CharField(max_length=100, blank=True)  # AWS service code
    usage_type_pattern = models.CharField(max_length=200, blank=True)  # Pattern to match usage types
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['category__order', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.service_id})"
    
    def get_estimated_monthly_cost(self, quantity=1, usage_hours=730):
        """
        Calculate estimated monthly cost based on pricing model
        """
        if self.price_per_hour:
            return self.price_per_hour * usage_hours * quantity
        elif self.price_per_month:
            return self.price_per_month * quantity
        elif self.price_per_gb_month:
            return self.price_per_gb_month * quantity
        return 0


class LowLevelServiceSnapshot(models.Model):
    """
    Snapshot of low-level services at a point in time
    Stores aggregated data for quick retrieval
    """
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='low_level_snapshots'
    )
    
    # Summary statistics
    total_services = models.IntegerField(default=0)
    estimated_monthly_cost = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    unique_service_types = models.IntegerField(default=0)
    unique_services_discovered = models.IntegerField(default=0)
    regions_scanned = models.JSONField(default=list)
    
    # Full snapshot data (for detailed view)
    snapshot_data = models.JSONField(default=dict)
    
    # Metadata
    scan_duration_seconds = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['account', '-created_at']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
    
    def is_valid(self):
        """Check if snapshot is still valid (less than 24 hours old)"""
        from django.utils import timezone
        if not self.expires_at:
            return True
        return timezone.now() < self.expires_at


class LowLevelServiceResource(models.Model):
    """
    Individual resource discovered in low-level tracking
    """
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='low_level_resources'
    )
    service_definition = models.ForeignKey(
        LowLevelServiceDefinition, 
        on_delete=models.CASCADE,
        related_name='resources'
    )
    
    # Resource identification
    resource_id = models.CharField(max_length=500)  # AWS resource ID
    resource_name = models.CharField(max_length=500, blank=True)  # Friendly name
    region = models.CharField(max_length=50, blank=True)
    availability_zone = models.CharField(max_length=50, blank=True)
    
    # Resource details
    count = models.IntegerField(default=1)  # Quantity (e.g., number of instances)
    estimated_monthly_cost = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    details = models.JSONField(default=dict)  # Additional resource details
    
    # Tracking
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ('account', 'service_definition', 'resource_id', 'region')
        indexes = [
            models.Index(fields=['account', 'is_active']),
            models.Index(fields=['service_definition', 'region']),
            models.Index(fields=['estimated_monthly_cost']),
        ]
    
    def __str__(self):
        return f"{self.service_definition.name}: {self.resource_name or self.resource_id}"


class LowLevelServiceCostHistory(models.Model):
    """
    Historical cost data for low-level services
    Tracks cost trends over time
    """
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='low_level_cost_history'
    )
    service_definition = models.ForeignKey(
        LowLevelServiceDefinition, 
        on_delete=models.CASCADE,
        related_name='cost_history'
    )
    
    # Cost data
    monthly_cost = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    resource_count = models.IntegerField(default=0)
    region_breakdown = models.JSONField(default=dict)  # Cost per region
    
    # Time period
    date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('account', 'service_definition', 'date')
        ordering = ['-date']
        indexes = [
            models.Index(fields=['account', 'date']),
            models.Index(fields=['service_definition', 'date']),
        ]
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.service_definition.name} - {self.date}"


# ============================================================
# RESOURCE SUMMARY MODELS
# ============================================================

class ResourceSummary(models.Model):
    """
    High-level resource summary across all AWS services
    """
    account = models.OneToOneField(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='resource_summary'
    )
    
    # Total counts
    total_resources = models.IntegerField(default=0)
    
    # Compute resources
    ec2_total = models.IntegerField(default=0)
    ec2_running = models.IntegerField(default=0)
    ec2_stopped = models.IntegerField(default=0)
    ec2_avg_running_hours = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    lambda_functions = models.IntegerField(default=0)
    eks_clusters = models.IntegerField(default=0)
    ecs_clusters = models.IntegerField(default=0)
    
    # Database resources
    rds_instances = models.IntegerField(default=0)
    dynamodb_tables = models.IntegerField(default=0)
    elasticache_clusters = models.IntegerField(default=0)
    redshift_clusters = models.IntegerField(default=0)
    
    # Storage resources
    s3_buckets = models.IntegerField(default=0)
    s3_avg_age_days = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    ebs_volumes = models.IntegerField(default=0)
    efs_filesystems = models.IntegerField(default=0)
    
    # Networking resources
    load_balancers = models.IntegerField(default=0)
    vpcs = models.IntegerField(default=0)
    nat_gateways = models.IntegerField(default=0)
    vpc_endpoints = models.IntegerField(default=0)
    
    # Other resources
    cloudfront_distributions = models.IntegerField(default=0)
    api_gateway_apis = models.IntegerField(default=0)
    sqs_queues = models.IntegerField(default=0)
    sns_topics = models.IntegerField(default=0)
    
    # Permissions issues
    permissions_issues = models.JSONField(default=list)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = "Resource Summaries"
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.total_resources} resources"
    
    def to_dict(self):
        """Convert to dictionary for API response"""
        return {
            'total_resources': self.total_resources,
            'ec2': {
                'total': self.ec2_total,
                'running': self.ec2_running,
                'stopped': self.ec2_stopped,
                'avg_running_hours': float(self.ec2_avg_running_hours)
            },
            'lambda': {'total_functions': self.lambda_functions},
            'eks': {'total': self.eks_clusters},
            'ecs': {'total': self.ecs_clusters},
            'rds': {'total_instances': self.rds_instances},
            'dynamodb': {'total': self.dynamodb_tables},
            'elasticache': {'total': self.elasticache_clusters},
            'redshift': {'total': self.redshift_clusters},
            's3': {
                'total_buckets': self.s3_buckets,
                'avg_age_days': float(self.s3_avg_age_days)
            },
            'ebs': {'total': self.ebs_volumes},
            'efs': {'total': self.efs_filesystems},
            'load_balancers': {'total': self.load_balancers},
            'vpc': {
                'total': self.vpcs,
                'nat_gateways': self.nat_gateways,
                'endpoints': self.vpc_endpoints
            },
            'cloudfront': {'total': self.cloudfront_distributions},
            'api_gateway': {'total': self.api_gateway_apis},
            'sqs': {'total': self.sqs_queues},
            'sns': {'total': self.sns_topics},
            'permissions_issues': self.permissions_issues
        }


class ResourceSummaryHistory(models.Model):
    """
    Historical resource summary snapshots
    Tracks resource changes over time
    """
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='resource_summary_history'
    )
    
    # Full snapshot data
    snapshot_data = models.JSONField()
    
    # Summary stats for quick access
    total_resources = models.IntegerField(default=0)
    total_estimated_cost = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = "Resource Summary Histories"
        indexes = [
            models.Index(fields=['account', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.created_at.strftime('%Y-%m-%d')}"


# ============================================================
# COST ANOMALY MODELS
# ============================================================

class CostAnomaly(models.Model):
    """
    Detected cost anomalies for an account
    """
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('detected', 'Detected'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='cost_anomalies'
    )
    
    # Anomaly details
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='detected')
    
    # Cost impact
    expected_cost = models.DecimalField(max_digits=12, decimal_places=2)
    actual_cost = models.DecimalField(max_digits=12, decimal_places=2)
    variance_percentage = models.DecimalField(max_digits=8, decimal_places=2)
    
    # Time period
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    
    # Additional context
    services_affected = models.JSONField(default=list)
    regions_affected = models.JSONField(default=list)
    related_deployments = models.JSONField(default=list)  # IDs of related deployments
    
    # Resolution
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    # Metadata
    detected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name_plural = "Cost Anomalies"
        indexes = [
            models.Index(fields=['account', 'severity']),
            models.Index(fields=['account', 'status']),
            models.Index(fields=['start_time']),
        ]
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.title} ({self.severity})"
    
    def get_cost_impact(self):
        """Get the actual cost impact"""
        return self.actual_cost - self.expected_cost


class CostOptimizationRecommendation(models.Model):
    """
    Cost optimization recommendations generated by AI analysis
    """
    PRIORITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('applied', 'Applied'),
        ('dismissed', 'Dismissed'),
        ('in_progress', 'In Progress'),
    ]
    
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='optimization_recommendations'
    )
    
    # Recommendation details
    title = models.CharField(max_length=200)
    description = models.TextField()
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Financial impact
    estimated_monthly_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    estimated_yearly_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    implementation_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0, null=True, blank=True)
    
    # Implementation details
    implementation_steps = models.JSONField(default=list)
    affected_resources = models.JSONField(default=list)
    services_affected = models.JSONField(default=list)
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    applied_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['account', 'priority']),
            models.Index(fields=['account', 'status']),
        ]
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.title} ({self.priority})"
    
    def get_roi(self):
        """Calculate ROI percentage"""
        if not self.implementation_cost or self.implementation_cost == 0:
            return 100
        return (self.estimated_yearly_savings / self.implementation_cost) * 100


# ============================================================
# SERVICE QUOTA MODELS
# ============================================================

class ServiceQuota(models.Model):
    """
    AWS service quotas for an account
    """
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='service_quotas'
    )
    
    # Quota details
    service_code = models.CharField(max_length=100)  # e.g., 'ec2', 'vpc'
    service_name = models.CharField(max_length=100)
    quota_code = models.CharField(max_length=100)  # AWS quota code
    quota_name = models.CharField(max_length=200)
    
    # Values
    quota_value = models.DecimalField(max_digits=12, decimal_places=2)
    current_usage = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    usage_percentage = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    
    # Region
    region = models.CharField(max_length=50, blank=True)
    
    # Metadata
    tracked_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('account', 'quota_code', 'region')
        ordering = ['service_name', 'quota_name']
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.service_name}: {self.quota_name} ({self.usage_percentage}%)"
    
    def is_approaching_limit(self, threshold=80):
        """Check if quota is approaching limit"""
        return self.usage_percentage >= threshold
    
    def is_exceeded(self):
        """Check if quota is exceeded"""
        return self.current_usage >= self.quota_value


# ============================================================
# COST FORECAST MODELS
# ============================================================

class CostForecast(models.Model):
    """
    Cost forecast for an account
    """
    PERIOD_CHOICES = [
        ('7d', '7 Days'),
        ('30d', '30 Days'),
        ('90d', '90 Days'),
        ('12m', '12 Months'),
    ]
    
    account = models.ForeignKey(
        AWSAccount, 
        on_delete=models.CASCADE, 
        related_name='cost_forecasts'
    )
    
    # Forecast details
    period = models.CharField(max_length=10, choices=PERIOD_CHOICES)
    total_forecast = models.DecimalField(max_digits=12, decimal_places=2)
    average_daily = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Breakdown
    daily_forecast = models.JSONField(default=list)  # Array of daily forecasts
    service_breakdown = models.JSONField(default=list)  # Forecast by service
    
    # Confidence intervals
    confidence_lower = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    confidence_upper = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    
    # Metadata
    start_date = models.DateField()
    end_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('account', 'period', 'start_date')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.account.account_alias} - {self.period} forecast (${self.total_forecast})"

# models.py - Verify your GitHubRepo model has these fields

class GitHubRepo(models.Model):
    """
    Stores user's connected GitHub repositories
    """
    STATUS_CHOICES = [
        ('connected', 'Connected'),
        ('disconnected', 'Disconnected'),
        ('failed', 'Connection Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='github_repos')
    aws_account = models.ForeignKey('AWSAccount', on_delete=models.CASCADE, related_name='github_repos', null=True, blank=True)
    
    # Repo details
    repo_id = models.BigIntegerField(help_text="GitHub repository ID")
    repo_name = models.CharField(max_length=255)
    repo_full_name = models.CharField(max_length=255)
    repo_url = models.URLField(max_length=500)  # Make sure max_length is sufficient
    
    # Access token (encrypted)
    access_token = EncryptedTextField(help_text="Encrypted GitHub access token")
    installation_id = models.BigIntegerField(null=True, blank=True)
    
    # Metadata
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='connected')
    webhook_id = models.BigIntegerField(null=True, blank=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    connected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'repo_id')
        ordering = ['-connected_at']

    def __str__(self):
        return f"{self.user.username} → {self.repo_full_name}"

class DeploymentEvent(models.Model):
    """
    Stores individual deployment events from GitHub PR merges
    """
    repo = models.ForeignKey(GitHubRepo, on_delete=models.CASCADE, related_name='deployments')
    aws_account = models.ForeignKey('AWSAccount', on_delete=models.CASCADE, related_name='deployments')
    
    # PR details
    pr_number = models.IntegerField()
    pr_title = models.CharField(max_length=500)
    pr_url = models.URLField()
    merged_by = models.CharField(max_length=255)
    merged_at = models.DateTimeField()
    
    # Changes
    files_changed = models.JSONField(default=list, help_text="List of files modified in this PR")
    services_affected = models.JSONField(default=list, help_text="AWS services that might be affected")
    
    # Correlation with costs
    cost_spike_id = models.ForeignKey('CostSpike', on_delete=models.SET_NULL, null=True, blank=True, related_name='deployments')
    cost_impact = models.DecimalField(max_digits=12, decimal_places=4, null=True, blank=True)
    is_correlated = models.BooleanField(default=False)
    
    # Timestamps
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('repo', 'pr_number')
        ordering = ['-merged_at']
        indexes = [
            models.Index(fields=['merged_at']),
            models.Index(fields=['aws_account', 'merged_at']),
        ]
    
    def __str__(self):
        return f"{self.repo.repo_full_name} #{self.pr_number} - {self.merged_at}"

# Also create CostSpike model if you don't have it
class CostSpike(models.Model):
    """
    Detected cost spikes from AWS Cost Explorer
    """
    aws_account = models.ForeignKey('AWSAccount', on_delete=models.CASCADE, related_name='cost_spikes')
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    increase_percentage = models.DecimalField(max_digits=6, decimal_places=2)
    before_cost = models.DecimalField(max_digits=12, decimal_places=4)
    after_cost = models.DecimalField(max_digits=12, decimal_places=4)
    services_affected = models.JSONField(default=list)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-start_time']
    
    def __str__(self):
        return f"{self.aws_account.account_alias} - +{self.increase_percentage}% at {self.start_time}"
    


# Add to models.py

class CostDataHistory(models.Model):
    """
    Stores permanent cost data history
    """
    COST_TYPES = [
        ('90_days', '90 Days Total'),
        ('monthly', 'Monthly Cost'),
        ('7_days', '7 Days Chart'),
        ('yesterday', 'Yesterday Cost'),
        ('low_level', 'Low Level Costs'),
        ('cost_drivers', 'Cost Drivers'),
    ]
    
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='cost_data_history')
    cost_type = models.CharField(max_length=20, choices=COST_TYPES)
    data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('aws_account', 'cost_type')
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"{self.aws_account.account_alias} - {self.cost_type}"


# Add to myground/models.py (at the end of the file)

# ============================================================
# STORAGE OPTIMIZATION MODELS
# ============================================================
# Add these to your models.py (they should already be there, but let's ensure they're complete)

class StorageOptimizationFinding(models.Model):
    """
    Stores unused/idle storage resource findings
    """
    SEVERITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('resolved', 'Resolved'),
        ('ignored', 'Ignored'),
        ('dismissed', 'Dismissed'),
    ]
    RESOURCE_TYPES = [
        ('ebs_volume', 'EBS Volume'),
        ('elastic_ip', 'Elastic IP'),
        ('ebs_snapshot', 'EBS Snapshot'),
        ('s3_bucket', 'S3 Bucket'),
        ('rds_instance', 'RDS Instance'),
        ('rds_snapshot', 'RDS Snapshot'),
        ('dynamodb_table', 'DynamoDB Table'),
        ('unused_ami', 'Unused AMI'),
        ('load_balancer', 'Load Balancer'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='storage_findings')
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPES)
    resource_id = models.CharField(max_length=500)
    resource_name = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=50, blank=True)
    
    size_gb = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    estimated_monthly_cost = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    confidence_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    reason = models.TextField()
    recommendation = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    metadata = models.JSONField(default=dict)
    
    detected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['user', 'aws_account', 'status']),
            models.Index(fields=['resource_type', 'severity']),
            models.Index(fields=['detected_at']),
        ]

    def __str__(self):
        return f"{self.resource_type}: {self.resource_id} ({self.severity})"


class DuplicateStorageFinding(models.Model):
    """
    Stores duplicate/redundant storage findings
    """
    DUPLICATE_TYPE_CHOICES = [
        ('exact', 'Exact Duplicate'),
        ('likely', 'Likely Duplicate'),
        ('redundant_backup', 'Redundant Backup Candidate'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='duplicate_findings')
    duplicate_type = models.CharField(max_length=20, choices=DUPLICATE_TYPE_CHOICES)
    group_id = models.CharField(max_length=100)
    group_name = models.CharField(max_length=500)
    resources = models.JSONField(default=list)
    total_wasted_size_gb = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    estimated_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    reason = models.TextField()
    recommendation = models.TextField()
    status = models.CharField(max_length=20, default='active')
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-detected_at']

    def __str__(self):
        return f"{self.group_name} ({self.duplicate_type})"


class ResourceUsageSnapshot(models.Model):
    """
    Daily snapshot of storage usage metrics
    """
    SERVICE_CHOICES = [
        ('ebs', 'EBS'),
        ('s3', 'S3'),
        ('rds', 'RDS'),
        ('snapshots', 'Snapshots'),
        ('dynamodb', 'DynamoDB'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='usage_snapshots')
    service_name = models.CharField(max_length=50, choices=SERVICE_CHOICES)
    region = models.CharField(max_length=50, blank=True)
    usage_value = models.DecimalField(max_digits=20, decimal_places=2)
    unit = models.CharField(max_length=20, default='GB')
    metadata = models.JSONField(default=dict)
    snapshot_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'aws_account', 'service_name', 'region', 'snapshot_date']
        ordering = ['-snapshot_date']
        indexes = [
            models.Index(fields=['user', 'aws_account', 'snapshot_date']),
            models.Index(fields=['service_name', 'snapshot_date']),
        ]

    def __str__(self):
        return f"{self.service_name}: {self.usage_value} {self.unit} ({self.snapshot_date})"


class CpuUsageSnapshot(models.Model):
    """
    CPU usage metrics for compute resources
    """
    RESOURCE_TYPE_CHOICES = [
        ('ec2', 'EC2 Instance'),
        ('rds', 'RDS Instance'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='cpu_snapshots')
    resource_type = models.CharField(max_length=20, choices=RESOURCE_TYPE_CHOICES)
    resource_id = models.CharField(max_length=500)
    resource_name = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=50)
    
    avg_cpu_percent = models.FloatField(default=0)
    max_cpu_percent = models.FloatField(default=0)
    min_cpu_percent = models.FloatField(default=0)
    sample_count = models.IntegerField(default=0)
    
    is_idle = models.BooleanField(default=False)
    idle_threshold = models.FloatField(default=5.0)
    
    recommendation = models.TextField(blank=True)
    estimated_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    metadata = models.JSONField(default=dict)
    snapshot_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'aws_account', 'resource_id', 'snapshot_date']
        ordering = ['-snapshot_date']
        indexes = [
            models.Index(fields=['user', 'aws_account', 'is_idle']),
            models.Index(fields=['resource_type', 'snapshot_date']),
        ]

    def __str__(self):
        return f"{self.resource_type}: {self.resource_id} - {self.avg_cpu_percent}% CPU"


class StorageOptimizationSummary(models.Model):
    """
    Cached summary for dashboard
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='optimization_summary')
    total_idle_resources = models.IntegerField(default=0)
    total_estimated_waste = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    duplicate_candidates = models.IntegerField(default=0)
    duplicate_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    idle_cpu_resources = models.IntegerField(default=0)
    cpu_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    weekly_growth_percent = models.FloatField(default=0)
    monthly_growth_percent = models.FloatField(default=0)
    summary_data = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'aws_account']

    def __str__(self):
        return f"Summary for {self.aws_account.account_id}"

class IdleEC2Instance(models.Model):
    """Stores idle EC2 instance findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    instance_id = models.CharField(max_length=100)
    instance_name = models.CharField(max_length=500, blank=True)
    instance_type = models.CharField(max_length=50)
    cpu_avg = models.FloatField()
    network_in_mb = models.FloatField(default=0)
    network_out_mb = models.FloatField(default=0)
    disk_read_mb = models.FloatField(default=0)
    disk_write_mb = models.FloatField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleAutoScalingGroup(models.Model):
    """Stores idle/over-provisioned Auto Scaling Group findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    asg_name = models.CharField(max_length=255)
    min_size = models.IntegerField()
    max_size = models.IntegerField()
    desired_capacity = models.IntegerField()
    current_instances = models.IntegerField()
    avg_cpu = models.FloatField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']

class IdleLoadBalancer(models.Model):
    """Stores idle/underutilized Load Balancer findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    lb_name = models.CharField(max_length=255)
    lb_type = models.CharField(max_length=50)
    lb_scheme = models.CharField(max_length=50)
    lb_state = models.CharField(max_length=50)
    total_requests = models.IntegerField(default=0)
    processed_gb = models.FloatField(default=0)
    healthy_targets = models.IntegerField(default=0)
    total_targets = models.IntegerField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleLambdaFunction(models.Model):
    """Stores idle/unused Lambda function findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    function_name = models.CharField(max_length=255)
    runtime = models.CharField(max_length=50)
    memory_mb = models.IntegerField()
    last_modified = models.CharField(max_length=100)
    invocations_30d = models.IntegerField(default=0)
    invocations_7d = models.IntegerField(default=0)
    avg_duration_ms = models.FloatField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']

class IdleECSService(models.Model):
    """Stores idle/underutilized ECS/Fargate service findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    service_name = models.CharField(max_length=255)
    cluster_name = models.CharField(max_length=255)
    cpu = models.IntegerField()
    memory_mb = models.IntegerField()
    running_tasks = models.IntegerField()
    desired_tasks = models.IntegerField()
    cpu_utilization = models.FloatField(default=0)
    memory_utilization = models.FloatField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleNATGateway(models.Model):
    """Stores idle NAT Gateway findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    nat_gateway_id = models.CharField(max_length=100)
    vpc_id = models.CharField(max_length=100)
    subnet_id = models.CharField(max_length=100)
    data_processed_gb = models.FloatField(default=0)
    packets_processed = models.IntegerField(default=0)
    avg_connections = models.FloatField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    yearly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleVPCEndpoint(models.Model):
    """Stores idle VPC Endpoint findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    endpoint_id = models.CharField(max_length=100)
    service_name = models.CharField(max_length=255)
    endpoint_type = models.CharField(max_length=50)
    vpc_id = models.CharField(max_length=100)
    total_packets = models.IntegerField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleAPIGateway(models.Model):
    """Stores idle/underutilized API Gateway findings"""
    API_TYPES = [
        ('REST', 'REST API'),
        ('HTTP', 'HTTP API'),
        ('WEBSOCKET', 'WebSocket API'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    api_id = models.CharField(max_length=100)
    api_name = models.CharField(max_length=255)
    api_type = models.CharField(max_length=20, choices=API_TYPES)
    total_requests_30d = models.IntegerField(default=0)
    requests_7d = models.IntegerField(default=0)
    active_stages = models.IntegerField(default=0)
    avg_connections = models.FloatField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleCloudWatchLogGroup(models.Model):
    """Stores idle CloudWatch Log Group findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    log_group_name = models.CharField(max_length=500)
    stored_gb = models.FloatField(default=0)
    retention_days = models.IntegerField(default=0)
    days_since_last_log = models.IntegerField(default=0)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleCloudWatchAlarm(models.Model):
    """Stores idle CloudWatch Alarm findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    alarm_name = models.CharField(max_length=255)
    state = models.CharField(max_length=50)
    actions_enabled = models.BooleanField(default=False)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleCloudWatchDashboard(models.Model):
    """Stores idle CloudWatch Dashboard findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    dashboard_name = models.CharField(max_length=255)
    days_since_modified = models.IntegerField(default=0)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']


class IdleCloudWatchMetric(models.Model):
    """Stores idle CloudWatch Custom Metric findings"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE)
    namespace = models.CharField(max_length=255)
    metric_name = models.CharField(max_length=255)
    monthly_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    reasons = models.JSONField(default=list)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']