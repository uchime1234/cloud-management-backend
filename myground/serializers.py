from rest_framework import serializers
from django.contrib.auth.models import User
# from .models import (
#     AWSAccountConnection, DailySpend, MonthlyCostSummary, 
#     RecentDailySpend, MFAConfiguration
# )
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import statistics

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']

# Add to myground/serializers.py

from .models import StorageOptimizationFinding, DuplicateStorageFinding


class StorageOptimizationFindingSerializer(serializers.ModelSerializer):
    resource_type_display = serializers.CharField(source='get_resource_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    
    class Meta:
        model = StorageOptimizationFinding
        fields = [
            'id', 'resource_type', 'resource_type_display', 'resource_id', 'resource_name',
            'region', 'size_gb', 'estimated_monthly_cost', 'confidence_score',
            'reason', 'recommendation', 'severity', 'severity_display', 'status',
            'metadata', 'detected_at', 'updated_at'
        ]

# Add to myground/serializers.py

from .models import (
    StorageOptimizationFinding, DuplicateStorageFinding,
    ResourceUsageSnapshot, CpuUsageSnapshot, StorageOptimizationSummary
)


class StorageOptimizationFindingSerializer(serializers.ModelSerializer):
    resource_type_display = serializers.CharField(source='get_resource_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    
    class Meta:
        model = StorageOptimizationFinding
        fields = [
            'id', 'resource_type', 'resource_type_display', 'resource_id', 'resource_name',
            'region', 'size_gb', 'estimated_monthly_cost', 'confidence_score',
            'reason', 'recommendation', 'severity', 'severity_display', 'status',
            'metadata', 'detected_at', 'updated_at'
        ]


class DuplicateStorageFindingSerializer(serializers.ModelSerializer):
    duplicate_type_display = serializers.CharField(source='get_duplicate_type_display', read_only=True)
    
    class Meta:
        model = DuplicateStorageFinding
        fields = [
            'id', 'duplicate_type', 'duplicate_type_display', 'group_id', 'group_name',
            'resources', 'total_wasted_size_gb', 'estimated_savings',
            'reason', 'recommendation', 'status', 'detected_at'
        ]


class ResourceUsageSnapshotSerializer(serializers.ModelSerializer):
    service_name_display = serializers.CharField(source='get_service_name_display', read_only=True)
    
    class Meta:
        model = ResourceUsageSnapshot
        fields = [
            'id', 'service_name', 'service_name_display', 'region',
            'usage_value', 'unit', 'metadata', 'snapshot_date'
        ]


class CpuUsageSnapshotSerializer(serializers.ModelSerializer):
    resource_type_display = serializers.CharField(source='get_resource_type_display', read_only=True)
    
    class Meta:
        model = CpuUsageSnapshot
        fields = [
            'id', 'resource_type', 'resource_type_display', 'resource_id', 'resource_name',
            'region', 'avg_cpu_percent', 'max_cpu_percent', 'min_cpu_percent',
            'sample_count', 'is_idle', 'recommendation', 'estimated_savings',
            'metadata', 'snapshot_date'
        ]


class StorageOptimizationSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = StorageOptimizationSummary
        fields = [
            'id', 'total_idle_resources', 'total_estimated_waste',
            'duplicate_candidates', 'duplicate_savings', 'idle_cpu_resources',
            'cpu_savings', 'weekly_growth_percent', 'monthly_growth_percent',
            'summary_data', 'updated_at'
        ]

# class AWSAccountConnectionSerializer(serializers.ModelSerializer):
#     user = UserSerializer(read_only=True)
    
#     class Meta:
#         model = AWSAccountConnection
#         fields = ['id', 'user', 'aws_account_id', 'role_arn', 'external_id', 
#                   'is_active', 'created_at', 'last_synced']
#         read_only_fields = ['id', 'user', 'created_at', 'last_synced']

# class CostAnalyticsSerializer(serializers.Serializer):
#     """Serializer for frontend analytics data"""
#     total_spend = serializers.DecimalField(max_digits=20, decimal_places=10)  # Changed to 10
#     current_month_spend = serializers.DecimalField(max_digits=20, decimal_places=10)  # Changed to 10
#     current_month_name = serializers.CharField()
#     today_spend = serializers.DecimalField(max_digits=20, decimal_places=10)  # Changed to 10
#     monthly_change = serializers.DecimalField(max_digits=20, decimal_places=10)  # Changed to 10
#     forecast = serializers.DictField()
#     daily_spend = serializers.ListField()
#     service_breakdown = serializers.ListField(required=False)  # Add th
    
#     def to_representation(self, instance):
#         data = super().to_representation(instance)
        
#         # Format all decimal fields to float for frontend
#         decimal_fields = ['total_spend', 'current_month_spend', 'today_spend', 'monthly_change']
#         for field in decimal_fields:
#             if field in data:
#                 data[field] = round(float(data[field]), 2)  # Round to 2 decimals
        
#         # Format forecast
#         if 'forecast' in data:
#             if data['forecast'].get('thirtyDay'):
#                 data['forecast']['thirtyDay'] = round(float(data['forecast']['thirtyDay']), 2)
#             if data['forecast'].get('sevenDay'):
#                 data['forecast']['sevenDay'] = round(float(data['forecast']['sevenDay']), 2)
        
#         # Format daily spend
#         if 'daily_spend' in data:
#             for day in data['daily_spend']:
#                 if 'amount' in day:
#                     day['amount'] = round(float(day['amount']), 2)

#         # Format for services breakdown            
#         if 'service_breakdown' in data:
#             for service in data['service_breakdown']:
#                 if 'amount' in service:
#                     service['amount'] = round(float(service['amount']), 2)
#                 if 'percentage' in service:
#                     service['percentage'] = round(float(service['percentage']), 1)
        
#         return data
    

# # serializers.py - Add this serializer
# from .models import ResourceSummary

# class ResourceSummarySerializer(serializers.ModelSerializer):
#     """Serializer for resource summary data"""
#     account = AWSAccountConnectionSerializer(read_only=True)
    
#     class Meta:
#         model = ResourceSummary
#         fields = '__all__'
    
#     def to_representation(self, instance):
#         """Convert to frontend-friendly format"""
#         data = super().to_representation(instance)
#         # Convert decimal fields to float for frontend
#         decimal_fields = ['ec2_avg_running_hours', 's3_avg_age_days']
#         for field in decimal_fields:
#             if field in data:
#                 data[field] = float(data[field]) if data[field] is not None else 0
        
#         # Format JSON fields
#         if 'permissions_issues' in data:
#             data['permissions_issues'] = data['permissions_issues'] or []
        
#         return data