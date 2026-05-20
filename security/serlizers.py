from rest_framework import serializers
from .models import IAMFinding

class IAMFindingSerializer(serializers.ModelSerializer):
    finding_type_display = serializers.CharField(source='get_finding_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    
    class Meta:
        model = IAMFinding
        fields = [
            'id', 'finding_type', 'finding_type_display', 'severity', 'severity_display',
            'resource_name', 'title', 'description', 'recommendation', 'metadata',
            'detected_at', 'is_resolved'
        ]

# Add to security/serializers.py

from .models import PublicExposureFinding, PublicExposureReport

class PublicExposureFindingSerializer(serializers.ModelSerializer):
    exposure_type_display = serializers.CharField(source='get_exposure_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    
    class Meta:
        model = PublicExposureFinding
        fields = [
            'id', 'exposure_type', 'exposure_type_display', 'severity', 'severity_display',
            'resource_name', 'resource_id', 'region', 'public_ip', 'port', 'protocol',
            'cidr', 'security_group_name', 'security_group_id', 'details',
            'title', 'description', 'recommendation', 'detected_at', 'is_resolved'
        ]


class PublicExposureReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PublicExposureReport
        fields = [
            'id', 'ai_analysis', 'total_findings', 'critical_count',
            'high_count', 'medium_count', 'low_count', 'created_at', 'updated_at'
        ]