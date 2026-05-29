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

from .models import PublicExposureFinding, PublicExposureReport, SecurityGroupAuditLog

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


from rest_framework import serializers
from .models import SecurityGroupAnalysis, secu

class RiskFindingSerializer(serializers.Serializer):
    type = serializers.CharField()
    severity = serializers.CharField()
    title = serializers.CharField()
    explanation = serializers.CharField()
    recommendation = serializers.CharField()
    details = serializers.JSONField()

class ExposedPortSerializer(serializers.Serializer):
    port = serializers.IntegerField()
    name = serializers.CharField()
    severity = serializers.CharField()

class AttachedResourceSerializer(serializers.Serializer):
    resource_id = serializers.CharField()
    resource_name = serializers.CharField()
    resource_type = serializers.CharField()
    status = serializers.CharField()
    region = serializers.CharField()

class ChangeHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityGroupAuditLog
        fields = ['timestamp', 'actor', 'action', 'summary', 'before', 'after']

class AIRecommendationSerializer(serializers.Serializer):
    security_summary = serializers.CharField()
    risks = serializers.ListField(child=serializers.CharField())
    optimization_recommendations = serializers.ListField(child=serializers.CharField())
    priority_recommendations = serializers.ListField(child=serializers.CharField())
    generated_at = serializers.CharField()
    model_used = serializers.CharField()

class SecurityGroupAnalysisSerializer(serializers.ModelSerializer):
    risk_findings = RiskFindingSerializer(many=True)
    exposed_ports = ExposedPortSerializer(many=True)
    attached_resources = AttachedResourceSerializer(many=True)
    change_history = ChangeHistorySerializer(many=True, read_only=True)
    ai_recommendation = AIRecommendationSerializer(read_only=True)
    
    class Meta:
        model = SecurityGroupAnalysis
        fields = [
            'id', 'security_group_id', 'security_group_name', 'region',
            'risk_findings', 'severity_score', 'health_score', 'risk_count',
            'open_world_rules', 'exposed_ports', 'dangerous_protocols',
            'any_to_any_traffic', 'attached_resources', 'is_orphaned',
            'duplicate_groups', 'traffic_insights', 'change_history',
            'ai_recommendation', 'last_analyzed_at'
        ]

class SecurityGroupListSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityGroupAnalysis
        fields = [
            'id', 'security_group_id', 'security_group_name', 'severity_score',
            'health_score', 'risk_count', 'attached_resources_count',
            'is_orphaned', 'last_analyzed_at'
        ]
    
    attached_resources_count = serializers.SerializerMethodField()
    
    def get_attached_resources_count(self, obj):
        return len(obj.attached_resources)