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