from rest_framework import serializers
from manati_ui.models import Weblog


class WeblogSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)
    attributes = serializers.JSONField(required=True)
    verdict = serializers.CharField(read_only=True)
    register_status = serializers.IntegerField(read_only=True)
    analysis_session_id = serializers.IntegerField(read_only=True)