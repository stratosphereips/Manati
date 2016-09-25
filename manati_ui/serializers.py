from rest_framework import serializers
from manati_ui.models import *


class WeblogSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    attributes = serializers.JSONField(required=True)
    verdict = serializers.CharField(choices=Weblog.VERDICT_STATUS, default=Weblog.VERDICT_STATUS.legitimate, max_length=20, null=True)
    register_status = enum.EnumField(Weblog.RegisterStatus, default=Weblog.RegisterStatus.READY, null=True)