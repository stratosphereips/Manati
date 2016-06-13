from __future__ import unicode_literals
import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class AnalysisSession(models.Model):

    users = models.ManyToManyField(User)
    created_at = models.TimeField(auto_now_add=True)
    updated_at = models.TimeField(auto_now=True)

    class Meta:
        db_table = 'manati_analysis_sessions'

class Weblog(models.Model):
    db_table = 'weblogs'
    analysis_session = models.ForeignKey(AnalysisSession, on_delete=models.CASCADE)
    timestamp = models.CharField(max_length=200)
    s_port = models.IntegerField()
    sc_http_status = models.CharField(max_length=200)
    sc_bytes = models.CharField(max_length=200)
    sc_header_bytes = models.CharField(max_length=200)
    c_port = models.CharField(max_length=200)
    cs_bytes = models.CharField(max_length=200)
    cs_header_bytes = models.CharField(max_length=200)
    cs_method = models.CharField(max_length=50)
    cs_url = models.URLField(max_length=255)
    s_ip = models.CharField(max_length=200)
    c_ip = models.CharField(max_length=200)
    connection_time = models.CharField(max_length=200)
    request_time = models.CharField(max_length=200)
    response_time = models.CharField(max_length=200)
    close_time = models.CharField(max_length=200)
    idle_time0 = models.CharField(max_length=200)
    idle_time1 = models.CharField(max_length=200)
    cs_mime_type = models.CharField(max_length=200)
    cs_Referer = models.CharField(max_length=200)
    cs_User_Agent = models.CharField(max_length=200)
    created_at = models.TimeField(auto_now_add=True)
    updated_at = models.TimeField(auto_now=True)

    class Meta:
        db_table = 'manati_weblogs'

