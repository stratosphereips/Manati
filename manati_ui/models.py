from __future__ import unicode_literals
import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from model_utils import Choices
from django.db import IntegrityError, transaction
from django.contrib.messages import constants as message_constants
MESSAGE_TAGS = {
    message_constants.DEBUG: 'info',
    message_constants.INFO: 'info',
    message_constants.SUCCESS: 'success',
    message_constants.WARNING: 'warning',
    message_constants.ERROR: 'danger',
}


class AnalysisSession(models.Model):

    users = models.ManyToManyField(User)
    name = models.CharField(max_length=200, blank=False, null=False)
    created_at = models.TimeField(auto_now_add=True)
    updated_at = models.TimeField(auto_now=True)

    class Meta:
        db_table = 'manati_analysis_sessions'

    @transaction.atomic
    def create_from_request(self, keys, data, name):
        try:
            with transaction.atomic():
                self.name = name
                self.save()
                for elem in data:
                    i = 0
                    hash_attr={}
                    for k in keys:
                        hash_attr[k] = elem[i]
                        i += 1
                    wb = Weblog(**hash_attr)
                    wb.analysis_session = self
                    wb.save()
            return self
        except IntegrityError:
            return None



class Weblog(models.Model):
    db_table = 'weblogs'
    analysis_session = models.ForeignKey(AnalysisSession, on_delete=models.CASCADE, null=False)
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
    # Verdict Status Attr
    VERDICT_STATUS = Choices('normal', 'malicious', 'legitimate', 'suspicious', ('false_positive','False Positive'))
    verdict = models.CharField(choices=VERDICT_STATUS, default=VERDICT_STATUS.normal, max_length=20)
    #attrs usefull for auditing
    created_at = models.TimeField(auto_now_add=True)
    updated_at = models.TimeField(auto_now=True)

    class Meta:
        db_table = 'manati_weblogs'

