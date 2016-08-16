from __future__ import unicode_literals
import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from model_utils import Choices
from django.db import IntegrityError, transaction
from django.contrib.messages import constants as message_constants
from django.core.exceptions import ValidationError
from django_enumfield import enum

MESSAGE_TAGS = {
    message_constants.DEBUG: 'info',
    message_constants.INFO: 'info',
    message_constants.SUCCESS: 'success',
    message_constants.WARNING: 'warning',
    message_constants.ERROR: 'danger',
}

class AnalysisSessionManager(models.Manager):

    @transaction.atomic
    def create_from_request(self, keys, data, name):
        try:
            analysis_session = AnalysisSession()
            with transaction.atomic():
                analysis_session.name = name
                analysis_session.full_clean()
                analysis_session.save()
                print(len(data))
                for elem in data:
                    i = 0
                    hash_attr = {}
                    for k in Weblog.get_model_fields():
                        hash_attr[k] = elem[i]
                        i += 1
                    wb = Weblog(**hash_attr)
                    wb.analysis_session = analysis_session
                    wb.register_status = RegisterStatus.READY
                    wb.full_clean()
                    wb.save()
            return analysis_session
        except ValidationError as e:
            print(e)
            return None
        except IntegrityError as e:
            print(e)
            return None

    @transaction.atomic
    def create(self, filename):
        try:
            analysis_session = AnalysisSession()
            previous_exist = AnalysisSession.objects.filter(name=filename).first()
            if (isinstance(previous_exist, AnalysisSession)):
                previous_exist.delete()
            with transaction.atomic():
                analysis_session.name = filename
                analysis_session.full_clean()
                analysis_session.save()
            return analysis_session
        except Exception as e:
            print(e)
            return None


    @transaction.atomic
    def add_weblogs(self,analysis_session_id, data):
        try:
            print("Weblogs to save: ")
            print(len(data))
            wb_list = []
            with transaction.atomic():
                for elem in data:
                    i = 0
                    hash_attr = {}
                    for k in Weblog.get_model_fields():
                        hash_attr[k] = elem[i]
                        i += 1
                    wb = Weblog(**hash_attr)
                    wb.analysis_session_id = analysis_session_id
                    wb.register_status = RegisterStatus.READY
                    wb.dt_id = elem[13]
                    wb.full_clean()
                    wb.save()
                    wb_list.append(wb)
            return wb_list
        except ValidationError as e:
            print(e)
            return []
        except IntegrityError as e:
            print(e)
            return []



class AnalysisSession(models.Model):

    users = models.ManyToManyField(User)
    name = models.CharField(max_length=200, blank=False, null=False, default='Name by Default')
    created_at = models.TimeField(auto_now_add=True)
    updated_at = models.TimeField(auto_now=True)

    objects = AnalysisSessionManager()

    class Meta:
        db_table = 'manati_analysis_sessions'




class RegisterStatus(enum.Enum):
    NOT_SAVE = -1
    READY = 0
    CLIENT_MODIFICATION = 1
    MODULE_MODIFICATION = 3
    UPGRADING_LOCK = 2

class Weblog(models.Model):
    analysis_session = models.ForeignKey(AnalysisSession, on_delete=models.CASCADE, null=False)
    # timestamp = models.CharField(max_length=200)
    # s_port = models.IntegerField()
    # sc_http_status = models.CharField(max_length=200)
    # sc_bytes = models.CharField(max_length=200)
    # sc_header_bytes = models.CharField(max_length=200)
    # c_port = models.CharField(max_length=200)
    # cs_bytes = models.CharField(max_length=200)
    # cs_header_bytes = models.CharField(max_length=200)
    # cs_method = models.CharField(max_length=50)
    # cs_url = models.URLField(max_length=255)
    # s_ip = models.CharField(max_length=200)
    # c_ip = models.CharField(max_length=200)
    # connection_time = models.CharField(max_length=200)
    # request_time = models.CharField(max_length=200)
    # response_time = models.CharField(max_length=200)
    # close_time = models.CharField(max_length=200)
    # idle_time0 = models.CharField(max_length=200)
    # idle_time1 = models.CharField(max_length=200)
    # cs_mime_type = models.CharField(max_length=200)
    # cs_Referer = models.CharField(max_length=200)
    # cs_User_Agent = models.CharField(max_length=200)
    time = models.CharField(max_length=200, null=True)
    http_url = models.URLField(max_length=255, null=True)
    http_status = models.CharField(max_length=30, null=True)
    endpoints_server = models.CharField(max_length=100, null=True)
    transfer_upload = models.IntegerField(null=True)
    transfer_download = models.IntegerField(null=True)
    time_duration = models.CharField(max_length=200, null=True)
    http_referer = models.CharField(max_length=200, null=True)
    http_userAgent = models.CharField(max_length=200, null=True)
    contentType_fromHttp = models.CharField(max_length=200, null=True)
    user_name = models.CharField(max_length=200, null=True)
    # Verdict Status Attr
    VERDICT_STATUS = Choices(('malicious','Malicious'), ('legitimate','Legitimate'), ('suspicious','Suspicious'), ('undefined', 'Undefined'), ('false_positive','False Positive'))
    verdict = models.CharField(choices=VERDICT_STATUS, default=VERDICT_STATUS.legitimate, max_length=20)
    #attrs useful for auditing
    created_at = models.TimeField(auto_now_add=True)
    updated_at = models.TimeField(auto_now=True)
    register_status = enum.EnumField(RegisterStatus, default=RegisterStatus.READY)
    dt_id = -1

    class Meta:
        db_table = 'manati_weblogs'

    @classmethod
    def get_model_fields(model):
        # attrs = [f.name for f in model._meta.get_fields()]
        # attrs.remove('analysis_session')
        # attrs.remove('created_at')
        # attrs.remove('updated_at')
        # return attrs
        return ['time', 'http_url', 'http_status', 'endpoints_server', 'transfer_upload', 'transfer_download',
                'time_duration', 'http_referer', 'http_userAgent', 'contentType_fromHttp','user_name', 'verdict',
                'register_status']

    def get_model_fields_json(self):
        return self.get_model_fields()

