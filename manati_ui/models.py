from __future__ import unicode_literals
import datetime
from django.db import models, migrations
from django.utils import timezone
from django.contrib.auth.models import User
from model_utils import Choices
from model_utils.fields import AutoCreatedField, AutoLastModifiedField
from django.utils.translation import ugettext_lazy as _
from django.db import IntegrityError, transaction
from django.contrib.messages import constants as message_constants
from django.core.exceptions import ValidationError
from django_enumfield import enum
from threading import Thread
from utils import *
import json
from jsonfield import JSONField
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


# from django.db.models.signals import post_save
# from django.dispatch import receiver

MESSAGE_TAGS = {
    message_constants.DEBUG: 'info',
    message_constants.INFO: 'info',
    message_constants.SUCCESS: 'success',
    message_constants.WARNING: 'warning',
    message_constants.ERROR: 'danger',
}


def postpone(function):
  def decorator(*args, **kwargs):
    t = Thread(target = function, args=args, kwargs=kwargs)
    t.daemon = True
    t.start()
  return decorator


@postpone
def delete_threading(previous_exist):
    previous_exist.delete()


class AnalysisSessionManager(models.Manager):

    @transaction.atomic
    def create(self, filename, key_list, weblogs, current_user):
        try:
            analysis_session = AnalysisSession()
            analysis_sessions_users = None
            wb_list = []
            previous_exist = AnalysisSession.objects.filter(name=filename).first()
            if isinstance(previous_exist, AnalysisSession):
                delete_threading(previous_exist)
            with transaction.atomic():
                analysis_session.name = filename
                analysis_session.clean()
                analysis_session.save()
                analysis_sessions_users = AnalysisSessionUsers.objects.create(analysis_session_id=analysis_session.id,
                                                                              user_id=current_user.id,
                                                                              columns_order=json.dumps(key_list))
                for elem in weblogs:
                    i = 0
                    hash_attr = {}
                    for k in key_list:
                        hash_attr[k] = elem[i]
                        i += 1
                    verdict = hash_attr["verdict"]
                    dt_id = hash_attr["dt_id"]
                    hash_attr.pop("db_id", None)
                    hash_attr.pop("register_status", None)
                    hash_attr.pop('verdict', None)
                    hash_attr.pop('dt_id', None)

                    wb = Weblog.objects.create(analysis_session_id=analysis_session.id, register_status=RegisterStatus.READY, id=dt_id, verdict=verdict, attributes=json.dumps(hash_attr), mod_attributes=json.dumps({}))
                    wb.clean()
                    wb_list.append(wb)

            return analysis_session
        except Exception as e:
            print_exception()
            return None


    @transaction.atomic
    def add_weblogs(self,analysis_session_id,key_list, data):
        try:
            temp_key_list = key_list
            print("Weblogs to save: ")
            print(len(data))
            wb_list = []
            with transaction.atomic():
                for elem in data:
                    i = 0
                    hash_attr = {}
                    for k in temp_key_list:
                        hash_attr[k] = elem[i]
                        i += 1
                    wb = Weblog()
                    wb.analysis_session_id = analysis_session_id
                    wb.register_status = RegisterStatus.READY
                    wb.dt_id = hash_attr["dt_id"]
                    wb.verdict = hash_attr["verdict"]
                    hash_attr.pop("db_id", None)
                    hash_attr.pop("register_status", None)
                    hash_attr.pop('verdict', None)
                    hash_attr.pop('dt_id', None)
                    wb.attributes = json.dumps(hash_attr)
                    wb.clean()
                    wb.save()
                    wb_list.append(wb)
            print("Weblogs saved: ")
            print(len(wb_list))
            return wb_list
        except ValidationError as e:
            print_exception()
            return e
        except IntegrityError as e:
            print_exception()
            return e
        except Exception as e:
            print_exception()
            return e

    @transaction.atomic
    def sync_weblogs(self, analysis_session_id,data):
        try:
            print("Weblogs to update: ")
            print(len(data))
            data_ids = list(data.keys())
            with transaction.atomic():
                #get all WB changed by models
                analysis_session = AnalysisSession.objects.get(id=analysis_session_id)
                wb_list = analysis_session.weblog_set.filter(register_status=RegisterStatus.MODULE_MODIFICATION)
                wb_exlude_similar = wb_list.exclude(id__in=data_ids)
                list_objs = []
                for wb in wb_exlude_similar:
                    wb.set_register_status(RegisterStatus.READY, save=True)
                    list_objs.append(wb)

                wb_similar = analysis_session.weblog_set.filter(id__in=data_ids)
                for wb in wb_similar:
                    wb.set_verdict(data[str(wb.id)], save=True)
                    list_objs.append(wb)

            return list_objs
        except ValidationError as e:
            print_exception()
            return []
        except IntegrityError as e:
            print_exception()
            return []
        except Exception as e:
            print_exception()
            return []


class TimeStampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    ``created`` and ``modified`` fields.

    """
    created_at = AutoCreatedField(_('created_at'))
    updated_at = AutoLastModifiedField(_('updated_at'))

    class Meta:
        abstract = True


class RegisterStatus(enum.Enum):
    NOT_SAVE = -1
    READY = 0
    CLIENT_MODIFICATION = 1
    MODULE_MODIFICATION = 3
    UPGRADING_LOCK = 2


class AnalysisSession(TimeStampedModel):
    users = models.ManyToManyField(User, through='AnalysisSessionUsers')
    name = models.CharField(max_length=200, blank=False, null=False, default='Name by Default')

    objects = AnalysisSessionManager()

    def __unicode__(self):
        return self.name

    class Meta:
        db_table = 'manati_analysis_sessions'


class AnalysisSessionUsers(TimeStampedModel):
    analysis_session = models.ForeignKey(AnalysisSession)
    user = models.ForeignKey(User)
    columns_order = JSONField(default=json.dumps({}), null=True)

    class Meta:
        db_table = 'manati_analysis_sessions_users'


class Weblog(TimeStampedModel):
    id = models.CharField(primary_key=True, null=False, max_length=15)
    analysis_session = models.ForeignKey(AnalysisSession, on_delete=models.CASCADE, null=False)
    attributes = JSONField(default=json.dumps({}), null=False)
    # Verdict Status Attr
    VERDICT_STATUS = Choices(('malicious','Malicious'),
                             ('legitimate','Legitimate'),
                             ('suspicious','Suspicious'),
                             ('undefined', 'Undefined'),
                             ('false_positive','False Positive'),
                             ('malicious_legitimate', 'Malicious/Legitimate'),
                             ('suspicious_legitimate', 'Suspicious/Legitimate'),
                             ('undefined_legitimate', 'Undefined/Legitimate'),
                             ('false_positive_legitimate', 'False Positive/Legitimate'),
                             ('undefined_malicious', 'Undefined/Malicious'),
                             ('suspicious_malicious', 'Suspicious/Malicious'),
                             ('false_positive_malicious', 'False Positive/Malicious'),
                             ('false_positive_suspicious', 'False Positive/Suspicious'),
                             ('undefined_suspicious', 'Undefined/Suspicious'),
                             ('undefined_false_positive', 'Undefined/False Positive'),
                             )
    verdict = models.CharField(choices=VERDICT_STATUS, default=VERDICT_STATUS.undefined, max_length=20, null=True)
    register_status = enum.EnumField(RegisterStatus, default=RegisterStatus.READY, null=True)
    mod_attributes = JSONField(default=json.dumps({}), null=True)
    dt_id = -1

    class Meta:
        db_table = 'manati_weblogs'

    def set_register_status(self, status, save=False):
        self.register_status = status
        if save:
            self.save()
    def set_verdict_from_module(self, verdict, save=False):
        #method that modules have to use for changing the verdict
        pass
    def set_verdict(self, verdict, save=False):
        #ADDING LOCK
        #check if verdict exist
        if verdict in dict(self.VERDICT_STATUS):
            if self.verdict and self.register_status == RegisterStatus.MODULE_MODIFICATION:
                temp_verdict1 = str(self.verdict) + '_' + str(verdict)
                temp_verdict2 = str(verdict) + '_' + str(self.verdict)
                if temp_verdict1 in dict(self.VERDICT_STATUS):
                    self.verdict = temp_verdict1
                elif temp_verdict2 in dict(self.VERDICT_STATUS):
                    self.verdict = temp_verdict2
                else:
                    raise KeyError
                self.set_register_status(RegisterStatus.READY)
            elif self.verdict and self.register_status == RegisterStatus.READY:
                self.verdict = verdict
            elif self.verdict:
                # this check any new state that we didn't consider yet
                raise Exception("It must not happen, there is register_status not zero (or READY) and should be to be changed")
            elif not self.verdict:
                #SOMETHING IS TOTALLY WRONG
                raise Exception(
                    "It must not happen, verdict is false  and should be to be changed")
        else:
            raise ValidationError

        if save:
            self.save()


class WeblogHistory(TimeStampedModel):
    weblog = models.ForeignKey(Weblog)
    new_verdict = models.CharField(choices=Weblog.VERDICT_STATUS, default=Weblog.VERDICT_STATUS.undefined, max_length=20, null=False)
    old_verdict = models.CharField(choices=Weblog.VERDICT_STATUS, default=Weblog.VERDICT_STATUS.undefined, max_length=20, null=False)
    description = models.CharField(max_length=255, null=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE) #User or Module
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')

    class Meta:
        db_table = 'manati_weblog_history'


class Comments(TimeStampedModel):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE) # Weblog or AnalysisSession
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')
    text = models.CharField(max_length=255)

    class Meta:
        db_table = 'manati_comments'


class Metric(TimeStampedModel):
    event_name = models.CharField(max_length=30)
    params = JSONField(default='', null=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)  #User or Module
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')

    class Meta:
        db_table = 'manati_metrics'


#class Module(TimeStampedModel):
# ????????




