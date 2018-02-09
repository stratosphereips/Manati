#
# Copyright (c) 2017 Stratosphere Laboratory.
#
# This file is part of ManaTI Project
# (see <https://stratosphereips.org>). It was created by 'Raul B. Netto <raulbeni@gmail.com>'
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. See the file 'docs/LICENSE' or see <http://www.gnu.org/licenses/>
# for copying permission.
#
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
from django.contrib.contenttypes.fields import GenericRelation
from django.core import management
from ipwhois import IPWhois
import manati
import whois
from manati.share_modules.virustotal import *
from manati.share_modules.util import get_domain_by_obj, get_data_from_url
import dateutil.parser
import re
import pythonwhois
from pythonwhois.shared import WhoisException
from bulk_update.helper import bulk_update
from guardian.shortcuts import assign_perm
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django_rq import job
vt = vt()



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
    def create(self, filename, key_list, weblogs, current_user,type_file, uuid):
        try:
            analysis_session = AnalysisSession(type_file=type_file, uuid=str(uuid))
            wb_list = []
            previous_exists = AnalysisSession.objects.filter(name=filename, users__id=current_user.id)
            if previous_exists.count() > 0:
                count = 1
                while previous_exists.count() > 0:
                    copy_filename = filename + " " + "(" + str(count) + ")"
                    previous_exists = AnalysisSession.objects.filter(name=copy_filename, users__id=current_user.id)
                    count += 1

                filename = copy_filename

            with transaction.atomic():
                analysis_session.name = filename
                analysis_session.clean()
                analysis_session.save()
                analysis_sessions_users = AnalysisSessionUsers.objects.create(analysis_session_id=analysis_session.id,
                                                                              user_id=current_user.id,
                                                                              columns_order=json.dumps(key_list))
                content_type = ContentType.objects.get_for_model(AnalysisSession)
                permissions = Permission.objects.filter(content_type=content_type)
                for user in analysis_session.users.all():
                    for permission in permissions:
                        assign_perm(permission.codename, user, analysis_session)

                for elem in weblogs:
                    i = 0
                    hash_attr = {}
                    for k in key_list:
                        hash_attr[k['column_name']] = elem[i]
                        i += 1
                    verdict = hash_attr["verdict"]
                    dt_id = hash_attr["dt_id"]
                    hash_attr.pop("db_id", None)
                    hash_attr.pop("register_status", None)
                    hash_attr.pop('verdict', None)
                    hash_attr.pop('dt_id', None)

                    wb = Weblog(   analysis_session=analysis_session,
                                   register_status=RegisterStatus.READY,
                                   id=dt_id,
                                   verdict=verdict,
                                   attributes=json.dumps(hash_attr),
                                   mod_attributes=json.dumps({}))
                    wb.clean(exclude=['analysis_session'])
                    wb_list.append(wb)
                # analysis_session.weblog_set.set(wb_list)
                Weblog.objects.bulk_create(wb_list) # create weblogs
                Weblog.create_bulk_IOCs(wb_list) # create IOCs
            return analysis_session
        except Exception as e:
            print_exception()
            return None

    @transaction.atomic
    def update_uuid(self, analysis_session, analysis_session_uuid, weblogs_id, weblogs_uuid):
        analysis_session.uuid = analysis_session_uuid
        analysis_session.save()
        assert len(weblogs_id) == len(weblogs_uuid)
        for index, id in enumerate(weblogs_id):
            weblog = analysis_session.weblog_set.filter(id=id)[0]
            attribute = weblog.attributes_obj
            attribute['uuid'] = weblogs_uuid[index]
            weblog.attributes = attribute
            weblog.save()

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
    def sync_weblogs(self, analysis_session_id,data, user):
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
                    wb.set_verdict(data[str(wb.id)], user, save=True)
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
    TYPE_FILES = Choices(('bro_http_log','BRO weblogs http.log'),
                         ('cisco_file', 'CISCO weblogs Specific File'),
                         ('apache_http_log', 'Apache logs'))
    STATUS = Choices(('open', 'Open'),('closed', 'Closed'),('removed', 'Removed'))
    INFO_ATTRIBUTES = {TYPE_FILES.cisco_file: {'url':'http.url', 'ip_dist':'endpoints.server'},
                       TYPE_FILES.bro_http_log: {'url': 'host', 'ip_dist': 'id.resp_h'},
                       TYPE_FILES.apache_http_log: {'url': 'host', 'ip_dist': 'id.resp_h'}
                       }

    users = models.ManyToManyField(User, through='AnalysisSessionUsers')
    name = models.CharField(max_length=200, blank=False, null=False, default='Name by Default')
    public = models.BooleanField(default=False)
    type_file = models.CharField(choices=TYPE_FILES, max_length=50, null=False, default=TYPE_FILES.cisco_file)
    uuid = models.CharField(max_length=40, null=True, default='')
    status = models.CharField(choices=STATUS, max_length=30, null=False, default=STATUS.open)

    objects = AnalysisSessionManager()
    comments = GenericRelation('Comment')

    def __unicode__(self):
        return unicode(self.name)

    def get_columns_order_by(self, user):
        asu = AnalysisSessionUsers.objects.filter(analysis_session_id=self.id, user_id=user.id).first()
        if asu is None:
            return []
        else:
            return json.loads(asu.columns_order)

    def set_columns_order_by(self,user,columns_order):
        asu = AnalysisSessionUsers.objects.filter(analysis_session=self,user_id=user.id).first()
        if asu is None:
            asu = AnalysisSessionUsers.objects.create(analysis_session=self, user_id=user.id)
        asu.columns_order = json.dumps(columns_order)
        asu.save()

    def __get_all_IOCs__(self, ioc_type):
        weblogs_ids = self.weblog_set.values_list('id', flat=True)
        return IOC.objects.filter(weblogs__in=weblogs_ids, ioc_type=ioc_type).distinct()

    def get_all_IOCs_domain(self):
        return self.__get_all_IOCs__(IOC.IOC_TYPES.domain)

    def get_all_IOCs_ip(self):
        return self.__get_all_IOCs__(IOC.IOC_TYPES.ip)

    class Meta:
        db_table = 'manati_analysis_sessions'
        permissions = (
            ("read_analysis_session", "Can read an analysis session"),
            ("edit_analysis_session", "Can edit an analysis session"),
            ("create_analysis_session", "Can create an analysis session"),
            ("update_analysis_session", "Can update an analysis session"),
        )


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
                             ('falsepositive','False Positive'),
                             ('malicious_legitimate', 'Malicious/Legitimate'),
                             ('suspicious_legitimate', 'Suspicious/Legitimate'),
                             ('undefined_legitimate', 'Undefined/Legitimate'),
                             ('falsepositive_legitimate', 'False Positive/Legitimate'),
                             ('undefined_malicious', 'Undefined/Malicious'),
                             ('suspicious_malicious', 'Suspicious/Malicious'),
                             ('falsepositive_malicious', 'False Positive/Malicious'),
                             ('falsepositive_suspicious', 'False Positive/Suspicious'),
                             ('undefined_suspicious', 'Undefined/Suspicious'),
                             ('undefined_falsepositive', 'Undefined/False Positive'),
                             )
    verdict = models.CharField(choices=VERDICT_STATUS, default=VERDICT_STATUS.undefined, max_length=50, null=True)
    register_status = enum.EnumField(RegisterStatus, default=RegisterStatus.READY, null=True)
    mod_attributes = JSONField(default=json.dumps({}), null=True)
    comments = GenericRelation('Comment')
    dt_id = -1

    @property
    def domain(self):
        if self.analysis_session.type_file == '':
            self.analysis_session.type_file = AnalysisSession.TYPE_FILES.cisco_file
            self.analysis_session.save()
        key_url = AnalysisSession.INFO_ATTRIBUTES[self.analysis_session.type_file]['url']
        url = self.attributes_obj[key_url]
        d_type, domain = get_data_from_url(url)
        return domain

    @property
    def domain_ioc(self):
        iocs = self.ioc_set.filter(ioc_type=IOC.IOC_TYPES.domain)
        if not iocs:
            self.create_IOCs()
            iocs = self.ioc_set.filter(ioc_type=IOC.IOC_TYPES.domain)
            if not iocs:
                return None
        return iocs.first()

    @property
    def ip(self):
        if self.analysis_session.type_file == '':
            self.analysis_session.type_file = AnalysisSession.TYPE_FILES.cisco_file
            self.analysis_session.save()
        key_ip = AnalysisSession.INFO_ATTRIBUTES[self.analysis_session.type_file]['ip_dist']
        return self.attributes_obj[key_ip]

    @transaction.atomic
    def create_IOCs(self, save=True):
        if not self.ioc_set.all():
            key_url = AnalysisSession.INFO_ATTRIBUTES[self.analysis_session.type_file]['url']
            if key_url in self.attributes_obj:
                url = self.attributes_obj[key_url]
            else:
                return None, None
            ioc_domain = None
            ioc_ip = None
            try:
                d_type, domain = get_data_from_url(url)
                if not domain:
                    raise Exception("Domain value cannot be None")
                else:
                    ioc_domain = IOC.objects.create_IOC_from_weblog(domain, d_type, self,save)
            except Exception as ex:
                logger.error("Error creating domain IOC , weblog-id " + str(self.id) + " | " + str(ex))

            try:
                ip = self.ip
                if not ip:
                    raise Exception("IP value cannot be None")
                else:
                    ioc_ip = IOC.objects.create_IOC_from_weblog(ip, 'ip', self, save)
            except:
                logger.error("Error creating IP IOC , weblog-id " + str(self.id)+ " | " + str(ex))

            return ioc_domain, ioc_ip


    @staticmethod
    @postpone
    def create_bulk_IOCs(weblogs):
        with transaction.atomic():
            for weblog in weblogs:
                weblog.create_IOCs()

    @property
    def attributes_obj(self):
        attr = self.attributes
        if attr:
            if type(attr) == dict:
                return attr
            else:
                return json.loads(attr)
        else:
            return json.loads({})

    class Meta:
        db_table = 'manati_weblogs'

    def clean(self, *args, **kwargs):
        exclude_list = kwargs.pop('exclude', [])
        exclude_list += ['verdict', 'mod_attributes']
        self.clean_fields(exclude=exclude_list, *args, **kwargs)
        if len(self.id.split(':')) <= 1:
            self.id = str(self.analysis_session_id) + ":" + str(self.id)
        merge_verdict = self.verdict.split('_')

        if len(merge_verdict) > 1:
            user_verdict = merge_verdict[0]
            model_verdict = merge_verdict[1]
            temp_verdict1 = str(user_verdict) + '_' + str(model_verdict)
            temp_verdict2 = str(model_verdict)+ '_' + str(user_verdict)
            if temp_verdict1 in dict(self.VERDICT_STATUS) is False and temp_verdict2 in dict(self.VERDICT_STATUS) is False :
                raise ValidationError({'verdict': _('Verdict is incorrect, you should use valid verdicts or merging of valid verdicts')})
            else:
                pass
        else:
            if not (self.verdict in dict(self.VERDICT_STATUS)):
                raise ValidationError(
                    {'verdict': _('Verdict is incorrect, you should use valid verdicts or merging of valid verdicts')})

    def weblogs_history(self):
        return WeblogHistory.objects.filter(weblog=self).order_by('-version')

    def set_mod_attributes(self, module_name, new_mod_attributes, save=False):
        new_mod_attributes['created_at'] = str(datetime.datetime.now())
        new_mod_attributes['Module Name'] = module_name
        if str(self.mod_attributes) == '':
            self.mod_attributes = {}
        try:
            self.mod_attributes[module_name] = new_mod_attributes
        except TypeError as e:
            self.mod_attributes = {}
            self.mod_attributes[module_name] = new_mod_attributes
        # self.moduleauxweblog_set.create(status=ModuleAuxWeblog.STATUS.modified)

        if save:
            self.clean()
            self.save()

    @transaction.atomic
    def save_with_history(self, content_object, *args, **kwargs):
        with transaction.atomic():
            old_wbl = Weblog.objects.get(id=self.id)
            old_verdict = kwargs['old_verdict'] if 'old_verdict' in kwargs else old_wbl.verdict
            new_verdict = kwargs['new_verdict'] if 'new_verdict' in kwargs else self.verdict
            if content_object is None:
                content_object = self.analysis_session.users.first()
            weblog_history = self.weblogs_history()
            if not weblog_history or self.verdict != weblog_history[0].verdict:
                newWeblogHistoy = WeblogHistory(weblog=self,
                                                old_verdict=old_verdict,
                                                verdict= new_verdict,
                                                content_object=content_object)
                newWeblogHistoy.save()
            # # save summary history
            kwargs.pop('old_verdict', None)
            kwargs.pop('new_verdict', None)
            self.clean()
            super(Weblog, self).save(*args, **kwargs)

    def set_register_status(self, status, save=False):
        # if RegisterStatus.is_state(status):
        self.register_status = status
        if save:
            self.clean()
            self.save()
        # else:
        #     raise ValidationError("Status Assigned is not correct")

    @staticmethod
    @transaction.atomic
    def bulk_verdict_and_attr_from_module(domain,module_verdict,mod_attribute,external_module):
        with transaction.atomic():
            weblogs = IOC.get_all_weblogs_by_domain(domain)
            if module_verdict:
                Metric.objects.labeling_by_module(external_module, weblogs, module_verdict,domain)

            for weblog in weblogs:
                weblog.set_mod_attributes(external_module.module_name, mod_attribute, save=False)
                if module_verdict:
                    weblog.set_verdict_from_module(module_verdict, external_module, save=False)
            bulk_update(weblogs)


    def set_verdict_from_module(self, module_verdict, external_module, save=False):
        old_verdict = self.verdict
        # ADDING LOCK
        #method that modules have to use for changing the verdict
        if module_verdict in dict(self.VERDICT_STATUS):
            if self.verdict != self.VERDICT_STATUS.undefined and self.verdict != module_verdict:
                merge_verdicts = self.verdict.split('_')
                if len(merge_verdicts) > 1:
                    user_verdict = merge_verdicts[0]
                else:
                    user_verdict = self.verdict

                ctype = ContentType.objects.filter(model='user')
                ctype = ctype.first()
                last_history = self.histories.filter(content_type=ctype)
                # the some verdict in the history in this weblog was labelled by a user
                if last_history.count() > 0 and not str(user_verdict) == str(module_verdict):
                    temp_verdict = str(user_verdict) + '_' + str(module_verdict)
                else:
                    temp_verdict = str(module_verdict)
                self.verdict = temp_verdict
            else:
                self.verdict = module_verdict
            self.set_register_status(RegisterStatus.MODULE_MODIFICATION)
        else:
            raise ValidationError({'verdict': 'The assigned verdict is invalid ' + module_verdict})

        new_verdict = self.verdict
        if save:
            self.clean()
            self.save_with_history(external_module, old_verdict=old_verdict, new_verdict=new_verdict)

    def set_verdict(self, verdict, user, save=False):
        #ADDING LOCK
        # check if verdict exist
        if verdict in dict(self.VERDICT_STATUS):
            if self.verdict and self.register_status == RegisterStatus.MODULE_MODIFICATION:
                # first is the user says
                temp_verdict = str(verdict) + '_' + str(self.verdict)
                self.verdict = temp_verdict
                # temp_verdict2 = str(verdict) + '_' + str(self.verdict)
                # if temp_verdict1 in dict(self.VERDICT_STATUS):
                #     self.verdict = temp_verdict1
                # elif temp_verdict2 in dict(self.VERDICT_STATUS):
                #     self.verdict = temp_verdict2
                # else:
                #     raise KeyError
                self.set_register_status(RegisterStatus.READY)
            elif self.verdict and self.register_status == RegisterStatus.READY:
                self.verdict = verdict
            elif self.verdict:
                # this check any new state that we didn't consider yet
                raise Exception(
                    "It must not happen, there is register_status not zero (or READY) and should be to be changed")
            elif not self.verdict:
                #SOMETHING IS TOTALLY WRONG
                raise Exception(
                    "It must not happen, verdict is false  and should be to be changed")
        else:
            raise ValidationError

        self.create_aux_seed()
        self.clean()
        if save:
            self.save_with_history(user)

    def create_aux_seed(self):
        self.moduleauxweblog_set.create(status=ModuleAuxWeblog.STATUS.seed)

    def remove_aux_seed(self):
        self.moduleauxweblog_set.filter(status=ModuleAuxWeblog.STATUS.seed).remove()

    def remove_all_aux_weblog(self):
        self.moduleauxweblog_set.clear()


class IOCManager(models.Manager):

    @transaction.atomic
    def create_IOC_from_weblog(self, value, ioc_type, weblog, save=True):
        if not value or not ioc_type or not weblog:
            return None

        iocs = IOC.objects.filter(value=value, ioc_type=ioc_type)
        if not iocs:
            ioc = IOC(value=value, ioc_type=ioc_type)
            if save:
                ioc.save()
        else:
            ioc = iocs[0]

        if save:
            ioc.weblogs.add(weblog)
        return ioc


class IOC(TimeStampedModel):
    value = models.CharField(max_length=256, null=False, unique=True)
    IOC_TYPES = Choices(('domain', 'Domain Name'),('ip', 'IP Address'),)
    ioc_type = models.CharField(choices=IOC_TYPES, max_length=20, null=False)
    weblogs = models.ManyToManyField(Weblog)
    whois_related_iocs = models.ManyToManyField('self', through='WHOISRelatedIOC', symmetrical=False)
    objects = IOCManager()

    @staticmethod
    def add_whois_related_domains(domains_related=[]):
        if len(domains_related) <= 1:
            return None
        iocs = IOC.objects.prefetch_related('whois_related_iocs').filter(value__in=domains_related,
                                                                         ioc_type='domain').distinct()
        exclude_list = []
        for ioc in iocs:
            exclude_list.append(ioc.id)
            # the relation is not symmetric,
            # it is necessary to re join relationships
            for ioc_b in iocs.exclude(id__in=exclude_list):
                if not WHOISRelatedIOC.objects.filter(from_ioc=ioc,to_ioc=ioc_b).exists() and \
                        not WHOISRelatedIOC.objects.filter(from_ioc=ioc_b,to_ioc=ioc).exists():
                    wri = WHOISRelatedIOC(from_ioc=ioc,to_ioc=ioc_b)
                    wri.save()
                # ioc.whois_related_iocs.add(ioc_b)

        return iocs

    @staticmethod
    def add_whois_related_couple_domains(domain_a, domain_b, distance_feature, numeric_distance):

        iocs = IOC.objects.prefetch_related('whois_related_iocs').filter(value__in=[domain_a,domain_b],
                                                                         ioc_type='domain').distinct()
        if iocs.count() > 1:
            ioc_a = iocs[0]
            ioc_b = iocs[1]
            if not WHOISRelatedIOC.objects.filter(from_ioc=ioc_a,to_ioc=ioc_b).exists() and \
                    not WHOISRelatedIOC.objects.filter(from_ioc=ioc_b,to_ioc=ioc_a).exists():
                wri = WHOISRelatedIOC(from_ioc=ioc_a,to_ioc=ioc_b,
                                      features_description=distance_feature,
                                      numeric_distance=numeric_distance)
                wri.save()
        return iocs

    def get_all_values_related_by(self, analysis_session_id):
        wris = self.whois_related_iocs.filter(ioc_type=self.ioc_type,
                                              weblogs__analysis_session_id=analysis_session_id).distinct()
        return [wri.value for wri in wris]

    def get_all_weblogs_from(self, analysis_session_id):
        return self.weblogs.filter(analysis_session_id=analysis_session_id).distinct()

    @staticmethod
    def get_all_weblogs_by_domain(domain):
        iocs = IOC.objects.filter(ioc_type='domain', value=domain)
        if not iocs:
            return []
        else:
            return iocs.first().weblogs.prefetch_related('histories').all().select_related('analysis_session')

    @staticmethod
    def get_all_weblogs_WHOIS_related(domain, analysis_session_id):
        iocs = IOC.objects.prefetch_related('whois_related_iocs').filter(ioc_type='domain', value=domain)
        iocs_id = iocs.values_list('whois_related_iocs__id', flat=True)
        return Weblog.objects.filter(ioc__in=iocs_id, analysis_session_id=analysis_session_id)




    class Meta:
        db_table = 'manati_indicators_of_compromise'


class WHOISRelatedIOC(TimeStampedModel):
    from_ioc = models.ForeignKey(IOC, related_name='from_ioc_id')
    to_ioc = models.ForeignKey(IOC, related_name='to_ioc_id')
    features_description = JSONField(default=json.dumps({}), null=True)
    numeric_distance = models.IntegerField(null=True)

    class Meta:
        db_table = 'manati_indicators_of_compromise_whois_related_iocs'


class WeblogHistory(TimeStampedModel):
    version = models.IntegerField(editable=False, default=0)
    weblog = models.ForeignKey(Weblog, on_delete=models.CASCADE, null=False, related_name='histories')
    verdict = models.CharField(choices=Weblog.VERDICT_STATUS,
                               default=Weblog.VERDICT_STATUS.undefined, max_length=50, null=False)
    old_verdict = models.CharField(choices=Weblog.VERDICT_STATUS,
                                   default=Weblog.VERDICT_STATUS.undefined, max_length=50, null=False)
    description = models.CharField(max_length=255, null=True, default="")
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE) #User or Module
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')

    def get_author_name(self):
        if type(self.content_object).__name__ == "ExternalModule":
            return self.content_object.module_name
        elif isinstance(self.content_object, User):
            return self.content_object.username

    def created_at_txt(self):
        return self.created_at.isoformat()

    class Meta:
        db_table = 'manati_weblog_history'
        unique_together = ('version', 'weblog')

    def save(self, *args, **kwargs):
        # start with version 1 and increment it for each book
        current_version = WeblogHistory.objects.filter(weblog=self.weblog).order_by('-version')[:1]
        self.version = current_version[0].version + 1 if current_version else 1
        super(WeblogHistory, self).save(*args, **kwargs)


class Comment(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE) # Weblog or AnalysisSession
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')
    text = models.CharField(max_length=255)

    class Meta:
        db_table = 'manati_comments'


class MetricManager(models.Manager):

    @transaction.atomic
    def create_bulk_by_user(self, measurements, current_user):
        with transaction.atomic():
            for elem in measurements:
                measure = json.loads(elem)
                event_name = measure['event_name']
                measure.pop('event_name', None)
                Metric.objects.create(event_name=event_name,
                                      params=json.dumps(measure),
                                      content_object=current_user)


    @transaction.atomic
    @postpone
    def labeling_by_module(self, module, weblogs, verdict,query_node):
        if weblogs.count() == 1:
            event_name = 'single_labeling_by_module'
        elif weblogs.count() > 1:
            event_name = 'multiple_labeling_by_module'
        else:
            return

        measure = dict()
        measure['event_produced_by'] = module.module_name
        measure['version_app'] = str(manati.__version__)
        measure['event_name'] = event_name
        measure['created_at'] = str(datetime.datetime.now())
        measure['created_at_precision'] = str(datetime.datetime.now())
        measure['amount_wbls'] = str(weblogs.count())
        measure['new_verdict'] = verdict
        measure['query_node'] = query_node
        measure['weblogs_affected'] = [{'uuid': wb.attributes_obj.get('uuid', '')} for wb in weblogs]
        Metric.objects.create(event_name=event_name,
                              params=json.dumps(measure),
                              content_object=module)

    def change_status_analysis_session(self,event_name,user, analysis_session):
        measure = dict()
        measure['version_app'] = str(manati.__version__)
        measure['event_name'] = event_name
        measure['created_at'] = str(datetime.datetime.now())
        measure['created_at_precision'] = str(datetime.datetime.now())
        measure['analysis_session_name'] = analysis_session.name
        measure['analysis_session_id'] = analysis_session.id
        measure['analysis_session_uuid'] = analysis_session.uuid
        Metric.objects.create(event_name=event_name,
                              params=json.dumps(measure),
                              content_object=user)

    @transaction.atomic
    @postpone
    def close_analysis_session(self, user, analysis_session):
        event_name = 'closing_analysis_session'
        self.change_status_analysis_session(event_name, user, analysis_session)

    @transaction.atomic
    @postpone
    def open_analysis_session(self, user, analysis_session):
        event_name = 'opening_analysis_session'
        self.change_status_analysis_session(event_name, user, analysis_session)


class Metric(TimeStampedModel):
    event_name = models.CharField(max_length=200)
    params = JSONField(default='', null=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)  #User or Module
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')
    objects = MetricManager()

    class Meta:
        db_table = 'manati_metrics'


class VTConsultManager(models.Manager):

    @transaction.atomic
    def create_one_consult(self, query_node,  user, line_report):
        with transaction.atomic():
            info = line_report.split(";")
            index = 0
            info_report_obj = {}
            for elem in info:
                info_report_obj[VTConsult.KEYS_INFO[index]] = elem
                index += 1
            VTConsult.objects.create(query_node=query_node, user=user, info_report=json.dumps(info_report_obj))


class VTConsult(TimeStampedModel):
    KEYS_INFO = ["IP","Rating","Owner","Country Code","Log Line No","Positives","Total","Malicious Samples","Hosts"]
    query_node = models.CharField(max_length=100, null=False)
    info_report = JSONField(default=json.dumps({}), null=False)
    user = models.ForeignKey(User)

    objects = VTConsultManager()

    @staticmethod
    def get_query_info(query_node, user, query_type):
        vt_consul = VTConsult.objects.filter(query_node=query_node,
                                             created_at__gt=timezone.now() - timezone.timedelta(days=15)).first()
        if vt_consul is None:
            if query_type == 'ip':
                management.call_command('virustotal_checker', "--nocsv", "--nocache", ff=query_node, user=user)
                vt_consul = VTConsult.objects.filter(query_node=query_node,
                                                     created_at__gt=timezone.now() - timezone.timedelta(days=15)).first()
            elif query_type == 'domain':
                api_key = user.profile.virustotal_key_api
                if not api_key:
                    api_key = AppParameter.objects.get(key=AppParameter.KEY_OPTIONS.virus_total_key_api).value
                vt.setkey(api_key)
                result = vt.getdomain(query_node)
                vt.setkey(None)
                vt_consul = VTConsult.objects.create(query_node=query_node, user=user, info_report=json.dumps(result))
            else:
                raise ValueError("query_type invalid")
        return vt_consul

    class Meta:
        db_table = 'manati_virustotal_consults'

    def __unicode__(self):
        return unicode(self.info_report) or u''


class AppParameter(TimeStampedModel):
    KEY_OPTIONS = Choices(('virus_total_key_api', 'Virus Total Key API'))
    key = models.CharField(choices=KEY_OPTIONS, default='', max_length=20, null=False)
    value = models.CharField(null=False, default='', max_length=255)

    class Meta:
        db_table = 'manati_app_parameters'


class WhoisConsult(TimeStampedModel):
    QUERY_TYPES = Choices(('ip','IP'),('domain','Domain'),)
    query_node = models.CharField(max_length=100, null=False)
    query_type = models.CharField(max_length=20, null=False, choices=QUERY_TYPES)
    info_report = JSONField(null=True)
    features_info = JSONField(null=True)  # pythonwhois
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE) # User or ExternalModule
    object_id = models.IntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    def __process_result_by_domain__(self,domain, save=True):  # python whois lib
        d = domain
        try:
            if not self.info_report and d:
                r = pythonwhois.get_whois(d)
                self.info_report = r
            elif not d:
                print("PW, domain null " + str(d) + " " + str(self.id))
                self.info_report = {}
        except WhoisException as e:
            print("PW rejects " + str(d)+ " " + str(self.id) + ", ERROR TRACE " + e.message)
            self.info_report = {}
        except:
            self.info_report = {}
            print("PW rejects " + str(d) + " " + str(self.id))

        if save:
            self.save()

    def check_info_report(self, domain, save=True):
        if not self.info_report:
            self.__process_result_by_domain__(domain, save=save)
        return self.info_report


    # python whois
    def process_features_by_domain(self, domain, save=True):
        result = self.check_info_report(domain, save=save)
        raw = result.get('raw', None)
        raw = raw[0].split('\n') if not raw is None else []
        try:
            raw = ','.join(raw).encode('utf-8').strip().split(',')
        except UnicodeDecodeError as e:
            print(raw)
            raw = ','.join(raw).encode('ascii', 'ignore').decode('ascii').strip().split(',')
        # self.features_info_pw

        def get_dict(dict_obj, key, default):
            value = dict_obj.get(key, type(default))
            if not isinstance(value, type(default)) and not type(default) == None:
                return default
            else:
                return value

        def get_emails():
            emails = result.get('emails', [])
            emails = [] if emails is None else emails
            emails = emails.split(',') if not isinstance(emails, list) else emails
            return emails

        def get_domain_name():
            pattern = r'^.*Domain Name:.*$'
            indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
            fields = str(raw[indices[0]]).split(':') if len(indices) > 0 else []
            domain_name = fields[1].strip() if len(fields) > 0 else ''
            if not domain_name or domain_name == '':
                _, domain_name = get_data_from_url(self.query_node)
                domain_name = domain_name if domain_name else ''
            return domain_name

        def get_name_servers():
            ns = result.get('nameservers', [])
            ns = ns.split(',') if isinstance(ns, basestring) else ns
            return ns

        def get_registrar():
            registrar = result.get('registrar', '')
            if not registrar or registrar == '':
                pattern = r'^.*Registrar:.*$'
                indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
                fields = str(raw[indices[0]]).split(':') if len(indices) > 0 else []
                registrar = fields[1].strip() if len(fields) > 0 else ''
            return registrar[0] if isinstance(registrar, list) else registrar

        def get_name():
            contacts = get_dict(result, 'contacts', {})
            name_admin = get_dict(contacts, 'admin', {}).get('name', '')
            name_tech = get_dict(contacts, 'tech', {}).get('name', '')
            name_registrant = get_dict(contacts, 'registrant', {}).get('name', '')
            names = list(set([name_admin, name_tech, name_registrant]))
            names = [n for n in names if n or not n == '']
            name = names[0] if len(names) > 0 else ''
            if not name or name == '':
                pattern = r'^.*name:.*$'
                indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
                names = []
                for indice in indices:
                    fields = str(raw[indice]).split(':') if len(indices) > 0 else []
                    names.append(fields[1].strip() if len(fields) > 0 else '')
                return names[0] if len(names) > 0 else ''
            else:
                return name

        def get_creation_date():
            cd_str = result.get('creation_date', [])
            if cd_str and len(cd_str) > 0:
                if isinstance(cd_str[0], basestring):
                    try:
                        return dateutil.parser.parse(cd_str[0])
                    except:
                        print("Date Invalid ", self.id, cd_str[0])
                        return None
                elif isinstance(cd_str[0], datetime.datetime):
                    return cd_str[0]
            else:
                return None

        def get_expiration_date():
            ed_str = result.get('expiration_date', [])
            if ed_str and len(ed_str) > 0:
                if isinstance(ed_str[0], basestring):
                    try:
                        return dateutil.parser.parse(ed_str[0])
                    except:
                        print("Date Invalid ", self.id, ed_str[0])
                        return None
                elif isinstance(ed_str[0], datetime.datetime):
                    return ed_str[0]
            else:
                return None

        def get_zipcodes():
            contacts = get_dict(result, 'contacts', {})
            postalcode_admin = get_dict(contacts, 'admin', {}).get('postalcode', '')
            postalcode_tech = get_dict(contacts, 'tech', {}).get('postalcode', '')
            postalcode_registrant = get_dict(contacts, 'registrant', {}).get('postalcode', '')
            return list(set([postalcode_admin, postalcode_tech, postalcode_registrant]))

        def get_orgs():
            contacts = get_dict(result, 'contacts', {})
            org_admin = get_dict(contacts, 'admin', {}).get('organization', '')
            org_tech = get_dict(contacts, 'tech', {}).get('organization', '')
            org_registrant = get_dict(contacts, 'registrant', {}).get('organization', '')
            return list(set([org_admin, org_tech, org_registrant]))

        if not self.features_info:
            features = dict(
                emails= get_emails(),
                domain_name=get_domain_name(),
                name_servers=get_name_servers(),
                registrar=get_registrar(),
                name=get_name(),
                creation_date=get_creation_date(),
                expiration_date=get_expiration_date(),
                zipcode=get_zipcodes(),
                org=get_orgs()
            )
            self.features_info = features
            if save:
                self.save()

    @staticmethod
    def get_whois_distance_features_by_domain(content_object, domain_name):
        query_type = 'domain'
        whois_objs = WhoisConsult.objects.filter(query_node=domain_name, query_type=query_type)
        if whois_objs.exists():
            whois = whois_objs.first()
        else:
            whois = WhoisConsult.objects.create(query_node=domain_name, query_type=query_type,
                                                content_object=content_object)
        return whois.whois_distance_features()

    def whois_distance_features(self):
        features = self.check_features_info().copy()
        del features['creation_date']
        del features['expiration_date']
        features['duration'] = self.domain_duration()
        return features

    def domain_duration(self):
        if self.features_info:
            creation_date_a = self.features_info['creation_date']
            expiration_date_a = self.features_info['expiration_date']
            if not creation_date_a or not expiration_date_a:
                return None
            cd_a = dateutil.parser.parse(creation_date_a) if not isinstance(creation_date_a,datetime.datetime) else creation_date_a
            ed_a = dateutil.parser.parse(expiration_date_a) if not isinstance(expiration_date_a,datetime.datetime) else expiration_date_a
            if cd_a and ed_a:
                return float(abs(cd_a - ed_a).days)
            else:
                return None



    def process_features_by_ip(self, ip):
        pass

    def check_features_info(self, save=True):
        if not self.features_info:
            self.process_features_by_domain(self.query_node,save=save)
        return self.features_info

    @staticmethod
    def get_features_info_by_set_url(content_object, urls_or_ips):
        query_ips = []
        query_domains = []
        result = {}
        for url_or_ip in urls_or_ips:
            query_type,query_node = get_data_from_url(url_or_ip)
            if query_type == 'ip':
                query_ips.append(query_node)
            elif query_type == 'domain':
                query_domains.append(query_node)
            result[query_node] = {}

        with transaction.atomic():
            #domain
            whois_objs = WhoisConsult.objects.filter(query_node__in=query_domains, query_type='domain')
            query_node_created = []
            for whois_obj in whois_objs:
                result[whois_obj.query_node] = whois_obj.check_features_info()
                query_node_created.append(whois_obj.query_node)

            whois_objs = []
            for query_node in query_domains:
                if not query_node in query_node_created:
                    whois_objs.append(WhoisConsult(query_node=query_node,
                                                   query_type='domain',
                                                   content_object=content_object))
            WhoisConsult.objects.bulk_create(whois_objs)
            for whois_obj in whois_objs:
                result[whois_obj.query_node] = whois_obj.check_features_info()

            # bulk_update(whois_objs)

            #ip TO-DO by IP
            # whois_objs_ip = WhoisConsult.objects.filter(query_node__in=query_domains, query_type='ip')
            for query_node in query_ips:
                result[query_node] = {}

        return result

    @staticmethod
    def get_features_info(content_object, url_or_ip):
        query_type, query_node = get_data_from_url(url_or_ip)
        if not query_node:
            return {}
        elif query_type == 'domain':
            return WhoisConsult.get_features_info_by_domain(content_object,query_node)
        elif query_type == 'ip':
            # TO-DO IP version
            return {}
        else:
            pass

    @staticmethod
    def get_features_info_by_domain(content_object,domain_name):
        query_type = 'domain'
        whois_objs = WhoisConsult.objects.filter(query_node=domain_name, query_type=query_type)
        if whois_objs.exists():
            whois = whois_objs.first()
        else:
            whois = WhoisConsult.objects.create(query_node=domain_name, query_type=query_type,
                                                content_object=content_object)

        if not whois.features_info:
            whois.process_features_by_domain(domain_name)
        features = whois.features_info
        return features


    @staticmethod
    def __get_query_info__(query_node, user, **kwargs):

        class ComplexEncoder(json.JSONEncoder):
            def default(self, obj):
                if hasattr(obj, 'reprJSON'):
                    return obj.reprJSON()
                if hasattr(obj, 'isoformat'):
                    return obj.isoformat()
                else:
                    return json.JSONEncoder.default(self, obj)

        whois_consult = WhoisConsult.objects.filter(query_node=query_node,
                                                    created_at__gt=timezone.now() - timezone.timedelta(days=365)).first()
        if whois_consult is None:
            if 'ip' in kwargs:
                obj = IPWhois(query_node)
                results = obj.lookup()
                whois_consult = WhoisConsult.objects.create(query_node=query_node,
                                                            info_report=results,
                                                            content_object=user)
            elif 'domain' in kwargs:
                w = pythonwhois.get_whois(query_node)
                whois_consult = WhoisConsult.objects.create(query_node=query_node,
                                                            info_report=w,
                                                            content_object=user)
            else:
                raise ValueError("you must determine is you want to do a domain or ip consultation by __get_query_info" +
                                 "__('query', SomeUser, domain=True or ip=True")
        whois_consult.check_info_report(query_node, save=True)

        return whois_consult

    @staticmethod
    def get_query_info_by_ip(query_node, user):
        return WhoisConsult.__get_query_info__(query_node, user, ip=True)

    @staticmethod
    def get_query_info_by_domain(query_node, user):
        return WhoisConsult.__get_query_info__(query_node, user, domain=True)

    @staticmethod
    def get_query_by_domain(query_node):
        user = User.objects.get(username='anonymous_user_for_metrics')
        return WhoisConsult.get_query_info_by_domain(query_node,user).info_report

    class Meta:
        db_table = 'manati_whois_consults'

    def __unicode__(self):
        return unicode(self.info_report) or u''


class ModuleAuxWeblog(TimeStampedModel):
    weblog = models.ForeignKey(Weblog, on_delete=models.CASCADE)
    STATUS = Choices('seed', 'modified', 'undefined')
    status = models.CharField(choices=STATUS, default=STATUS.undefined, max_length=20, null=False)

    class Meta:
        db_table = 'manati_module_aux_weblogs'


def get_anonymous_user_instance(User):
    return User.objects.get(username='anonymous_user_for_metrics')





