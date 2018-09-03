from django.db import models
from .base import TimeStampedModel
from django.db import transaction
from manati import __version__ as manati_version
from manati.analysis_sessions.utils import RegisterStatus, print_exception, postpone
import json
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from jsonfield import JSONField
import datetime



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
        measure['version_app'] = str(manati_version)
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
        measure['version_app'] = str(manati_version)
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
