from __future__ import unicode_literals

from django.db import models
from manati_ui.models import TimeStampedModel
from model_utils.fields import AutoCreatedField,AutoLastModifiedField
from django.utils.translation import ugettext_lazy as _
from jsonfield import JSONField
from model_utils import Choices
import json


class ExternalModuleManager(models.Manager):

    def create(self, module_instance, filename, module_name, description, version, authors, available_events, *args, **kwargs):
        external_module_obj = ExternalModule()
        external_module_obj.module_instance = module_instance
        external_module_obj.filename = filename
        external_module_obj.module_name = module_name
        external_module_obj.description = description
        external_module_obj.version = version
        external_module_obj.authors = authors
        for event in available_events:
            # if event innot dict(self.VERDICT_STATUS):
            external_module_obj.MODULES_RUN_EVENTS[event]
        external_module_obj.run_in_events = json.dumps(available_events)
        external_module_obj.status = ExternalModule.MODULES_STATUS.idle
        external_module_obj.clean()
        external_module_obj.save()

    def find_idle_modules_by_event(self, event_name):
        return ExternalModule.objects.filter(run_in_events__contains=event_name,
                                             status=ExternalModule.MODULES_STATUS.idle).distinct()

    def find_by_event(self, event_name):
        ets= ExternalModule.objects.filter(run_in_events__contains=event_name)\
            .exclude(status=ExternalModule.MODULES_STATUS.removed).distinct()
        etss = []
        for et in ets:
            run_in_events = json.loads(et.run_in_events)
            if event_name in run_in_events:
                etss.append(et)
        return etss


class ExternalModule(TimeStampedModel):
    MODULES_RUN_EVENTS = Choices('labelling', 'bulk_labelling', 'labelling_malicious', 'after_save', 'by_request')
    MODULES_STATUS = Choices('idle', 'running', 'removed')
    module_instance = models.CharField(max_length=50, unique=True)
    module_name = models.CharField(max_length=50, unique=True)
    description = models.CharField(max_length=200)
    version = models.CharField(max_length=30)
    authors = JSONField(default=json.dumps({}))
    run_in_events = JSONField(default=json.dumps({}))
    filename = models.CharField(max_length=50, null=True)
    status = models.CharField(max_length=20, choices=MODULES_STATUS, default=MODULES_STATUS.idle)

    objects = ExternalModuleManager()

    def set_status(self, status):
        pass

    def get_events(self):
        return json.loads(self.run_in_events)

    def has_event(self, event):
        available_event = self.get_events()
        return event in available_event

    def mark_idle(self, save=False):
        self.status = self.MODULES_STATUS.idle
        # hem = HistoryExternalModule.objects.last()
        # hem.save()
        if save:
            self.save()

    def mark_running(self, save=False):
        self.status = self.MODULES_STATUS.running
        # HistoryExternalModule.objects.create()
        if save:
            self.save()

    class Meta:
        db_table = 'manati_externals_modules'
#
#
# class HistoryExternalModule(models.Model):
#
#     external_module = models.ForeignKey(ExternalModule, on_delete=models.CASCADE, null=False)
#     start_running = AutoCreatedField(_('start_running'))
#     stop_running = AutoLastModifiedField(_('stop_running'))
#
#     class Meta:
#         db_table = 'manati_history_externals_modules'
