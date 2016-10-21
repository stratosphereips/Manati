from __future__ import unicode_literals

from django.db import models
from manati_ui.models import TimeStampedModel
from jsonfield import JSONField
from model_utils import Choices
import json


class ExternalModuleManager(models.Manager):

    def create(self, module_instance, filename, module_name, description, version, authors, acronym, available_events, *args, **kwargs):
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
        external_module_obj.acronym = acronym[0:5] if len(acronym) > 5 else acronym
        external_module_obj.status = ExternalModule.MODULES_STATUS.idle
        external_module_obj.clean()
        external_module_obj.save()


class ExternalModule(TimeStampedModel):
    MODULES_RUN_EVENTS = Choices('labelling', 'bulk_labelling')
    MODULES_STATUS = Choices('idle', 'running', 'removed')
    module_instance = models.CharField(max_length=20, unique=True)
    module_name = models.CharField(max_length=30, unique=True)
    description = models.CharField(max_length=200)
    version = models.CharField(max_length=20)
    authors = JSONField(default=json.dumps({}))
    run_in_events = JSONField(default=json.dumps({}))
    acronym = models.CharField(max_length=5, unique=True)
    filename = models.CharField(max_length=20, null=True)
    status = models.CharField(max_length=20, choices=MODULES_STATUS, default=MODULES_STATUS.idle)

    objects = ExternalModuleManager()

    def set_status(self, status):
        pass

    def get_events(self):
        return json.loads(self.run_in_events)

    def has_event(self, event):
        available_event = self.get_events()
        return event in available_event

    class Meta:
        db_table = 'manati_externals_modules'
