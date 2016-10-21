import json
import os
import imp
from manati import settings
from manati_ui.models import Weblog
from django.utils import timezone
from api_manager.models import ExternalModule
from background_task import background
from django.core import serializers
from django.db import transaction


class ModulesManager:

    MODULES_RUN_EVENTS = ExternalModule.MODULES_RUN_EVENTS

    def __init__(self):
        pass

    @staticmethod
    @background(schedule=timezone.now())
    def load_modules():
        pass

    @staticmethod
    @background(schedule=timezone.now())
    def checking_modules():
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        modules = ExternalModule.objects.all()
        for module in modules:
            filename = module.filename
            filename_path = os.path.join(path, filename)
            if os.path.exists(filename_path) is False:
                module.status = ExternalModule.MODULES_STATUS.removed
                module.save()


    @staticmethod
    @background(schedule=timezone.now())
    def register_modules():
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        for filename in os.listdir(path):
            if filename == '__init__.py' or filename == '__init__.pyc':
                continue
            module_instance = "".join(filename[0:-3].title().split('_'))
            module_path = os.path.join(path, filename)
            module = imp.load_source(module_instance, module_path)
            m = module.module_obj
            exms = ExternalModule.objects.filter(module_name=m.module_name)
            if exms.exists() is False:
                exm = ExternalModule.objects.create(module_instance, filename, m.module_name,
                                                    m.description, m.version, m.authors,
                                                    m.acronym, m.events)

    @staticmethod
    def execute_module(module_name):
        pass

    @staticmethod
    def run_modules():
        pass

    @staticmethod
    @background(schedule=timezone.now())
    def get_all_weblogs_json():
        return serializers.serialize('json', Weblog.objects.all())

    @staticmethod
    def set_changes_weblogs(module_name, weblogs_json):
        weblogs = json.loads(weblogs_json)
        module = ExternalModule.objects.get(module_name=module_name)
        for attr_weblog in weblogs:
            with transaction.atomic():
                weblog = Weblog.objects.get(id=attr_weblog.pk)
                attributes = json.loads(attr_weblog.attributes)
                weblog.set_mod_attributes(module.acronym, attributes['mod_attributes'], save=True)
                # weblog.set_verdict_from_module() thinking about that


        pass
