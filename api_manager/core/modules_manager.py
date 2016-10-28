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
from manati_ui.utils import *


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
    def get_all_weblogs_json():
        return serializers.serialize('json', Weblog.objects.all())

    @staticmethod
    def get_filtered_weblogs_json(**kwargs):
        return serializers.serialize('json', Weblog.objects.filter(kwargs))

    @staticmethod
    def module_done(module_name):
        module = ExternalModule.objects.get(module_name=module_name)
        module.mark_idle(save=True)
        return module

    @staticmethod
    @transaction.atomic
    def set_changes_weblogs(module_name, weblogs_json):
        weblogs = json.loads(weblogs_json)
        module = ModulesManager.module_done(module_name)
        for attr_weblog in weblogs:
            with transaction.atomic():
                weblog = Weblog.objects.get(id=attr_weblog['pk'])
                fields = attr_weblog['fields']
                assert isinstance(fields['mod_attributes'], dict)
                weblog.set_mod_attributes(module.acronym, fields['mod_attributes'], save=True)
                # weblog.set_verdict_from_module() thinking about that

    @staticmethod
    def __run_modules(event_thrown, modules, weblogs_seed_json):
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        weblogs_json_all = serializers.serialize("json",Weblog.objects.all()) # just for testing
        weblogs_json = {
                    ModulesManager.MODULES_RUN_EVENTS.labelling:  weblogs_json_all,
                    ModulesManager.MODULES_RUN_EVENTS.bulk_labelling: weblogs_json_all,
                  }.get(event_thrown)
        for external_module in modules:
            module_path = os.path.join(path, external_module.filename)
            module_instance = external_module.module_instance
            module = imp.load_source(module_instance, module_path)
            module.module_obj.run(weblogs=weblogs_json,
                                  event_thrown=event_thrown,
                                  weblogs_seed=weblogs_seed_json)
            external_module.mark_running(save=True)

    @staticmethod
    @background(schedule=timezone.now())
    def __attach_event(event_name, weblogs_seed_json):
        external_modules = ExternalModule.objects.find_by_event(event_name)
        ModulesManager.__run_modules(event_name, external_modules, weblogs_seed_json)

    @staticmethod
    def attach_event_after_update_verdict(weblogs_seed_json):
        try:
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling, weblogs_seed_json)
        except Exception as e:
            print_exception()



