import json
import os
import imp
from model_utils import Choices
from manati import settings
from manati_ui.models import Weblog
from api_manager.models import ExternalModule
import threading


class ModulesManager:

    MODULES_RUN_EVENTS = ExternalModule.MODULES_RUN_EVENTS

    def __init__(self):
        pass

    @staticmethod
    def load_modules():
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        for filename in os.listdir(path):
            if filename == '__init__.py' or filename == '__init__.pyc':
                continue
            module_instance = "".join(filename[0:-3].title().split('_'))
            path = os.path.join(path, filename)
            module = imp.load_source(module_instance, path)
            m = module.module_obj
            exms = ExternalModule.objects.filter(module_name=m.module_name)
            if exms.exists() is False:
                exm = ExternalModule.objects.create(module_instance, filename, m.module_name,
                                 m.description, m.version, m.authors,
                                 m.acronym, m.events)


    @staticmethod
    def checking_modules():
        pass

    @staticmethod
    def register_modules():
        pass

    @staticmethod
    def execute_module(module_name):
        pass

    @staticmethod
    def run_modules():
        pass

    @staticmethod
    def get_all_weblogs():
        return json.dumps({})

    @staticmethod
    def set_changes_weblogs(weblogs):
        pass
