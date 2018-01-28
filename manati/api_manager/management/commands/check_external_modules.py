# Copyright (C) 2016-2017 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'docs/LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 11/10/17.

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from api_manager.models import ExternalModule
import config.settings.base as settings
import json
import imp
import os
import logging
import threading
# Get an instance of a logger
logger = logging.getLogger(__name__)

def postpone(function):
    def decorator(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()

    return decorator

@transaction.atomic
def register_modules():
    print("######################################################")
    print("Starting tp register new External Modules ....")
    path = str(settings.APPS_DIR.path('api_manager/modules'))
    assert os.path.isdir(path) is True
    try:
        for filename in os.listdir(path):
            if filename == '__init__.py' or filename == '__init__.pyc' or filename[-4:] == '.pyc' \
                    or filename[-3:] != '.py':
                continue
            module_instance = "".join(filename[0:-3].title().split('_'))
            module_path = os.path.join(path, filename)
            module = imp.load_source(module_instance, module_path)
            m = module.module_obj
            exms = ExternalModule.objects.filter(module_name=m.module_name)
            if exms.exists():
                exm = exms.first()
                if exm.status == ExternalModule.MODULES_STATUS.removed:
                    exm.status = ExternalModule.MODULES_STATUS.idle
                    exm.save()
                    print("Module: " + m.module_name + "enabled")
            else:
                ExternalModule.objects.create(module_instance, filename, m.module_name,
                                                    m.description, m.version, m.authors,
                                                    m.events)
                print("New Module added: " + m.module_name)
    except Exception as ex:
        logger.error(str(ex))
        raise ex
    print("Finished registering new External Modules succeed ")
    print("######################################################")

@transaction.atomic
def checking_modules():
    print("######################################################")
    print("Starting to check  external modules ....")
    path = str(settings.APPS_DIR.path('api_manager/modules'))
    modules = ExternalModule.objects.all()
    assert os.path.isdir(path) is True
    try:
        for module in modules:
            filename = module.filename
            filename_path = os.path.join(path, filename)
            file_exist = os.path.exists(filename_path) is True
            if not file_exist and not module.status == ExternalModule.MODULES_STATUS.removed:
                # remove module or change its status
                module.status = ExternalModule.MODULES_STATUS.removed
                module.save()
                print("Module: " + module.module_name + " is removed")
            elif file_exist:
                # update information
                module_file = imp.load_source(module.module_instance, filename_path)
                module_instanced = module_file.module_obj
                module.description = module_instanced.description
                module.version = module_instanced.version
                module.authors = module_instanced.authors
                module.run_in_events = json.dumps(module_instanced.events)
                module.status = ExternalModule.MODULES_STATUS.idle
                module.save()
                print("Information of Module: " + module.module_name + " is checked")

    except Exception as ex:
        logger.error(str(ex))
        raise ex
    print("Finished to check External Modules succeed ")
    print("######################################################")


class Command(BaseCommand):

    def handle(self, *args, **options):
        register_modules()
        checking_modules()

