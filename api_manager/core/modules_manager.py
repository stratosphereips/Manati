import json
import os
import imp
from manati import settings
from manati_ui.models import Weblog, ModuleAuxWeblog
from django.utils import timezone
from api_manager.models import ExternalModule
from background_task import background
from django.core import serializers
from django.db import transaction
from manati_ui.utils import *
import re
from django.db.models import Q


class ModulesManager:
    # ('labelling', 'bulk_labelling', 'labelling_malicious')
    MODULES_RUN_EVENTS = ExternalModule.MODULES_RUN_EVENTS

    def __init__(self):
        pass

    @staticmethod
    @background(schedule=timezone.now())
    def load_modules():
        pass

    @staticmethod
    @transaction.atomic
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
    # @background(schedule=timezone.now())
    def register_modules():
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        for filename in os.listdir(path):
            if filename == '__init__.py' or filename == '__init__.pyc' or filename[-4:] == '.pyc':
                continue
            module_instance = "".join(filename[0:-3].title().split('_'))
            module_path = os.path.join(path, filename)
            module = imp.load_source(module_instance, module_path)
            m = module.module_obj
            exms = ExternalModule.objects.filter(module_name=m.module_name)
            if exms.exists():
                exm = exms.first()
                if exm.status == ExternalModule.MODULES_STATUS.removed:
                    module.status = ExternalModule.MODULES_STATUS.idle
                    module.save()
            else:
                exm = ExternalModule.objects.create(module_instance, filename, m.module_name,
                                                    m.description, m.version, m.authors,
                                                    m.acronym, m.events)

    @staticmethod
    def execute_module(external_module, event_thrown, weblogs_seed_json, path=os.path.join(settings.BASE_DIR, 'api_manager/modules')):
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        external_module.mark_running(save=True)
        return module.module_obj.run(event_thrown=event_thrown,
                              weblogs_seed=weblogs_seed_json)

    @staticmethod
    def run_modules():
        pass

    @staticmethod
    def get_all_weblogs_json():
        return serializers.serialize('json', Weblog.objects.all())

    @staticmethod
    def get_filtered_weblogs_json(**kwargs):
        return serializers.serialize('json', Weblog.objects.filter(Q(**kwargs)))

    @staticmethod
    @transaction.atomic
    def update_mod_attribute_filtered_weblogs(module_name, mod_attribute, **kwargs):
        with transaction.atomic():
            external_module = ExternalModule.objects.get(module_name=module_name)
            weblogs = Weblog.objects.filter(Q(**kwargs))
            for weblog in weblogs:
                weblog.set_mod_attributes(external_module.module_name,external_module.acronym , mod_attribute, save=True)
                if 'verdict' in mod_attribute:
                    weblog.set_verdict_from_module(mod_attribute['verdict'], external_module, save=True)

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
                weblog.set_mod_attributes(module.module_name,module.acronym, fields['mod_attributes'], save=True)
                if 'verdict' in fields['mod_attributes']:
                    weblog.set_verdict_from_module(fields['mod_attributes']['verdict'], module, save=True)

    @staticmethod
    def __run_modules(event_thrown, modules, weblogs_seed_json):
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        # weblogs_json_all = serializers.serialize("json",Weblog.objects.all()) # just for testing
        # weblogs_json = {
        #             ModulesManager.MODULES_RUN_EVENTS.labelling:  weblogs_json_all,
        #             ModulesManager.MODULES_RUN_EVENTS.bulk_labelling: weblogs_json_all,
        #           }.get(event_thrown)
        for external_module in modules:
            module_path = os.path.join(path, external_module.filename)
            module_instance = external_module.module_instance
            module = imp.load_source(module_instance, module_path)
            external_module.mark_running(save=True)
            module.module_obj.run(event_thrown=event_thrown,
                                  weblogs_seed=weblogs_seed_json)

    @staticmethod
    @background(schedule=timezone.now())
    def __attach_event(event_name, weblogs_seed_json):
        try:
            external_modules = ExternalModule.objects.find_by_event(event_name)
            ModulesManager.__run_modules(event_name, external_modules, weblogs_seed_json)
        except Exception as e:
            print_exception()
            for external_module in external_modules:
                ModulesManager.module_done(external_module.module_name)


    @staticmethod
    def attach_all_event():
        aux_weblogs = ModuleAuxWeblog.objects.select_related('weblog').filter(status=ModuleAuxWeblog.STATUS.seed)
        if aux_weblogs.exists() and aux_weblogs.count() > 10:
            weblogs_seed_json = serializers.serialize('json', [ w.weblog for w in aux_weblogs])
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling, weblogs_seed_json)
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.bulk_labelling, weblogs_seed_json)
            weblogs_malicious = [w.weblog for w in aux_weblogs.filter(weblog__verdict=Weblog.VERDICT_STATUS.malicious)]
            if weblogs_malicious:
                print(weblogs_malicious)
                weblogs_seed_json = serializers.serialize('json', weblogs_malicious)
                ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling_malicious, weblogs_seed_json)
            aux_weblogs.delete()


    @staticmethod
    def attach_event_after_update_verdict(weblogs_seed_json):
        try:
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling, weblogs_seed_json)
        except Exception as e:
            print_exception()

    @staticmethod
    def get_domain(url):
        """Return top two domain levels from URI"""
        re_3986_enhanced = re.compile(r"""
            # Parse and capture RFC-3986 Generic URI components.
            ^                                    # anchor to beginning of string
            (?:  (?P<scheme>    [^:/?#\s]+): )?  # capture optional scheme
            (?://(?P<authority>  [^/?#\s]*)  )?  # capture optional authority
                 (?P<path>        [^?#\s]*)      # capture required path
            (?:\?(?P<query>        [^#\s]*)  )?  # capture optional query
            (?:\#(?P<fragment>      [^\s]*)  )?  # capture optional fragment
            $                                    # anchor to end of string
            """, re.MULTILINE | re.VERBOSE)
        re_domain = re.compile(r"""
            # Pick out top two levels of DNS domain from authority.
            (?P<domain>[^.]+\.[A-Za-z]{2,6})  # $domain: top two domain levels.
            (?::[0-9]*)?                      # Optional port number.
            $                                 # Anchor to end of string.
            """,
                               re.MULTILINE | re.VERBOSE)
        result = ""
        m_uri = re_3986_enhanced.match(url)
        if m_uri and m_uri.group("authority"):
            auth = m_uri.group("authority")
            m_domain = re_domain.search(auth)
            if m_domain and m_domain.group("domain"):
                result = m_domain.group("domain");
        return result



