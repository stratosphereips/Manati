import json
import os
import imp
from manati import settings
import whois
from manati_ui.models import Weblog, ModuleAuxWeblog, AnalysisSession, IOC
from django.utils import timezone
from api_manager.models import ExternalModule, IOC_WHOIS_RelatedExecuted
from background_task import background
from django.core import serializers
from django.db import transaction
from manati_ui.utils import *
import re
from django.db.models import Q
from model_utils import Choices
from share_modules.constants import Constant
from tryagain import retries
from manati_ui.serializers import WeblogSerializer
import share_modules.whois_distance
import threading
import os
from django.db import connection
from django.core import management
import logging


# Get an instance of a logger
logger = logging.getLogger(__name__)


def postpone(function):
    def decorator(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()

    return decorator


class ModulesManager:
    # ('labelling', 'bulk_labelling', 'labelling_malicious')
    MODULES_RUN_EVENTS = ExternalModule.MODULES_RUN_EVENTS
    LABELS_AVAILABLE = Choices('malicious','legitimate','suspicious','undefined','falsepositive')
    INFO_ATTRIBUTES = AnalysisSession.INFO_ATTRIBUTES
    URL_ATTRIBUTES_AVAILABLE = Constant.URL_ATTRIBUTES_AVAILABLE
    background_task_thread = None

    @staticmethod
    @transaction.atomic
    def checking_modules():
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        modules = ExternalModule.objects.all()
        for module in modules:
            filename = module.filename
            filename_path = os.path.join(path, filename)
            if os.path.exists(filename_path) is False:
                # remove module or change its status
                module.status = ExternalModule.MODULES_STATUS.removed
                module.save()
            else:
                #update information
                module_file = imp.load_source(module.module_instance, filename_path)
                module_instanced = module_file.module_obj
                module.description = module_instanced.description
                module.version = module_instanced.version
                module.authors = module_instanced.authors
                module.run_in_events = json.dumps(module_instanced.events)
                module.status = ExternalModule.MODULES_STATUS.idle
                module.save()

    @staticmethod
    @postpone
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
                ExternalModule.objects.create(module_instance, filename, m.module_name,
                                                    m.description, m.version, m.authors,
                                                    m.events)

    @staticmethod
    @background(schedule=timezone.now())
    def execute_module(external_module, event_thrown, weblogs_seed_json,
                       path=os.path.join(settings.BASE_DIR, 'api_manager/modules')):
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        external_module.mark_running(save=True)
        return module.module_obj.run(event_thrown=event_thrown, weblogs_seed=weblogs_seed_json)

    @staticmethod
    def run_modules():
        pass

    @staticmethod
    def get_all_weblogs_json():
        weblogs_qs = Weblog.objects.all()
        weblogs_json = WeblogSerializer(weblogs_qs, many=True).data
        return json.dumps(weblogs_json)

    @staticmethod
    def get_filtered_weblogs_json(**kwargs):
        weblogs_qs = Weblog.objects.filter(Q(**kwargs))
        weblogs_json = WeblogSerializer(weblogs_qs, many=True).data
        return json.dumps(weblogs_json)

    @staticmethod
    def get_filtered_analysis_session_json(**kwargs):
        return AnalysisSession.objects.filter(Q(**kwargs))

    @staticmethod
    def get_whois_info_by_domain_obj(query_node, module=None):
        def make_whois_domain(domain):
            try:
                return whois.whois(domain)
            except Exception as e:
                # print(e)
                print(domain, " is not in DB")
                return None

        return make_whois_domain(query_node)

    @staticmethod
    def get_whois_features_of(module_name, domains):
        try:
            external_module = ExternalModule.objects.get(module_name=module_name)
            return share_modules.whois_distance.get_whois_information_features_of(external_module, domains)
        except Exception as e:
            print(e)
            print_exception()
            return None

    @staticmethod
    def distance_domains(module_name, domain_a, domain_b):
        external_module = ExternalModule.objects.get(module_name=module_name)
        return share_modules.whois_distance.distance_domains(external_module,domain_a, domain_b)

    @staticmethod
    def distance_related_domains(module_name, domain_a, domain_b):
        external_module = ExternalModule.objects.get(module_name=module_name)
        return share_modules.whois_distance.distance_related_by_whois_obj(external_module, domain_a, domain_b)

    @staticmethod
    @transaction.atomic
    def update_mod_attribute_filtered_weblogs(module_name, mod_attribute,domain):
        with transaction.atomic():
            external_module = ExternalModule.objects.get(module_name=module_name)
            verdict = mod_attribute.get('verdict', None)
            Weblog.bulk_verdict_and_attr_from_module(domain,verdict,mod_attribute,external_module)

    @staticmethod
    @transaction.atomic
    def set_whois_related_domains(module_name, analysis_session_id, domains_related):
        with transaction.atomic():
            IOC.add_whois_related_domains(domains_related)

    @staticmethod
    def module_done(module_name):
        module = ExternalModule.objects.get(module_name=module_name)
        module.mark_idle(save=True)
        logger.info("Finishing Module: " + module_name)
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
                weblog.set_mod_attributes(module.module_name, fields['mod_attributes'], save=True)
                if 'verdict' in fields['mod_attributes']:
                    weblog.set_verdict_from_module(fields['mod_attributes']['verdict'], module, save=True)

    @staticmethod
    # @background(schedule=timezone.now())
    def __run_modules(event_thrown, module_name, weblogs_seed_json):
        # try:
        print("Running module: " + module_name)
        logger.info("Running module: " + module_name)
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        external_module = ExternalModule.objects.get(module_name=module_name)
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        # external_module.mark_running(save=True)
        module.module_obj.run(event_thrown=event_thrown,
                              weblogs_seed=weblogs_seed_json)
        # except Exception as es:
        #     print(str(es))
        #
        #     print_exception()
        # ModulesManager.execute_module(external_module, event_thrown, weblogs_seed_json, path) # background task

    @staticmethod
    def __run_modules_sync(event_thrown, module_name, weblogs_seed_json):
        # try:
        print("Running module: " + module_name)
        logger.info("Running module: " + module_name)
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        external_module = ExternalModule.objects.get(module_name=module_name)
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        # external_module.mark_running(save=True)
        module.module_obj.run(event_thrown=event_thrown,
                              weblogs_seed=weblogs_seed_json)

    @staticmethod
    @retries(max_attempts=10, exceptions=(Exception), wait=5)
    def unstable_externa_module_is_free(module_name):
        em = ExternalModule.objects.get(module_name=module_name)
        if em and em.status == ExternalModule.MODULES_STATUS.idle:
            return em
        else:
            raise Exception("The module is not free")

    @staticmethod
    @transaction.atomic
    def get_all_IOC_by(analysis_session_id, ioc_type='domain'):
        analysis_session = AnalysisSession.objects.prefetch_related('weblog_set').get(id=analysis_session_id)
        if ioc_type == 'domain':
            iocs = analysis_session.get_all_IOCs_domain()
        elif ioc_type == 'ip':
            iocs = analysis_session.get_all_IOCs_ip()
        else:
            logger.error('ioc_type is not correct ' + str(ioc_type))
            return None
        return [ioc.value for ioc in iocs]

    @staticmethod
    def __attach_event(event_name, weblogs_seed_json, async=True):
        # try:
        external_modules = ExternalModule.objects.find_by_event(event_name)
        if len(external_modules) > 0:
            if async:
                for external_module in external_modules:
                    ModulesManager.__run_modules(event_name, external_module.module_name, weblogs_seed_json)
            else:
                for external_module in external_modules:
                    ModulesManager.__run_modules_sync(event_name, external_module.module_name, weblogs_seed_json)

        # except Exception as e:
        #     print(e)
        #     print_exception()
        #     for external_module in external_modules:
        #         ModulesManager.module_done(external_module.module_name)

    @staticmethod
    def db_table_exists(table_name):
        return table_name in connection.introspection.table_names()

    @staticmethod
    def __run_background_task_service__():
        if not ModulesManager.background_task_thread and \
                ModulesManager.db_table_exists('manati_externals_modules') and \
                ModulesManager.db_table_exists('background_task') and \
                ModulesManager.db_table_exists('django_content_type'):

            ModulesManager.checking_modules()  # checking modules
            ModulesManager.register_modules()  # registering new modules

            path_log_dir = os.path.join(settings.BASE_DIR, 'logs')
            logfile_name = os.path.join(path_log_dir, "background_tasks.log")
            if not os.path.isfile(logfile_name):
                if not os.path.isdir(path_log_dir):
                    os.makedirs(path_log_dir)
                f = open(logfile_name, "w")
                print('Creating file: ' + logfile_name)
            ModulesManager.background_task_thread = threading.Thread(target=management.call_command, args=('process_tasks',
                                                                            "--sleep", "10",
                                                                            "--log-level", "DEBUG",
                                                                            "--log-std", logfile_name))
            # thread.daemon = True  # Daemonize thread
            ModulesManager.background_task_thread.start()

    @staticmethod
    def attach_all_event():
        ModulesManager.__run_background_task_service__()
        aux_weblogs = ModuleAuxWeblog.objects.filter(status=ModuleAuxWeblog.STATUS.seed)
        if aux_weblogs.exists():
            weblogs_qs = Weblog.objects.filter(moduleauxweblog__in=aux_weblogs.values_list('id', flat=True)).distinct()
            weblogs_seed = WeblogSerializer(weblogs_qs, many=True).data
            weblogs_seed_json = json.dumps(weblogs_seed)
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling, weblogs_seed_json)
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.bulk_labelling, weblogs_seed_json)
            weblogs_malicious = [w.weblog for w in aux_weblogs.filter(weblog__verdict=Weblog.VERDICT_STATUS.malicious)]
            if weblogs_malicious:
                weblogs_seed_json = serializers.serialize('json', weblogs_malicious)
                ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling_malicious, weblogs_seed_json)
            aux_weblogs.delete()

    @staticmethod
    def after_save_attach_event(analysis_session):
        # try:
        weblogs_qs = analysis_session.weblog_set.all()
        weblogs_json = json.dumps(WeblogSerializer(weblogs_qs, many=True).data)
        ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.after_save,weblogs_json)
        # except Exception as e:
        #     print(e)
        #     print_exception()


    @staticmethod
    @background(schedule=timezone.now())
    def bulk_labeling_by_whois_relation(username, analysis_session_id, domain,verdict):
        ModulesManager.check_to_WHOIS_relate_domain(analysis_session_id, domain)
        external_module = ExternalModule.objects.get(module_name='bulk_labeling_whois_relation')
        mod_attribute = {
            'verdict': verdict,
            'description': 'Bulk labeled by WHOIS related function. The seed domain was: ' + domain +
                           ' by the user: ' + username}

        weblogs_whois_related = IOC.get_all_weblogs_WHOIS_related(domain, analysis_session_id)
        Weblog.bulk_verdict_and_attr_from_module(weblogs_whois_related,
                                                 verdict,
                                                 mod_attribute,
                                                 external_module,
                                                 domain)

    @staticmethod
    @background(schedule=timezone.now())
    def __run_find_whois_related_domains__(analysis_session_id, domains_json):
        # special cases of running after events. re-do it now is a HACK!!!
        external_module = ExternalModule.objects.get(module_name='whois_relation_req')
        module_name = external_module.module_name
        event_name = ModulesManager.MODULES_RUN_EVENTS.by_request

        print("Running module: " + module_name)
        logger.info("Running module: " + module_name)
        path = os.path.join(settings.BASE_DIR, 'api_manager/modules')
        assert os.path.isdir(path) is True
        external_module = ExternalModule.objects.get(module_name=module_name)
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        module.module_obj.run(event_thrown=event_name,
                              analysis_session_id=analysis_session_id,
                              domains=domains_json)

    # only for the module whois_relation_req
    @staticmethod
    def whois_similarity_distance_module_done(module_name,analysis_session_id,domain):
        module = ExternalModule.objects.get(module_name=module_name)
        module.mark_idle(save=True)
        IOC_WHOIS_RelatedExecuted.finish(analysis_session_id, domain)
        logger.info("Finishing Module: " + module_name)
        return module

    @staticmethod
    def find_whois_related_domains(analysis_session_id, domains):
        for domain in domains:
            IOC_WHOIS_RelatedExecuted.start(analysis_session_id, domain)
            domains_json = json.dumps([domain])
            ModulesManager.__run_find_whois_related_domains__(analysis_session_id, domains_json)


    @staticmethod
    def attach_event_after_update_verdict(weblogs_seed_json):
        try:
            ModulesManager.__attach_event(ModulesManager.MODULES_RUN_EVENTS.labelling, weblogs_seed_json)
        except Exception as e:
            print_exception()

    @staticmethod
    def get_domain_by_obj(attributes_obj):
        keys = attributes_obj.keys()
        possible_key_url = ModulesManager.URL_ATTRIBUTES_AVAILABLE
        indices = [i for (i, x) in enumerate(keys) if x in set(keys).intersection(possible_key_url)]
        if indices:
            key_url = str(keys[indices[0]])
            if key_url == 'host':
                return str(attributes_obj[key_url])
            else:
                return ModulesManager.get_domain(str(attributes_obj[key_url]))
        else:
            return None

    @staticmethod
    def check_to_WHOIS_relate_domain(analysis_session_id, domain):
        if not IOC_WHOIS_RelatedExecuted.relation_perfomed_by_domain(analysis_session_id, domain):
            ModulesManager.find_whois_related_domains(analysis_session_id, [domain])

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
                result = m_domain.group("domain")
        return result



