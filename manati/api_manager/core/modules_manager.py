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
import json
import imp
import config.settings.base as settings
import whois
from manati.analysis_sessions.models import Weblog, ModuleAuxWeblog, AnalysisSession, IOC
from django.utils import timezone
from manati.api_manager.models import ExternalModule, IOC_WHOIS_RelatedExecuted
from background_task import background
from django.core import serializers
from django.db import transaction
from manati.analysis_sessions.utils import *
import re
from django.db.models import Q
from model_utils import Choices
import manati.share_modules as share_modules
from manati.share_modules.constants import Constant
from tryagain import retries
from manati.analysis_sessions.serializers import WeblogSerializer
import manati.share_modules.whois_distance as whois_distance
import threading
import os
from django.db import connection
from django.core import management
import django.core.exceptions
import logging
import django_rq
from django_rq import job


# Get an instance of a logger
logger = logging.getLogger(__name__)


def postpone(function):
    def decorator(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()

    return decorator


def run_external_module(event_thrown, module_name, weblogs_seed_json):
    print("Running module: " + module_name)
    logger.info("Running module: " + module_name)
    path = str(settings.APPS_DIR.path('api_manager/modules'))
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

def __run_find_whois_related_domains__(analysis_session_id,domain, domains_json):
    try:
        external_module = ExternalModule.objects.get(module_name='whois_relation_req')
        module_name = external_module.module_name
        event_name = ModulesManager.MODULES_RUN_EVENTS.by_request
        print("Running module: " + module_name)
        logger.info("Running module: " + module_name)
        path = str(settings.APPS_DIR.path('api_manager/modules'))
        assert os.path.isdir(path) is True
        external_module = ExternalModule.objects.get(module_name=module_name)
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        module.module_obj.run(event_thrown=event_name,
                              analysis_session_id=analysis_session_id,
                              domains=domains_json)
    except Exception as ex:
        logger.error(str(ex))
        logger.error("ERROR Running module: whois_relation_req was stopped")
        IOC_WHOIS_RelatedExecuted.mark_error(analysis_session_id, domain)


def __bulk_labeling_by_whois_relation_aux__(username, analysis_session_id, domain,verdict):
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

class ModulesManager:
    # ('labelling', 'bulk_labelling', 'labelling_malicious')
    MODULES_RUN_EVENTS = ExternalModule.MODULES_RUN_EVENTS
    LABELS_AVAILABLE = Choices('malicious','legitimate','suspicious','undefined','falsepositive')
    INFO_ATTRIBUTES = AnalysisSession.INFO_ATTRIBUTES
    URL_ATTRIBUTES_AVAILABLE = Constant.URL_ATTRIBUTES_AVAILABLE
    background_task_thread = None

    @staticmethod
    def execute_module(external_module, event_thrown, weblogs_seed_json,
                       path=str(settings.APPS_DIR.path('api_manager/modules'))):
        module_path = os.path.join(path, external_module.filename)
        module_instance = external_module.module_instance
        module = imp.load_source(module_instance, module_path)
        external_module.mark_running(save=True)
        return module.module_obj.run(event_thrown=event_thrown, weblogs_seed=weblogs_seed_json)

    @staticmethod
    def run_modules():
        pass


##########################
#### API METHODS #########
##########################
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

    def get_filtered_weblogs(**kwargs):
        weblogs_qs = Weblog.objects.filter(Q(**kwargs))
        return weblogs_qs

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
            return whois_distance.get_whois_information_features_of(external_module, domains)
        except Exception as e:
            print(e)
            print_exception()
            return None

    @staticmethod
    def distance_domains(module_name, domain_a, domain_b):
        external_module = ExternalModule.objects.get(module_name=module_name)
        return whois_distance.distance_domains(external_module,domain_a, domain_b)

    @staticmethod
    def distance_related_domains(module_name, domain_a, domain_b):
        external_module = ExternalModule.objects.get(module_name=module_name)
        return whois_distance.distance_related_by_whois_obj(external_module, domain_a, domain_b)

    @staticmethod
    @transaction.atomic
    def update_mod_attribute_filtered_weblogs(module_name, mod_attribute,domain):
        with transaction.atomic():
            external_module = ExternalModule.objects.get(module_name=module_name)
            verdict = mod_attribute.get('verdict', None)
            Weblog.bulk_verdict_and_attr_from_module(domain,verdict,mod_attribute,external_module)

    @staticmethod
    @transaction.atomic
    def add_whois_related_domain(module_name, analysis_session_id, domain_a, domain_b, distance_feture_detail, numeric_distance):
        with transaction.atomic():
            IOC.add_whois_related_couple_domains(domain_a, domain_b, distance_feture_detail,numeric_distance)

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

    ##########################
    #### ENDS API METHODS #########
    ##########################

    @staticmethod
    def __attach_event(event_name, weblogs_seed_json, async=True):
        # try:
        external_modules = ExternalModule.objects.find_by_event(event_name)
        if len(external_modules) > 0:
            if async:
                queue = django_rq.get_queue('default')
                for external_module in external_modules:
                    queue.enqueue(run_external_module,
                                  event_name,
                                  external_module.module_name,
                                  weblogs_seed_json)

            else:
                for external_module in external_modules:
                    run_external_module(event_name, external_module.module_name, weblogs_seed_json)

        # except Exception as e:
        #     print(e)
        #     print_exception()
        #     for external_module in external_modules:
        #         ModulesManager.module_done(external_module.module_name)

    @staticmethod
    def db_table_exists(table_name):
        return table_name in connection.introspection.table_names()

    @staticmethod
    def attach_all_event():
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
    def bulk_labeling_by_whois_relation(username, analysis_session_id, domain,verdict):
        queue = django_rq.get_queue('high')
        queue.enqueue(__bulk_labeling_by_whois_relation_aux__,
                      username,
                      analysis_session_id,
                      domain,verdict)

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
        queue = django_rq.get_queue('high')
        for domain in domains:
            IOC_WHOIS_RelatedExecuted.start(analysis_session_id, domain)
            domains_json = json.dumps([domain])
            queue.enqueue(__run_find_whois_related_domains__,
                          analysis_session_id,
                          domain,
                          domains_json)


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
            return ModulesManager.get_domain_from_url(str(attributes_obj[key_url]))
        else:
            return None
    @staticmethod
    def get_domain_from_url(url):
        return share_modules.util.get_data_from_url(url)

    @staticmethod
    def check_to_WHOIS_relate_domain(analysis_session_id, domain):
        if not IOC_WHOIS_RelatedExecuted.started(analysis_session_id, domain):
            ModulesManager.find_whois_related_domains(analysis_session_id, [domain])




