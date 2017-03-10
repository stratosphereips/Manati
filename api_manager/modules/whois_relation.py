from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class WhoisRelation(Module):
    module_name = 'whois_relation'
    description = 'the idea is find whois relations between all weblogs of one analysis session. The "whois distance"' \
                  ' between the whois information of the domains of the weblogs'
    version = 'v0.1'
    authors = ['Raul B. Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.after_save]
    CONSTANT_THRESHOLD = 0.5 # I found this value after the experiment number 5.

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        analysis_session_id = weblogs_seed[0]['fields']['analysis_session']
        analysis_session = json.loads(ModulesManager.get_filtered_analysis_session_json(id=analysis_session_id))[0]
        type_file = analysis_session['fields']['type_file']
        url = ModulesManager.INFO_ATTRIBUTES[type_file]['url']
        ip_dist = ModulesManager.INFO_ATTRIBUTES[type_file]['ip_dist']
        domains_joins = []
        for weblog_a in weblogs_seed:
            domains_measured = {}
            fields_a = weblog_a['fields']
            id_a = weblog_a['pk']
            attributes_a = json.loads(fields_a['attributes'])
            domain_a = ModulesManager.get_domain_by_obj(attributes_a)
            for weblog_b in weblogs_seed:
                fields_b = weblog_b['fields']
                id_b = weblog_b['pk']
                if id_a == id_b:
                    continue
                attributes_b = json.loads(fields_b['attributes'])
                join = [id_a, id_b]
                domain_b = ModulesManager.get_domain_by_obj(attributes_b)
                if join not in domains_joins and list(reversed(join)) not in domains_joins:
                    distance = ModulesManager.distance_domains(domain_a,domain_b)
                    if distance <= self.CONSTANT_THRESHOLD:
                        domains_measured.setdefault(id_a,[]).append(id_b)
                        domains_measured.setdefault(id_b,[]).append(id_a)
                        domains_joins.append(join)
                else:
                    continue
            ModulesManager.update_whois_related_weblogs(domains_measured, id__in=domains_measured.keys())
        ModulesManager.module_done(self.module_name)

module_obj = WhoisRelation()