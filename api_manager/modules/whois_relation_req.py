from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class WhoisRelationReq(Module):
    module_name = 'whois_relation_req'
    description = 'the idea is to find whois relations between all weblogs of one analysis session using ' \
                  'one seed weblog times N weblogs. The "WHOIS Similarity Distance"' \
                  ' between the WHOIS information of the domains of the weblogs'
    version = 'v0.1'
    authors = ['Raul B. Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.by_request]
    # CONSTANT_THRESHOLD = 0.5  # I found this value after the experiment number 5.

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        domain_primary = json.loads(kwargs['domains'])[0]
        analysis_session_id = kwargs['analysis_session_id']
        domains_list = list(set(ModulesManager.get_all_IOC_by(analysis_session_id)))
        domains_added = []

        for domain_b in domains_list:
            # we don't care the if it is related or not. In the UI, the user can use threshold slider.
            related, distance_numeric, distance_feature_detail = ModulesManager.distance_related_domains(self.module_name,
                                                                                domain_primary,
                                                                                domain_b)
            if not domain_b in domains_added:
                ModulesManager.set_whois_related_domains(self.module_name,
                                                         analysis_session_id,
                                                        domain_primary,domain_b,
                                                         distance_feature_detail,distance_numeric)
                domains_added.append(domain_b)
        ModulesManager.whois_similarity_distance_module_done(self.module_name,
                                                             analysis_session_id,
                                                             domain_primary)

module_obj = WhoisRelationReq()
