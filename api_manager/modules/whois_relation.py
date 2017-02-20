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

    def run(self, **kwargs):
        #
        # implement logic
        #
        ModulesManager.module_done(self.module_name)

module_obj = WhoisRelation()