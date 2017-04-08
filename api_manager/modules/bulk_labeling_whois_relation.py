from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class BulkLabelingWhoisRelation(Module):
    module_name = 'bulk_labeling_whois_relation'
    description = 'This module can find all the weblogs related with one selected, in the same session and ' \
                  'and mark these weblogs related with the same verdict that the selected one'
    version = 'v0.1'
    authors = ['Raul B. Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.by_request]

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        pass

module_obj = BulkLabelingWhoisRelation()
