from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class BulkLabeling(Module):
    module_name = 'bulk_labeling'
    description = 'Getting all labeled weblogs seed, and find for all the weblogs with the same domain'
    version = 'v0.3'
    authors = ['Raul Benitez']
    events = [ModulesManager.MODULES_RUN_EVENTS.bulk_labelling]

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        domains = []
        for weblog in weblogs_seed:
            verdict = weblog['verdict']
            if not verdict in dict(ModulesManager.LABELS_AVAILABLE):
                continue
            attributes = weblog['attributes']
            if isinstance(attributes, basestring):
                attributes = json.loads(attributes)
            _ , domain = ModulesManager.get_domain_by_obj(attributes)

            if domain != '':
                domains.append(domain)
        domains = list(set(domains))
        for domain in domains:  
            mod_attribute = {
                    'verdict': verdict,
                    'description': 'Labelled to '+verdict+' because one weblog before,'
                                   ' with the same domain was labeled with the same verdict'}
            ModulesManager.update_mod_attribute_filtered_weblogs(self.module_name, mod_attribute,domain)
        ModulesManager.module_done(self.module_name)

module_obj = BulkLabeling()