from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class BulkMalicious(Module):
    module_name = 'bulk_malicious'
    description = 'Getting the malicious weblogs seed, and find for all the weblogs with the same domain'
    version = 'v0.2'
    authors = ['Raul Benitez']
    events = [ModulesManager.MODULES_RUN_EVENTS.bulk_labelling]

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        for index in range(len(weblogs_seed)):
            fields = weblogs_seed[index]['fields']
            verdict = fields['verdict']
            if not verdict in dict(ModulesManager.LABELS_AVAILABLE):
                continue
            attributes = fields['attributes']
            if isinstance(attributes, basestring):
                attributes = json.loads(attributes)
            domain = ModulesManager.get_domain_by_obj(attributes)

            if domain != '':
                mod_attribute = {
                    'verdict': verdict,
                    'description': 'Labelled to malicious because one weblog before,'
                                   ' with the same domain was marked  malicious'}

                ModulesManager.update_mod_attribute_filtered_weblogs(self.module_name, mod_attribute,
                                                                     attributes__contains=domain)
        ModulesManager.module_done(self.module_name)

module_obj = BulkMalicious()