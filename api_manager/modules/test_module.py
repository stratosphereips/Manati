from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json
import random


class TestModule(Module):
    module_name = 'test_module'
    acronym = 'tm'
    description = 'nothing to say, is just a test'
    version = 'v0.1'
    authors = ['Raul Benitez']
    events = [ModulesManager.MODULES_RUN_EVENTS.labelling]

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs = random.sample(json.loads(ModulesManager.get_all_weblogs_json()), 10)
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        for index in range(len(weblogs)):
            weblogs[index]['fields']['mod_attributes'] = {'tested': "Reviewed", "verdict": "malicious"}

        # ModulesManager.set_changes_weblogs(self.module_name, json.dumps(weblogs))
        ModulesManager.module_done(self.module_name)
        return

module_obj = TestModule()
