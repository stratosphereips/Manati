from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class TestModule(Module):
    module_name = 'test_module'
    acronym = 'tm'
    description = 'nothing to say, is just a test'
    version = 'v0.1'
    authors = ['Raul Benitez']
    events = [ModulesManager.MODULES_RUN_EVENTS.labelling]

    def run(self, *args):
        event = args['event_thrown']
        weblog = args['weblog']
        weblogs = json.loads(ModulesManager.get_all_weblogs_json())
        # do something with that
        ModulesManager.set_changes_weblogs(self.module_name, weblogs)
        #end

module_obj = TestModule()
