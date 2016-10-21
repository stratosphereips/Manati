from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module


class TestModule(Module):
    module_name = 'test_module'
    acronym = 'tm'
    description = 'nothing to say, is just a test'
    version = 'v0.1'
    authors = ['Raul Benitez']
    events = [ModulesManager.MODULES_RUN_EVENTS.labelling]

    def run(self):
        pass

module_obj = TestModule()
