from abc import ABCMeta, abstractmethod


class Module(object):

    __metaclass__ = ABCMeta
    module_name = ''
    description = ''
    version = ''
    authors = []
    events = []

    def __init__(self):
        pass

    @abstractmethod
    def run(self, *args):
        # try:
        #     self.args = self.parser.parse_args(self.command_line)
        # except ArgumentErrorCallback as e:
        #     self.log(*e.get())
        pass

    def module_key(self):
        return self.module_name + "_" + self.version

    def __str__(self):
        return "; ".join([self.module_name, ", ".join(self.authors), self.description])

    def __getitem__(self, key):
        return self.module_name
