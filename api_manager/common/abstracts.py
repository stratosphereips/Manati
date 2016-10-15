from abc import ABCMeta, abstractmethod


class Module(object):

    __metaclass__ = ABCMeta
    module_name = ''
    description = ''
    version = ''
    authors = []

    def __init__(self):
        # self.parser = ArgumentParser(prog=self.cmd, description=self.description)
        pass

    @abstractmethod
    def run(self):
        # try:
        #     self.args = self.parser.parse_args(self.command_line)
        # except ArgumentErrorCallback as e:
        #     self.log(*e.get())
        pass

    def module_key(self):
        return self.module_name + "_" + self.version