#
# Copyright (c) 2017 Stratosphere Lab.
# 
# This file is part of ManaTI Project 
# (see <https://stratosphereips.org>). It was created by 'Raul B. Netto <raulbeni@gmail.com>'
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program. See the file 'docs/LICENSE' or see <http://www.gnu.org/licenses/> 
# for copying permission.
#
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
