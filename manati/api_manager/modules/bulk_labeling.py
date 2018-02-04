#
# Copyright (c) 2018 Stratosphere Laboratory.
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
from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class BulkLabeling(Module):
    module_name = 'bulk_labeling'
    description = 'Getting all labeled weblogs seed, and the module is looking' \
                  ' for all the weblogs with the same domain in the whole database'
    version = 'v0.3'
    authors = ['Raul Benitez Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.bulk_labelling]  # events when the module will be thrown

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        domains = []
        # getting all the domains of the weblogs labelled recently
        for weblog in weblogs_seed:
            verdict = weblog['verdict']
            if not verdict in dict(ModulesManager.LABELS_AVAILABLE):
                continue
            attributes = weblog['attributes']
            if isinstance(attributes, basestring):
                attributes = json.loads(attributes)
            _ , domain = ModulesManager.get_domain_by_obj(attributes) # getting the domain name from the URL

            if domain != '':
                domains.append(domain)
        domains = list(set(domains))  # just unique domains
        for domain in domains:
            # message of description of the actions performed by the module. It will be added to the attribute
            # mod_attribute of the weblog obj
            mod_attribute = {
                    'verdict': verdict,
                    'description': 'Labelled to '+verdict+' because one weblog before,'
                                   ' with the same domain was labeled with the same verdict'}
            # updating all the weblogs in the DB with given domain
            ModulesManager.update_mod_attribute_filtered_weblogs(self.module_name, mod_attribute,domain)
        # finishing module
        ModulesManager.module_done(self.module_name)

module_obj = BulkLabeling()  # instance of the BulkLabeling module
