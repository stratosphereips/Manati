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

from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module
import json


class BulkFindWhois(Module):
    module_name = 'bulk_find_whois'
    description = 'Find all the whois information of the weblogs recently saved'
    version = 'v0.1'
    authors = ['Raul B. Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.after_save]

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        weblogs_seed = json.loads(kwargs['weblogs_seed'])
        analysis_session_id = weblogs_seed[0]['analysis_session_id']
        analysis_session = ModulesManager.get_filtered_analysis_session_json(id=analysis_session_id)[0]
        type_file = analysis_session.type_file
        url = ModulesManager.INFO_ATTRIBUTES[type_file]['url']
        ip_dist = ModulesManager.INFO_ATTRIBUTES[type_file]['ip_dist']
        domains= []
        for weblog_a in weblogs_seed:
            id_a = weblog_a['id']
            attributes_a = weblog_a['attributes']
            type, domain_a = ModulesManager.get_domain_by_obj(attributes_a)
            if type == 'domain':
                domains.append(domain_a)
        domains = list(set(domains))
        ModulesManager.get_whois_features_of(self.module_name, domains)
        ModulesManager.module_done(self.module_name)

module_obj = BulkFindWhois()