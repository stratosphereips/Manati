#
# Copyright (c) 2017 Stratosphere Laboratory.
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


class WhoisRelationReq(Module):
    module_name = 'whois_relation_req'
    description = 'the idea is to find whois relations between all weblogs of one analysis session using ' \
                  'one seed weblog times N weblogs. The "WHOIS Similarity Distance"' \
                  ' between the WHOIS information of the domains of the weblogs'
    version = 'v0.1'
    authors = ['Raul B. Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.by_request]
    # CONSTANT_THRESHOLD = 0.5  # I found this value after the experiment number 5.

    def run(self, **kwargs):
        event = kwargs['event_thrown']
        domain_primary = json.loads(kwargs['domains'])[0]
        analysis_session_id = kwargs['analysis_session_id']
        domains_list = list(set(ModulesManager.get_all_IOC_by(analysis_session_id)))
        domains_added = []

        for domain_b in domains_list:
            # we don't care the if it is related or not. In the UI, the user can use threshold slider.
            related, distance_numeric, distance_feature_detail = ModulesManager.distance_related_domains(self.module_name,
                                                                                domain_primary,
                                                                                domain_b)
            if not domain_b in domains_added:
                ModulesManager.add_whois_related_domain(self.module_name,
                                                        analysis_session_id,
                                                        domain_primary, domain_b,
                                                        distance_feature_detail, distance_numeric)
                domains_added.append(domain_b)
        ModulesManager.whois_similarity_distance_module_done(self.module_name,
                                                             analysis_session_id,
                                                             domain_primary)

module_obj = WhoisRelationReq()
