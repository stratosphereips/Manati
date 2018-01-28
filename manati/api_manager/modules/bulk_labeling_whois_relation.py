# Copyright (C) 2016-2018 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'docs/LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 1/28/18.
from api_manager.core.modules_manager import ModulesManager
from api_manager.common.abstracts import Module


class BulklabelingWhoisrelation(Module):

    module_name = 'bulk_labeling_whois_relation'
    description = 'FAKE MODULE FOR BULK WHOIS LABELING. THIS PROCESS IS IMPLEMENTED IN modules_manage.py'
    version = 'v0.1'
    authors = ['Raul B. Netto']
    events = [ModulesManager.MODULES_RUN_EVENTS.by_request]

    def run(self, **kwargs):
        pass


module_obj = BulklabelingWhoisrelation()
