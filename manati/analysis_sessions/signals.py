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
from django.db.models.signals import post_save,pre_save,pre_delete
from django.dispatch import receiver
from manati.analysis_sessions.models import *


@receiver(pre_save, sender=Weblog)
def check_id(sender, **kwargs):
    instance = kwargs.get('instance')
    if len(instance.id.split(':')) <= 1:
        instance.id = str(instance.analysis_session_id)+":"+str(instance.id)


@receiver(post_save, sender=Weblog)
def create_ioc(sender, **kwargs):
    instance = kwargs.get('instance')
    created = kwargs.get('created')
    if created:
        instance.create_IOCs()


@receiver(pre_delete, sender=Weblog)
def pre_delete_story(sender, instance, **kwargs):
    instance.ioc_set.clear()
