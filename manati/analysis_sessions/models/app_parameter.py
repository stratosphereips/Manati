# Copyright (C) 2016-2018 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'docs/LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 8/26/18.
from django.db import models
from .base import TimeStampedModel
from model_utils import Choices


class AppParameter(TimeStampedModel):
    KEY_OPTIONS = Choices(('virus_total_key_api', 'Virus Total Key API'))
    key = models.CharField(choices=KEY_OPTIONS, default='', max_length=20, null=False)
    value = models.CharField(null=False, default='', max_length=255)

    class Meta:
        db_table = 'manati_app_parameters'
