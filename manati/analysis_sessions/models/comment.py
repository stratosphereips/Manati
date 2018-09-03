# Copyright (C) 2016-2018 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'docs/LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 8/26/18.

from django.db import models
from .base import TimeStampedModel
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.auth.models import User


class Comment(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE) # Weblog or AnalysisSession
    object_id = models.CharField(max_length=20)
    content_object = GenericForeignKey('content_type', 'object_id')
    text = models.CharField(max_length=255)

    class Meta:
        db_table = 'manati_comments'
