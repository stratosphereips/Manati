# Copyright (C) 2016-2018 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'docs/LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 1/28/18.

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from manati.user_profiles.models import UserProfile
from django.dispatch import receiver
from django.core import management


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        management.call_command('check_permissions')


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()


