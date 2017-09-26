from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import ugettext as _
from userena.models import UserenaBaseProfile
from encrypted_fields import EncryptedTextField, EncryptedEmailField
from model_utils.fields import AutoCreatedField, AutoLastModifiedField


class UserProfile(UserenaBaseProfile):
    user = models.OneToOneField(User, unique=True, related_name='profile')
    passivetotal_key_api = EncryptedTextField(null=True, max_length=255)
    passivetotal_user = EncryptedEmailField(null=True, max_length=60)
    virustotal_key_api = EncryptedTextField(null=True, max_length=255)
    created_at = AutoCreatedField(_('created_at'))
    updated_at = AutoLastModifiedField(_('updated_at'))

    class Meta:
        db_table = 'manati_users_profiles'

