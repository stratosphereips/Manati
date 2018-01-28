from __future__ import unicode_literals

from django.apps import AppConfig


class UserProfilesConfig(AppConfig):
    name = 'manati.user_profiles'
    verbose_name = "User Profiles"

    def ready(self):
        import manati.user_profiles.signals
        pass
