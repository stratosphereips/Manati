from __future__ import unicode_literals

from django.apps import AppConfig


class ManatiUiConfig(AppConfig):
    name = 'manati_ui'
    verbose_name = 'Manati UI Application'

    def ready(self):
        import manati_ui.signals
