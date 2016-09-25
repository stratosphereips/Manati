from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
from manati_ui.models import *

@receiver(pre_save, sender=Weblog)
def check_id(sender, **kwargs):
    instance = kwargs.get('instance')
    if len(instance.id.split(':')) <= 1:
        instance.id = str(instance.analysis_session_id)+":"+str(instance.id)
