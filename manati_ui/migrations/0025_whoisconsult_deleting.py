from __future__ import unicode_literals
from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [("manati_ui", "0024_analysissession_status")]

    operations = [
        migrations.DeleteModel("WhoisConsult"),
    ]