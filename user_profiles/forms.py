#encoding:utf-8

from __future__ import unicode_literals
from django import forms
from userena.forms import EditProfileForm
from userena.utils import get_profile_model
from django.utils.translation import ugettext_lazy as _
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Field, Layout, HTML
from crispy_forms.bootstrap import FormActions


class EditProfileFormExtra(EditProfileForm):
    """ Base form used for fields that are always required """
    first_name = forms.CharField(label=_('First Name'), max_length=30,required=False)
    last_name = forms.CharField(label=_('Last name'),max_length=30,required=False)
    # email = forms.EmailField(required=False)
    passivetotal_key_api = forms.CharField(widget=forms.Textarea, label=_('PassiveTotal KEY API'),
                                           required=False, max_length=255)
    passivetotal_user = forms.CharField(label=_('PassiveTotal EMAIL USER'),required=False, max_length=60)
    virustotal_key_api = forms.CharField(widget=forms.Textarea, label=_('VirusTotal KEY API'),
                                         required=False, max_length=255)

    def __init__(self, *args, **kwargs):
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('first_name'),
            Field('last_name'),
            Field('passivetotal_user'),
            Field('passivetotal_key_api', rows="3", css_class='input-xlarge'),
            Field('virustotal_key_api', rows="3", css_class='input-xlarge'),
            FormActions(
                HTML("<a href='{% url 'userena_password_change' user.username %}' "
                     "class='btn btn-link'>Change password</a>"),
                # HTML("<a href='{% url 'userena_email_change' user.username %}' "
                #      "class='btn btn-link'>Change email</a>"),
                HTML("<a href='/manati_project/manati_ui/analysis_session/new' "
                     "class='btn btn-link' id='button-id-cancel'>Cancel</a>"),
                Submit('save_changes', 'Save changes', css_class="btn-primary"),
            )
        )
        super(EditProfileFormExtra, self).__init__(*args, **kwargs)

    class Meta:
        model = get_profile_model()
        exclude = ['user', 'mugshot', 'privacy']
