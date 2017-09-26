from django import forms
from userena.forms import EditProfileForm
from userena.utils import get_profile_model
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit


class UserProfileForm(forms.Form):
    """ Base form used for fields that are always required """

    virustotal_key_api = forms.CharField(
        label="VirusTotal KEY API",
        max_length=200,
        required=False,
    )

    passivetotal_user = forms.CharField(
        label="PassiveTotal USER/EMAIL",
        max_length=90,
        required=False,
    )

    passivetotal_key_api = forms.CharField(
        label="PassiveTotal KEY API",
        max_length=200,
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super(UserProfileForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-exampleForm'
        self.helper.form_class = 'blueForms'
        self.helper.form_method = 'post'
        self.helper.form_action = 'submit_survey'
        self.helper.add_input(Submit('submit', 'Update Info'))
