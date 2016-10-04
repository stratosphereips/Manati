from django import forms
from django.contrib.auth.models import User


class UserProfileForm(forms.Form):
    username = forms.CharField(max_length=20)
    first_name = forms.CharField(max_length=50)
    last_name = forms.CharField(max_length=50)
    email = forms.EmailField(max_length=50)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email']

