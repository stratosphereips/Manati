from django.contrib.auth.forms import AuthenticationForm 
from django import forms

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Username", max_length=30, 
                               widget=forms.TextInput(attrs={"placeholder": "Username", 'class': 'form-control', 'name': 'username', "autofocus": True}))
    password = forms.CharField(label="Password", max_length=30, 
                               widget=forms.TextInput(attrs={'type': 'password', "placeholder": "Password",'class': 'form-control', 'name': 'password'}))