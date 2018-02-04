#
# Copyright (c) 2017 Stratosphere Laboratory.
# 
# This file is part of ManaTI Project 
# (see <https://stratosphereips.org>). It was created by 'Raul B. Netto <raulbeni@gmail.com>'
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program. See the file 'docs/LICENSE' or see <http://www.gnu.org/licenses/> 
# for copying permission.
#
from django.contrib.auth.forms import AuthenticationForm 
from django import forms

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Username", max_length=30, 
                               widget=forms.TextInput(attrs={"placeholder": "Username", 'class': 'form-control', 'name': 'username', "autofocus": True}))
    password = forms.CharField(label="Password", max_length=30, 
                               widget=forms.TextInput(attrs={'type': 'password', "placeholder": "Password",'class': 'form-control', 'name': 'password'}))