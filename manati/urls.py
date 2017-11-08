#
# Copyright (c) 2017 Stratosphere Lab.
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
"""manati URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import include,url
from django.contrib import admin
from django.contrib.auth import views
from login.forms import LoginForm
import login
from manati import settings

path_name = 'manati_project'

urlpatterns = [

    url(r'^'+path_name+'/manati_ui/', include('manati_ui.urls')),
    url(r'^'+path_name+'/admin/', include(admin.site.urls)),
    url(r'^'+path_name+'/django-rq/', include('django_rq.urls')), # adding django-rq urls.
    url(r''+path_name+'/', include('login.urls')),
    url(r'^'+path_name+'/index.html$', login.views.home, name="home"),
    url(r'^'+path_name+'/login/$', views.login, {'template_name': 'login.html', 'authentication_form': LoginForm}),
    url(r'^'+path_name+'/logout/$', views.logout, {'next_page':'/manati_project/login'}),
    url(r'^', login.views.home, name="home"),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [
        url(r'^__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns




