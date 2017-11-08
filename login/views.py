#!python
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
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect

# Create your views here.
# this login required decorator is to not allow to any  
# view without authenticating
@login_required(login_url="/manati_project/login/")
def home(request):
    redirect = request.GET.get('redirect_to','')
    if redirect == '':
        return HttpResponseRedirect(reverse('manati_ui:new_analysis_session'))
    else:
        return HttpResponseRedirect(str(redirect))
