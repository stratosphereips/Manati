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
from django.http import Http404, HttpResponseRedirect, HttpResponse, JsonResponse
from django.template.loader import render_to_string, get_template
from django.template import Context, Template
from django.contrib import messages

# `data` is a python dictionary
def render_to_json(request, data):
    # return HttpResponse(
    #     json.dumps(data, ensure_ascii=False),
    #     mimetype=request.is_ajax() and "application/json" or "text/html"
    # )
    temp = get_template('messages.html')
    c = {"stooges": ["Larry", "Curly", "Moe"]}
    msg = render_to_string('manati_ui/messages.html', {messages: messages})
    # msg = temp.render(c)
    return JsonResponse(dict(data=data, msg=msg ))

