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
from django import template
import subprocess
import manati
import config.settings.base as settings
register = template.Library()


@register.simple_tag
def get_git_revision_number():
    if settings.DEBUG:
        try:
            return "git rev.: " +str(subprocess.check_output(['git', 'rev-list', '--count', 'HEAD']))
        except OSError as ose:
            return "v" + version_app()
        except Exception as ex:
            return "v" + version_app()
    else:
        return "v" + version_app()

@register.simple_tag
def version_app():
    return manati.__version__

@register.simple_tag
def display_flash_messages(messages):
    html = []
    for message in messages:
        temp_html = "<div class='alert alert-%s alert-dismissable' >" % message.level_tag
        temp_html += "<button class='close' data-dismiss='alert' aria-hidden='true' > & times;></button>"
        temp_html += str(message)
        temp_html += "</div>"
        html.append(temp_html)

    return ''.join(html)
