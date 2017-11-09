from django import template
import subprocess
import manati
import manati.settings as settings
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
