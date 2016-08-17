from django import template
import subprocess

register = template.Library()


@register.simple_tag
def get_git_revision_number():
    return subprocess.check_output(['git', 'rev-list', '--count', 'HEAD'])