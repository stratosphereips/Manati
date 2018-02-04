from django.conf.urls import include,url
from . import forms

urlpatterns = [
    url(r'^(?P<username>[\.\w-]+)/edit/$', 'userena.views.profile_edit',
        {'edit_profile_form': forms.EditProfileFormExtra,'success_url': '/profile_form.html'}, name='edit-profile'),
    url(r'^', include('userena.urls')),
]
