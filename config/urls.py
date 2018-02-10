from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from django.contrib import admin
from django.views.generic import TemplateView, RedirectView
from django.views import defaults as default_views
from django.contrib.auth import views
import manati.login.views
import manati.login.forms

path_name = 'manati_project'
urlpatterns = [
    # url(r'^$', TemplateView.as_view(template_name='pages/home.html'), name='home'),
    # url(r'^about/$', TemplateView.as_view(template_name='pages/about.html'), name='about'),

    # Django Admin, use {% url 'admin:index' %}
    url(settings.ADMIN_URL, admin.site.urls),

    # User management
    # url(r'^users/', include('manati.users.urls', namespace='users')),
    # url(r'^accounts/', include('allauth.urls')),

    # Your stuff: custom urls includes go here
    url(r'^'+path_name+'/manati_ui/', include('analysis_sessions.urls')),
    url(r'^'+path_name+'/user_profiles/', include('user_profiles.urls')),
    url(r'^'+path_name+'/admin/', include(admin.site.urls)),
    url(r'^'+path_name+'/django-rq/', include('django_rq.urls')), # adding django-rq urls.
    url(r''+path_name+'/', include('login.urls')),
    url(r'^'+path_name+'/index.html$', manati.login.views.home, name="home"),
    url(r'^'+path_name+'/login/$', views.login, {'template_name': 'login.html', 'authentication_form': manati.login.forms.LoginForm}),
    url(r'^'+path_name+'/logout/$', views.logout, {'next_page':'/manati_project/login'}),
    url(r'^$','manati.analysis_sessions.views.new_analysis_session_view', name="redirect-default"),


] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    # This allows the error pages to be debugged during development, just visit
    # these url in browser to see how these error pages look like.
    urlpatterns += [
        url(r'^400/$', default_views.bad_request, kwargs={'exception': Exception('Bad Request!')}),
        url(r'^403/$', default_views.permission_denied, kwargs={'exception': Exception('Permission Denied')}),
        url(r'^404/$', default_views.page_not_found, kwargs={'exception': Exception('Page not Found')}),
        url(r'^500/$', default_views.server_error),
    ]
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            url(r'^__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
