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
from api_manager.core.modules_manager import ModulesManager
import login
from django.core import management
import threading
from manati import settings
import os

path_name = 'manati_project'

urlpatterns = [

    url(r'^'+path_name+'/manati_ui/', include('manati_ui.urls')),
    url(r'^'+path_name+'/admin/', include(admin.site.urls)),
    url(r''+path_name+'/', include('login.urls')),
    url(r'^'+path_name+'/index.html$', login.views.home, name="home"),
    url(r'^'+path_name+'/login/$', views.login, {'template_name': 'login.html', 'authentication_form': LoginForm}),
    url(r'^'+path_name+'/logout/$', views.logout, {'next_page':'/manati_project/login'}),
    url(r'^', login.views.home, name="home"),

]

ModulesManager.checking_modules()
ModulesManager.register_modules()


def __run_background_task_service__():
    path_log_file = os.path.join(settings.BASE_DIR, 'logs')
    logfile_name = os.path.join(path_log_file, "background_tasks.log")
    logfile_task_manager = os.path.join(path_log_file, "creating_task.log")
    thread = threading.Thread(target=management.call_command, args=('process_tasks',
                                                                    "--sleep", "10",
                                                                    "--log-level", "DEBUG",
                                                                    "--log-std", logfile_name))
    # thread.daemon = True  # Daemonize thread
    thread.start()

__run_background_task_service__()
