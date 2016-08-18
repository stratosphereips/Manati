from django.conf.urls import url
from . import views

app_name = 'manati_ui'

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^analysis_session/new$', views.new_analysis_session_view, name='new_analysis_session'),
    url(r'^analysis_session/create$', views.create_analysis_session, name='create_analysis_session'),
    url(r'^analysis_session/sync_db', views.sync_db, name='sync_db_analysis_session'),
    url(r'^analysis_session/add_weblogs', views.add_weblogs, name='add_wb_analysis_session'),
    url(r'^analysis_sessions', views.IndexAnalysisSession.as_view(), name='index_analysis_sessions'),

]