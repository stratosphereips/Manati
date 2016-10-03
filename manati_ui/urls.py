from django.conf.urls import url
from . import views

app_name = 'manati_ui'

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^analysis_session/new$', views.new_analysis_session_view, name='new_analysis_session'),
    url(r'^analysis_session/(?P<pk>[0-9]+)/edit', views.EditAnalysisSession.as_view(), name='edit_analysis_session'),
    url(r'^user/edit', views.profile_view, name='profie_view_user'),
    url(r'^user/profile_update', views.profile_update, name='profile_update_user'),
    url(r'^analysis_session/create$', views.create_analysis_session, name='create_analysis_session'),
    url(r'^consult_virus_total$', views.make_virus_total_consult, name='make_virus_total_consult'),
    url(r'^analysis_session/sync_db', views.sync_db, name='sync_db_analysis_session'),
    url(r'^analysis_session/sync_metrics', views.sync_metrics, name='sync_metrics_analysis_session'),
    url(r'^analysis_session/get_weblogs', views.get_weblogs, name='get_weblogs_analysis_session'),
    url(r'^analysis_sessions', views.IndexAnalysisSession.as_view(), name='index_analysis_sessions'),
]