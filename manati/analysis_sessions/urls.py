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
from django.conf.urls import url
from manati.analysis_sessions import views

app_name = 'manati_ui'

urlpatterns = [
    # url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^analysis_session/new$', views.new_analysis_session_view, name='new_analysis_session'),
    url(r'^analysis_session/(?P<pk>[0-9]+)/edit', views.EditAnalysisSession.as_view(), name='edit_analysis_session'),
    url(r'^analysis_session/(?P<id>[0-9]+)/delete', views.delete_analysis_session, name='delete_analysis_session'),
    url(r'^user/edit', views.profile_view, name='profie_view_user'),
    url(r'^analysis_session/(?P<id>[0-9]+)/comment/create', views.update_comment_analysis_session, name='analysis_session_comment'),
    url(r'^weblog/comment/create', views.update_comment_weblog, name='weblog_comment_update'),
    url(r'^weblog/comment/get', views.get_comment_weblog, name='weblog_comment_get'),
    url(r'^user/profile_update', views.profile_update, name='profile_update_user'),
    url(r'^analysis_session/create$', views.create_analysis_session, name='create_analysis_session'),
    url(r'^consult_virus_total$', views.make_virus_total_consult, name='make_virus_total_consult'),
    url(r'^consult_whois$', views.make_whois_consult, name='make_whois_consult'),
    url(r'^export_metrics', views.export_metrics, name='export_metrics'),
    url(r'^analysis_session/weblog/history$', views.get_weblog_history, name='weblog_history'),
    url(r'^analysis_session/weblog/iocs', views.get_weblog_iocs, name='get_weblog_iocs'),
    url(r'^analysis_session/weblog/modules_changes_attributes', views.get_modules_changes, name='weblog_mod_changes'),
    url(r'^analysis_session/weblog/modules_whois_related', views.find_domains_whois_related, name='weblogs_whois_related'),
    url(r'^analysis_session/find_wsd_details', views.find_whois_distance_similarity_details, name='weblogs_whois_related'),
    url(r'^analysis_session/weblog/reload_modal_domains_whois_related', views.refreshing_domains_whois_related,
        name='reload_modal_domains_whois_related'),
    url(r'^analysis_session/weblog/label_weblogs_whois_related', views.label_weblogs_whois_related, name='label_weblogs_whois_related'),
    url(r'^analysis_session/sync_db', views.sync_db, name='sync_db_analysis_session'),
    url(r'^analysis_session/sync_metrics', views.sync_metrics, name='sync_metrics_analysis_session'),
    url(r'^analysis_session/get_weblogs', views.get_weblogs, name='get_weblogs_analysis_session'),
    url(r'^analysis_sessions', views.IndexAnalysisSession.as_view(), name='index_analysis_sessions'),
    url(r'^external_modules', views.IndexExternalModules.as_view(), name='index_external_modules'),
    url(r'^hotkeys/list', views.IndexHotkeys.as_view(), name='index_hotkeys'),
    url(r'^analysis_session/(?P<id>[0-9]+)/publish', views.publish_analysis_session, name='publish_analysis_session'),
    url(r'^analysis_session/(?P<id>[0-9]+)/update_uuid', views.update_uuid_analysis_session,
        name='uuid_analysis_session'),
    url(r'^analysis_session/(?P<id>[0-9]+)/change_status',views.change_status_analysis_session,
        name='changes_status_analysis_session'),
]
