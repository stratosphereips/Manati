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
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.decorators import login_required
from guardian.decorators import permission_required_or_403
from django.http import HttpResponseServerError
from django.core.urlresolvers import reverse
from django.views import generic
from manati.analysis_sessions.models import *
from manati.analysis_sessions.forms import UserProfileForm
from django.contrib.auth.models import User, AnonymousUser
from django.views.decorators.csrf import csrf_exempt
from helpers import *
import json, collections
from django.core import serializers
from django.contrib.auth.mixins import LoginRequiredMixin
from utils import *
from manati.share_modules.util import *
from manati.api_manager.core.modules_manager import ModulesManager
from manati.api_manager.models import *
from preserialize.serialize import serialize
from django.db.models import Q
import logging
from manati.analysis_sessions.serializers import WeblogSerializer
import manati.share_modules as share_modules
import django_rq

# Get an instance of a logger
logger = logging.getLogger(__name__)

REDIRECT_TO_LOGIN = "/manati_project/login"
# class IndexView(generic.ListView):
#     template_name = 'manati_ui/index.html'
#     context_object_name = 'latest_question_list'
#
#     def get_queryset(self):
#         """
# 		Return the last five published questions (not including those set to be
# 		published in the future).
# 		"""
#         return ''

# class AnalysisSessionNewView(generic.DetailView):
#     model = AnalysisSession
#     template_name = 'manati_ui/analysis_session/new.html'


def postpone(function):
    def decorator(*args, **kwargs):
        t = Thread(target=function, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()

    return decorator


@postpone
def call_after_save_event(analysis_session):
    ModulesManager.after_save_attach_event(analysis_session)

@postpone
def call_after_sync_event():
    ModulesManager.attach_all_event()  # it will check if will create the task or not


# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def new_analysis_session_view(request):
    context = {'analysissession':AnalysisSession(), 'comment': Comment()}
    return render(request, 'manati_ui/analysis_session/new.html', context)

#ajax connexions
@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def create_analysis_session(request):
    analysis_session_id = -1
    # try:
    if request.method == 'POST':
        current_user = request.user
        filename = str(request.POST.get('filename', ''))
        u_data_list = json.loads(request.POST.get('data[]',''))
        u_key_list = json.loads(request.POST.get('headers[]',''))
        type_file = request.POST.get('type_file','')
        uuid = request.POST.get('uuid','')
        analysis_session = AnalysisSession.objects.create(filename, u_key_list, u_data_list,current_user,
                                                          type_file,uuid)

        if not analysis_session :
            # messages.error(request, 'Analysis Session wasn\'t created .')
            return HttpResponseServerError("Error saving the data")
        else:
            # messages.success(request, 'Analysis Session was created .')
            analysis_session_id = analysis_session.id
            call_after_save_event(analysis_session)
            return JsonResponse(dict(data={'analysis_session_id': analysis_session_id,
                                           'filename': analysis_session.name,
                                           'data_length': analysis_session.weblog_set.count()
                                           },
                                     msg='Analysis Session was created .'))

    else:
        messages.error(request, 'Only POST request')
        return HttpResponseServerError("Only POST request")
    # except Exception as e:
    #     messages.error(request, 'Error Happened')
    #     data = {'dd': 'something', 'safe': True}
    #     # return JsonResponse({"nothing to see": "this isn't happening"})
    #     return render_to_json(request, data)


# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def make_virus_total_consult(request):
    try:
        if request.method == 'GET':
            current_user = request.user
            qn = str(request.GET.get('query_node', ''))
            query_type, query_node = get_data_from_url(qn)
            # query_type = str(request.GET.get('query_type', ''))
            if not current_user.is_authenticated():
                current_user = User.objects.get(username='anonymous_user_for_metrics')
            vtc_query_set = VTConsult.get_query_info(query_node, current_user,query_type)

            return JsonResponse(dict(query_node=query_node,
                                     info_report=vtc_query_set.info_report,
                                     msg='VT Consult Done'))
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def make_whois_consult(request):
    try:
        if request.method == 'GET':
            current_user = request.user
            if not current_user.is_authenticated():
                current_user = User.objects.get(username='anonymous_user_for_metrics')
            qn = str(request.GET.get('query_node', ''))
            # query_type = str(request.GET.get('query_type', ''))
            query_type, query_node = get_data_from_url(qn)
            if query_type == "ip":
                wc_query_set = WhoisConsult.get_query_info_by_ip(query_node, current_user)
            else:
                wc_query_set = WhoisConsult.get_query_info_by_domain(query_node, current_user)

            return JsonResponse(dict(query_node=query_node,
                                     info_report=wc_query_set.info_report,
                                     msg='Whois Consult Done'))
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def export_metrics(request):
    try:
        if request.method == 'GET':
            metrics = Metric.objects.all()
            data = serializers.serialize('json', metrics)
            response = HttpResponse(data, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename=metrics.json'
            return response
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def get_weblog_history(request):
    try:
        if request.method == 'GET':
            # current_user = request.user
            weblog_id = str(request.GET.get('weblog_id', ''))
            webh_query_set = WeblogHistory.objects.filter(weblog_id=weblog_id).order_by('-created_at')
            # webh_json = serializers.serialize("json", webh_query_set)
            webh_json = serialize(webh_query_set,
                                  fields=['id', 'weblog_id','version','created_at','verdict', 'old_verdict','author_name'],
                                  exclude=['weblog'],
                                  aliases={'author_name': 'get_author_name', 'created_at':'created_at_txt'})
            return JsonResponse(dict(data=json.dumps(webh_json), msg='WeblogHistory Consulst DONE'))
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def label_weblogs_whois_related(request):
    if request.method == 'POST':
        current_user = request.user
        weblog_id = str(request.POST.get('weblog_id', ''))
        weblog = Weblog.objects.get(id=weblog_id)
        verdict = str(request.POST.get('verdict', ''))
        ModulesManager.bulk_labeling_by_whois_relation(current_user.username,
                                                       weblog.analysis_session_id,
                                                       weblog.domain,
                                                       verdict)
        return JsonResponse(dict(msg='All the weblogs related with ' + weblog.domain + " will be label like " + verdict))
    else:
        return HttpResponseServerError("Only POST request")


# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def find_domains_whois_related(request): # BY DOMAIN
    # try:
    if request.method == 'GET':
        # current_user = request.user
        weblog_id = str(request.GET.get('weblog_id', ''))
        weblog = Weblog.objects.get(id=weblog_id)
        domain_ioc = weblog.domain_ioc
        domain = domain_ioc.value
        analysis_session_id = weblog.analysis_session_id
        if not domain_ioc:
            return HttpResponseServerError("The selected weblogs, does not have domain in the given URL or host")
        else:
            ModulesManager.check_to_WHOIS_relate_domain(analysis_session_id, domain)
            whois_related_domains = domain_ioc.get_all_values_related_by(analysis_session_id)
            return JsonResponse(dict(whois_related_domains=whois_related_domains,domain_primary=domain,
                                 msg='Starting Module to process the relationship between domains...'))
    else:
        return HttpResponseServerError("Only GET request")

@csrf_exempt
def find_whois_distance_similarity_details(request):  # Between 2 domains
    # try:
    if request.method == 'GET':
        current_user = request.user
        if not current_user.is_authenticated():
            current_user = User.objects.get(username='anonymous_user_for_metrics')
        domain_a = str(request.GET.get('domain_a', ''))
        domain_b = str(request.GET.get('domain_b', ''))
        related, distance_numeric, dist_feature_detail = share_modules.whois_distance.distance_related_by_whois_obj(current_user, domain_a, domain_b)
        if not dist_feature_detail:
            return HttpResponseServerError("There is an error processing in the WSD algorithm")
        else:
            return JsonResponse(dict(related=related,
                                     distance_numeric=distance_numeric,
                                     distance_feature=dist_feature_detail,
                                     msg='WHOIS Similarity Distance details were obtained successfully'))
    else:
        return HttpResponseServerError("Only GET request")



@csrf_exempt
def refreshing_domains_whois_related(request):
    if request.method == 'GET':
        current_user = request.user
        if not current_user.is_authenticated():
            current_user = User.objects.get(username='anonymous_user_for_metrics')
        weblog_id = str(request.GET.get('weblog_id', ''))
        weblog = Weblog.objects.get(id=weblog_id)
        domain_ioc = weblog.domain_ioc
        whois_related_domains = {}
        root_whois_features = {}
        if not domain_ioc:
            msg = 'It does not have a IOC domain assigned'
        else:
            msg = 'Refreshing WHOIS related domains'
            wris = domain_ioc.whois_related_iocs.filter(ioc_type=domain_ioc.ioc_type,
                                                  weblogs__analysis_session_id=weblog.analysis_session_id).distinct()
            wri_ids = [wri.id for wri in wris]

            wris = WHOISRelatedIOC.objects.filter((Q(from_ioc=domain_ioc) & Q(to_ioc__in=wri_ids)) |
                                                  (Q(to_ioc=domain_ioc) & Q(from_ioc__in=wri_ids))).distinct()
            for wri in wris:
                if wri.from_ioc.id == domain_ioc.id:
                    value = wri.to_ioc.value
                elif wri.to_ioc.id == domain_ioc.id:
                    value = wri.from_ioc.value
                else:
                    value = "null"

                whois_features = WhoisConsult.get_whois_distance_features_by_domain(current_user, value)
                whois_related_domains[value] = [whois_features, wri.features_description]

            root_whois_features = WhoisConsult.get_whois_distance_features_by_domain(current_user, domain_ioc.value)

        return JsonResponse(dict(whois_related_domains=whois_related_domains,
                                 root_whois_features=root_whois_features,
                                 msg=msg,
                                 was_related=IOC_WHOIS_RelatedExecuted.finished(weblog.analysis_session_id,
                                                                                domain_ioc.value)))

    else:
        return HttpResponseServerError("Only GET request")



# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def get_modules_changes(request):
    try:
        if request.method == 'GET':
            # current_user = request.user
            weblog_id = str(request.GET.get('weblog_id', ''))
            weblog = Weblog.objects.filter(id=weblog_id).first()
            return JsonResponse(dict(data=json.dumps(weblog.mod_attributes), msg='Modules Changes History Consulst DONE'))
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data

# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def sync_db(request):
    # try:
    if request.method == 'POST':
        user = request.user
        received_json_data = json.loads(request.body)
        analysis_session_id = received_json_data['analysis_session_id']
        data = {}
        if user.is_authenticated():
            if "headers[]" in received_json_data:
                headers = json.loads(received_json_data['headers[]'])
                analysis_session = AnalysisSession.objects.get(id=analysis_session_id)
                analysis_session.set_columns_order_by(request.user, headers)
                print("Headers Updated")
            data = convert(received_json_data['data'])

        wb_query_set = AnalysisSession.objects.sync_weblogs(analysis_session_id, data,user)
        json_query_set = serializers.serialize("json", wb_query_set)
        call_after_sync_event()
        return JsonResponse(dict(data=json_query_set, msg='Sync DONE'))
    else:
        messages.error(request, 'Only POST request')
        return HttpResponseServerError("Only POST request")
    # except Exception as e:
    #     raise e
        # error = print_exception()
        # logger.error(str(error))
        # logger.error(str(e.message))
        #return HttpResponseServerError("ERROR in the server: " + str(e.message) + "\n:" + error)


@login_required(login_url=REDIRECT_TO_LOGIN)
@permission_required_or_403('delete_analysissession', (AnalysisSession, 'pk','id'),template_name="403.html")
@csrf_exempt
def delete_analysis_session(request, id):
    analysis_session = get_object_or_404(AnalysisSession, pk=id)
    analysis_session.status = analysis_session.STATUS.removed
    analysis_session.save()
    delete_analysis_session_aux.delay(id)
    messages.info(request, 'Deleting analysis session: ' + id)
    return redirect("/manati_project/manati_ui/analysis_sessions")


@job('low')
def delete_analysis_session_aux(id):
    AnalysisSession.objects.get(id=id).delete()

# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def sync_metrics(request):
    try:
        if request.method == 'POST':
            current_user = request.user
            if not current_user.is_authenticated():
                current_user = User.objects.get(username='anonymous_user_for_metrics')
            u_measurements = json.loads(request.POST.get('measurements[]', ''))
            u_keys = json.loads(request.POST.get('keys[]', ''))
            Metric.objects.create_bulk_by_user(u_measurements, current_user)
            json_data = json.dumps({'msg': 'Sync Metrics DONE',
                                    'measurements_length': len(u_measurements), 'keys': u_keys})
            return HttpResponse(json_data, content_type="application/json")
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def publish_analysis_session(request, id):
    try:
        if request.method == 'POST':
            analysis_session = AnalysisSession.objects.get(id=id)
            publish_data = request.POST.get('publish', '')
            if publish_data == "True":
                analysis_session.public = True
                msg = "the Analysis Session " + analysis_session.name + " was posted"
            elif publish_data == "False":
                analysis_session.public = False
                msg = "the Analysis Session " + analysis_session.name + " is no public "
            else:
                raise ValueError("Incorrect Value")
            analysis_session.save()

            return JsonResponse(dict(msg=msg))

        else:
            messages.error(request, 'Only POST request')
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def change_status_analysis_session(request, id):
    try:
        if request.method == 'POST':
            current_user = request.user
            analysis_session = AnalysisSession.objects.get(id=id)
            status = request.POST.get('status', '')
            old_status = analysis_session.status
            if status == AnalysisSession.STATUS.closed:
                msg = "the Analysis Session " + analysis_session.name + " was closed"
                Metric.objects.close_analysis_session(current_user, analysis_session)
            elif status == AnalysisSession.STATUS.open:
                msg = "the Analysis Session " + analysis_session.name + " was opened "
                Metric.objects.open_analysis_session(current_user, analysis_session)
            else:
                raise ValueError("Incorrect Value")
            analysis_session.status = status
            analysis_session.save()
            return JsonResponse(dict(msg=msg,
                                     new_status=analysis_session.status,
                                     old_status=old_status))

        else:
            messages.error(request, 'Only POST request')
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def update_uuid_analysis_session(request, id):
    try:
        if request.method == 'POST':
            current_user = request.user
            analysis_session = AnalysisSession.objects.prefetch_related('weblog_set').get(id=id)
            uuid = request.POST.get('uuid', '')
            weblogs_ids = json.loads(request.POST.get('weblogs_ids[]', ''))
            weblogs_uuids = json.loads(request.POST.get('weblogs_uuids[]', ''))
            if uuid:
                AnalysisSession.objects.update_uuid(analysis_session, uuid, weblogs_ids, weblogs_uuids)
                msg = "the Analysis Session " + analysis_session.name + " UUID updated"
            else:
                msg = "the Analysis Session " + analysis_session.name + " UUID not updated"
            return JsonResponse(dict(msg=msg,
                                     analysis_session_id=analysis_session.id))

        else:
            messages.error(request, 'Only POST request')
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

# @login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def get_weblogs(request):
    try:
        if request.method == 'GET':
            user = request.user
            analysis_session_id = request.GET.get('analysis_session_id', '')
            analysis_session = AnalysisSession.objects.prefetch_related('weblog_set').get(id=analysis_session_id)
            headers = convert(analysis_session.get_columns_order_by(user))
            weblogs_qs = analysis_session.weblog_set.all()
            weblogs_json = WeblogSerializer(weblogs_qs, many=True).data
            return JsonResponse(dict(weblogs=weblogs_json,
                                     analysissessionid=analysis_session_id,
                                     analysissessionuuid=analysis_session.uuid,
                                     name=analysis_session.name,
                                     headers=json.dumps(headers)))

        else:
            messages.error(request, 'Only GET request')
            return HttpResponseServerError("Only GET request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


class IndexAnalysisSession(generic.ListView):
    login_url = REDIRECT_TO_LOGIN
    redirect_field_name = 'redirect_to'
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/index.html'
    context_object_name = 'analysis_sessions'

    def get_queryset(self):
        # Get the analysis session created by the admin (old website) and the current user or analysis session public
        user = self.request.user
        return AnalysisSession.objects.filter(Q(users__in=[user.id]) | Q(public=True))


class IndexExternalModules(generic.ListView):
    login_url = REDIRECT_TO_LOGIN
    redirect_field_name = 'redirect_to'
    model = ExternalModule
    template_name = 'manati_ui/modules/index.html'
    context_object_name = 'external_modules'

    def get_queryset(self):
        return ExternalModule.objects.exclude(status=ExternalModule.MODULES_STATUS.removed)

from django.views.generic.detail import SingleObjectTemplateResponseMixin

class IndexHotkeys(generic.ListView, SingleObjectTemplateResponseMixin,):
    login_url = REDIRECT_TO_LOGIN
    redirect_field_name = 'redirect_to'
    template_name = 'manati_ui/analysis_session/hotkeys_list.html'
    context_object_name = 'hotkeys'

    def render_to_response(self, context):
        # Look for a 'format=json' GET argument
        if self.request.is_ajax():
            return JsonResponse(dict(hotkeys=context['hotkeys']))
        else:
            return super(IndexHotkeys, self).render_to_response(context)

    def get_context_data(self, **kwargs):
        # Call the base implementation first to get a context
        context = super(IndexHotkeys, self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        hotkeys = [
            dict(description='Sync up ', command='cmd+s | ctrl+s'),
            dict(description='Label selected weblog like Malicious', command='cmd+m | ctrl+m'),
            dict(description='Label selected weblog like Legitimate', command='cmd+l | ctrl+l'),
            dict(description='Label selected weblog like False Positive', command='cmd+p | ctrl+p'),
            dict(description='Label selected weblog like Suspicious', command='cmd+i | ctrl+i'),
            dict(description='Label selected weblog like Undefined', command='cmd+u | ctrl+u'),
            dict(description='Filter table by Malicious weblog', command='cmd+1 | ctrl+1'),
            dict(description='Filter table by Legitimate weblog', command='cmd+2 | ctrl+2'),
            dict(description='Filter table by Suspicious weblog', command='cmd+3 | ctrl+3'),
            dict(description='Filter table by False Positive weblog', command='cmd+4 | ctrl+4'),
            dict(description='Filter table by Undefined weblog', command='cmd+5 | ctrl+5'),
            dict(description='Open VirusTotal Pop-up by DOMAIN', command='cmd+shift+v | ctrl+shift+v'),
            dict(description='Open VirusTotal Pop-up by IP', command='cmd+shift+i | ctrl+shift+i'),
            dict(description='Open WHOIS Pop-up by DOMAIN', command='cmd+shift+p | ctrl+shift+p'),
            dict(description='Open WHOIS Pop-up by IP', command='cmd+shift+o | ctrl+shift+o'),
            dict(description='Open WHOIS related domains Pop-up', command='command+shift+d | ctrl+shift+d'),
            dict(description='Moving down in the table (VI-Style)', command='j'),
            dict(description='Moving up in the table (VI-Style)', command='k'),
            dict(description='Mark a row to be labeled', command='space'),
            dict(description='Move to the previous page in the table', command='left'),
            dict(description='Move to the next page in the table', command='right'),
            dict(description='Mark with the verdict of the selected row, all the ' +
                             'weblogs with the same IP, in the current session ', command='p'),
            dict(description='Mark with the verdict of the selected row, all the ' +
                             'weblogs with the same domain, in the current session ', command='d'),
        ]
        return hotkeys


class EditAnalysisSession(generic.DetailView):
    login_url = REDIRECT_TO_LOGIN
    redirect_field_name = 'redirect_to'
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/edit.html'

    def get_context_data(self, **kwargs):
        context = super(EditAnalysisSession, self).get_context_data(**kwargs)
        object = super(EditAnalysisSession, self).get_object()
        context['analysis_session_id'] = object.id
        context['comment'] = object.comments.last() if object.comments.exists() else Comment()
        return context


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def profile_view(request):
    user = request.user
    form = UserProfileForm(initial={'first_name': user.first_name,
                                    'last_name': user.last_name,
                                    'email': user.email,
                                    'username': user.username})
    context = {"form": form}
    return render(request, 'manati_ui/user/edit.html', context)

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def update_comment_analysis_session(request, id):
    try:
        if request.method == 'POST':
            user = request.user
            analysis_session = AnalysisSession.objects.get(id=id)
            comment = analysis_session.comments.last() if analysis_session.comments.exists() else Comment(user=user,
                                                                                        content_object=analysis_session)
            comment.text = request.POST['text']
            comment.full_clean()
            comment.save()
            json_data = json.dumps({'msg':"The comment was save correcly"})
            return HttpResponse(json_data, content_type="application/json")

        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")



@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def update_comment_weblog(request):
    try:
        if request.method == 'POST':
            user = request.user
            weblog_id = request.POST.get('weblog_id', '')
            weblog = Weblog.objects.get(id=weblog_id)
            comment = weblog.comments.last() if weblog.comments.exists() else Comment(user=user,content_object=weblog)
            text = request.POST.get('text', None)
            if text:
                comment.text = text
                comment.full_clean()
                comment.save()
                msg = "The comment was save correctly"
            else:
                msg = "Empty comment was not saved"
            return JsonResponse({'msg': msg})

        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def get_comment_weblog(request):
    try:
        if request.method == 'GET':
            user = request.user
            weblog_id = request.GET.get('weblog_id', '')
            weblog = Weblog.objects.get(id=weblog_id)
            if weblog.comments.exists():
                comment = weblog.comments.last()
                text = comment.text
            else:
                text = ""
            return JsonResponse({'text': text})

        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def get_weblog_iocs(request):
    # try:
    if request.method == 'GET':
        weblog_id = request.GET.get('weblog_id', '')
        iocs = Weblog.objects.prefetch_related('ioc_set').get(id=weblog_id).ioc_set.all()
        iocs_list = [{'value': ioc.value, 'ioc_type': ioc.ioc_type} for ioc in iocs]
        return JsonResponse(dict(iocs=iocs_list))
    # except Exception as e:
    #     print_exception()
    #     return HttpResponseServerError("There was a error in the Server")

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def profile_update(request):
    try:
        if request.method == 'POST':
            user = request.user
            form = UserProfileForm(request.POST or None)
            if form.is_valid():
                user.first_name = request.POST['first_name']
                user.last_name = request.POST['last_name']
                user.username = request.POST['username']
                user.email = request.POST['email']
                user.save()
            context = {
                "form": form
            }
            return HttpResponseRedirect(redirect_to='/')
        else:
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")




