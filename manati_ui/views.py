from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseServerError
from django.core.urlresolvers import reverse
from django.views import generic
from .models import *
from manati_ui.forms import UserProfileForm
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from helpers import *
import json, collections
from django.core import serializers
from django.contrib.auth.mixins import LoginRequiredMixin
from utils import *
from api_manager.core.modules_manager import ModulesManager
from django.core import management
import threading
from manati import settings
import os

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


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def new_analysis_session_view(request):
    # ModulesManager.load_modules()
    context = {}
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
        analysis_session = AnalysisSession.objects.create(filename, u_key_list, u_data_list,current_user)

        if not analysis_session :
            # messages.error(request, 'Analysis Session wasn\'t created .')
            return HttpResponseServerError("Error saving the data")
        else:
            # messages.success(request, 'Analysis Session was created .')
            analysis_session_id = analysis_session.id
            return JsonResponse(dict(data={'analysis_session_id': analysis_session_id}, msg='Analysis Session was created .' ))

    else:
        messages.error(request, 'Only POST request')
        return HttpResponseServerError("Only POST request")
    # except Exception as e:
    #     messages.error(request, 'Error Happened')
    #     data = {'dd': 'something', 'safe': True}
    #     # return JsonResponse({"nothing to see": "this isn't happening"})
    #     return render_to_json(request, data)


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def make_virus_total_consult(request):
    # script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # p = Popen(["/Users/raulbeniteznetto/proyectos/master_tesis/project_manati/venv/bin/python", script_dir+"/modules_extra/vt-checker-hosts.py", "-ff", "216.176.200.22", "--nocsv", "--nocache"], cwd=script_dir, stdout=PIPE, stderr=PIPE)
    # out, err = p.communicate()
    # print(out)"
    # print(err)
    try:
        if request.method == 'GET':
            current_user = request.user
            query_node = str(request.GET.get('query_node', ''))
            vtc_query_set = VTConsult.get_query_info(query_node, current_user)
            return JsonResponse(dict(query_node=query_node, info_report=vtc_query_set.info_report, msg='VT Consult Done' ))
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


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def get_weblog_history(request):
    try:
        if request.method == 'GET':
            # current_user = request.user
            weblog_id = str(request.GET.get('weblog_id', ''))
            webh_query_set = WeblogHistory.objects.filter(weblog_id=weblog_id).order_by('-created_at')
            return JsonResponse(dict(data=serializers.serialize("json", webh_query_set), msg='WeblogHistory Consulst DONE'))
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


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def sync_db(request):
    try:
        if request.method == 'POST':
            received_json_data = json.loads(request.body)
            analysis_session_id = received_json_data['analysis_session_id']
            if "headers[]" in received_json_data:
                headers = json.loads(received_json_data['headers[]'])
                analysis_session = AnalysisSession.objects.get(id=analysis_session_id)
                analysis_session.set_columns_order_by(request.user, headers)
                print("Headers Updated")
            data = convert(received_json_data['data'])

            wb_query_set = AnalysisSession.objects.sync_weblogs(analysis_session_id, data)
            json_query_set = serializers.serialize("json", wb_query_set)
            if wb_query_set:
                ModulesManager.attach_event_after_update_verdict(json_query_set)
            return JsonResponse(dict(data=json_query_set, msg='Sync DONE'))
        else:
            messages.error(request, 'Only POST request')
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def delete_analysis_session(request, id):
    AnalysisSession.objects.filter(id=id).delete()
    return HttpResponseRedirect("/manati_ui/analysis_sessions")


@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def sync_metrics(request):
    try:
        if request.method == 'POST':
            current_user = request.user
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
def get_weblogs(request):
    try:
        if request.method == 'GET':
            user = request.user
            analysis_session_id = request.GET.get('analysis_session_id', '')
            analysis_session = AnalysisSession.objects.get(id=analysis_session_id)
            headers = convert(analysis_session.get_columns_order_by(user))
            return JsonResponse(dict(weblogs=serializers.serialize("json", analysis_session.weblog_set.all()),
                                     analysissessionid=analysis_session_id,
                                     name=analysis_session.name,
                                     headers=json.dumps(headers)))

        else:
            messages.error(request, 'Only GET request')
            return HttpResponseServerError("Only GET request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


class IndexAnalysisSession(LoginRequiredMixin,generic.ListView):
    login_url = REDIRECT_TO_LOGIN
    redirect_field_name = 'redirect_to'
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/index.html'
    context_object_name = 'analysis_sessions'

    def get_queryset(self):
        #Get the analysis session created by the admin (old website) and the current user
        user = self.request.user
        return AnalysisSession.objects.filter(users__in=[1, user.id])


class EditAnalysisSession(LoginRequiredMixin, generic.DetailView):
    login_url = REDIRECT_TO_LOGIN
    redirect_field_name = 'redirect_to'
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/edit.html'

    def get_context_data(self, **kwargs):
        context = super(EditAnalysisSession, self).get_context_data(**kwargs)
        object = super(EditAnalysisSession, self).get_object()
        path_log_file = os.path.join(settings.BASE_DIR, 'logs')
        logfile_name = os.path.join(path_log_file, "background_tasks.log")
        thread = threading.Thread(target=management.call_command, args=('process_tasks',
                                                                        "--sleep", "60",
                                                                        "--log-level", "DEBUG",
                                                                        "--log-std", logfile_name))
        # thread.daemon = True  # Daemonize thread
        thread.start()

        context['analysis_session_id'] = object.id
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




