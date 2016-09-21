from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse, JsonResponse, HttpResponseServerError
from django.core.urlresolvers import reverse
from django.views import generic
from django.utils import timezone
from .models import AnalysisSession, Weblog
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from helpers import *
import json, collections
from django.core import serializers
from django.contrib.auth.mixins import LoginRequiredMixin
from utils import *


class IndexView(generic.ListView):
    template_name = 'manati_ui/index.html'
    context_object_name = 'latest_question_list'

    def get_queryset(self):
		"""
		Return the last five published questions (not including those set to be
		published in the future).
		"""
		return ''

class AnalysisSessionNewView(generic.DetailView):
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/new.html'

@login_required(login_url="/")
def new_analysis_session_view(request):
    # lastest_question_list = Question.objects.order_by('-pub_date')[:5]
    # output = ', '.join([q.question_text for q in lastest_question_list])
    context = {"weblogs_attribute": Weblog.get_model_fields()}
    return render(request, 'manati_ui/analysis_session/new.html', context)

#ajax connexions
@login_required(login_url="/")
@csrf_exempt
def create_analysis_session(request):
    analysis_session_id = -1
    # try:
    if request.method == 'POST':
        filename = str(request.POST.get('filename', ''))
        analysis_session = AnalysisSession.objects.create(filename)
        if not analysis_session :
            messages.error(request, 'Analysis Session wasn\'t created .')
            return HttpResponseServerError("Error saving the data")
        else:
            messages.success(request, 'Analysis Session was created .')
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

#ajax connexions
@login_required(login_url="/")
@csrf_exempt
def add_weblogs(request):
    if request.method == 'POST':
        # json_data = json.loads(request.body)
        # data = json_data['data']
        u_data_list = json.loads(request.POST.get('data[]',''))
        # data_list = [str(x).split(',') for x in u_data_list]
        analysis_session_id = request.POST.get('analysis_session_id', '')
        data = AnalysisSession.objects.add_weblogs(analysis_session_id, u_data_list)
        if isinstance(data, Exception):
            messages.error(request, data.message)
            return HttpResponseServerError(data.message)
        else:
            json_data = []
            for elem in data:
                json_data.append({'id': elem.id, 'register_status': elem.register_status, 'dt_id': elem.dt_id })
            return JsonResponse(dict(data=json_data, msg='All WBs were created'))

    else:
        messages.error(request, 'Only POST request')
        return HttpResponseServerError("Error with the data")


def update_analysis_session(request):
    return JsonResponse({'foo': 'bar'})

def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data

@login_required(login_url="/")
@csrf_exempt
def sync_db(request):
    try:
        if request.method == 'POST':
            received_json_data = json.loads(request.body)
            analysis_session_id = received_json_data['analysis_session_id']
            data = convert(received_json_data['data'])

            wb_query_set = AnalysisSession.objects.sync_weblogs(analysis_session_id, data)
            return JsonResponse(dict(data=serializers.serialize("json", wb_query_set), msg='Sync DONE'))
        else:
            messages.error(request, 'Only POST request')
            return HttpResponseServerError("Only POST request")
    except Exception as e:
        print_exception()
        return HttpResponseServerError("There was a error in the Server")


class IndexAnalysisSession(LoginRequiredMixin,generic.ListView):
    login_url = '/'
    redirect_field_name = 'redirect_to'
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/index.html'
    context_object_name = 'analysis_sessions'


class EditAnalysisSession(LoginRequiredMixin, generic.DetailView):
    login_url = '/'
    redirect_field_name = 'redirect_to'
    model = AnalysisSession
    template_name = 'manati_ui/analysis_session/edit.html'

    def get_context_data(self, **kwargs):
        # Call the base implementation first to get a context
        context = super(EditAnalysisSession, self).get_context_data(**kwargs)
        object = super(EditAnalysisSession, self).get_object()
        # Add in a QuerySet of all the books
        context['weblogs_attribute'] = Weblog.get_model_fields()
        context['weblogs'] = serializers.serialize("json",object.weblog_set.all())
        context['analysis_session_id'] = object.id
        return context



