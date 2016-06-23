from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse, JsonResponse
from django.core.urlresolvers import reverse
from django.views import generic
from django.utils import timezone
from .models import AnalysisSession
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from helpers import *

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
    context = {}
    return render(request, 'manati_ui/analysis_session/new.html', context)

@login_required(login_url="/")
@csrf_exempt
def create_analysis_session(request):
    analysis_session_id = -1
    # try:
    if request.method == 'POST':
        data = request.POST.getlist('data[]')
        print(data)
        keys = request.POST.get('keys', '')
        filename = request.POST.get('filename', '')
        analysis_session = AnalysisSession.objects.create_from_request(keys, data, filename)
        if analysis_session is AnalysisSession:
            messages.success(request, 'Analysis Session was created .')
            analysis_session_id = analysis_session.id
        else:
            messages.error(request, 'Analysis Session wasn\'t created .')
    else:
        messages.error(request, 'Only POST request')

    return HttpResponseRedirect('/manati_ui/analysis_session/new')
    # except Exception as e:
    #     messages.error(request, 'Error Happened')
    #     data = {'dd': 'something', 'safe': True}
    #     # return JsonResponse({"nothing to see": "this isn't happening"})
    #     return render_to_json(request, data)




# Create your views here.
