from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.views import generic
from django.utils import timezone
from .models import AnalysisSession

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



# Create your views here.
