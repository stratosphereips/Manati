from django.shortcuts import render
from django.shortcuts import get_object_or_404, render
from django.http import Http404, HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.views import generic
from django.utils import timezone

class IndexView(generic.ListView):
    template_name = 'manati_ui/index.html'
    context_object_name = 'latest_question_list'

    def get_queryset(self):
		"""
		Return the last five published questions (not including those set to be
		published in the future).
		"""
		return ''

# Create your views here.
