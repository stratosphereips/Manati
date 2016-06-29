#!python
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from manati_ui.models import Weblog

# Create your views here.
# this login required decorator is to not allow to any  
# view without authenticating
@login_required(login_url="login/")
def home(request):
    # return render(request,"home.html")
    context = {"weblogs_attribute": Weblog.get_model_fields()}
    return render(request, 'manati_ui/analysis_session/new.html', context)
