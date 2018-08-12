from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import logging
# Get an instance of a logger
logger = logging.getLogger(__name__)
REDIRECT_TO_LOGIN = "/manati_project/login"

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def index(request):
    context = {}
    return render(request, 'ip_profiles/index.html', context)

@login_required(login_url=REDIRECT_TO_LOGIN)
@csrf_exempt
def new(request):
    context = {}
    return render(request, 'ip_profiles/new.html', context)


