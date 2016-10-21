#!python
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect

# Create your views here.
# this login required decorator is to not allow to any  
# view without authenticating
@login_required(login_url="/manati_project/login/")
def home(request):
    redirect = request.GET.get('redirect_to','')
    if redirect == '':
        return HttpResponseRedirect(reverse('manati_ui:new_analysis_session'))
    else:
        return HttpResponseRedirect(str(redirect))
