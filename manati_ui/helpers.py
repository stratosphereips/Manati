from django.http import Http404, HttpResponseRedirect, HttpResponse, JsonResponse
from django.template.loader import render_to_string, get_template
from django.template import Context, Template
from django.contrib import messages

# `data` is a python dictionary
def render_to_json(request, data):
    # return HttpResponse(
    #     json.dumps(data, ensure_ascii=False),
    #     mimetype=request.is_ajax() and "application/json" or "text/html"
    # )
    temp = get_template('messages.html')
    c = {"stooges": ["Larry", "Curly", "Moe"]}
    msg = render_to_string('manati_ui/messages.html', {messages: messages})
    # msg = temp.render(c)
    return JsonResponse(dict(data=data, msg=msg ))

