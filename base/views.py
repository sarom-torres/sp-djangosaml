from django.shortcuts import render, redirect, reverse
from django.contrib.auth.decorators import login_required
from django.contrib import auth
from django.http import HttpResponse
from django.template import loader

# Create your views here.
def index(request):
    return render(request, 'base/index.html')

@login_required
def users(request):
    template = loader.get_template('base/users.html')
    meta = request.META
    #print(meta['shib'])
    return HttpResponse(template.render(meta, request))
    #data = {'user':request.user}
    #return render(request, 'base/users.html', data)
    #else:
    #    return redirect(reverse('base:index'))
