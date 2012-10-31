from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from admins.loginforms import LoginForm
from admins.views.login import CheckLogin
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from lib.tools import init_random_pass
from lib.tools import ajaxterm_daemon
import re


def login_page(request):
    if request.user.is_authenticated():
        return HttpResponseRedirect('/admins/')
    failed_login = False
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            USERNAME = form.cleaned_data['username']
            PASSWORD = form.cleaned_data['password']
            user = authenticate(username=USERNAME,password=PASSWORD)
            if user is not None:
                login(request,user)
                init_random_pass(request)
                Next = re.search(r"=/(.+)/", request.get_full_path())
                if Next:
                    Next = Next.group(1)
                else:
                    Next = "admins"
                return HttpResponseRedirect("/%s" % Next)
            else:
                failed_login = True
    else:
        form = LoginForm()
    return render_to_response('index.html',{'form':form,'failed_login':failed_login})

def logout_page(request):
    ajaxterm = ajaxterm_daemon(request=request)
    ajaxterm.stop_daemon()
    logout(request)
    #return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
    return HttpResponse("<script>window.top.location.href='/'</script>")
    
