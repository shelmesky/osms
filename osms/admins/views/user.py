from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

@login_required()
def useradd(request):
    #user = User.objects.create_user(username,email,password)
    #user.is_staff = True
    #user.save()
    return HttpResponse('useradd')

@login_required()
def usermgm(request):
    return HttpResponse('usermgm')

@login_required()
def userdel(request):
    return HttpResponse('userdel')

@login_required()
def change_password(request):
    return HttpResponse('change_password')
