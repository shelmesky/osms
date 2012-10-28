# Create your views here.
# coding: utf-8

from django.contrib.auth.decorators import login_required
from lib.tools import render


@login_required()
def index(request):
    return render('admin_index.html',{},request)


@login_required()
def right(request):
    return render('admin_right.html',{},request)
    

@login_required()
def left(request):
    return render('admin_left.html',{},request)
