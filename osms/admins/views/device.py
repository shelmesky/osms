# coding: utf-8

from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from lib.tools import render, get_device_info
from lib.tools import sshclient
from lib.tools import check_if_online
from admins.models import Device, SSH
from django.db.models import Q
import os
from settings import BASEROOT


@login_required()
def device_view(request):
	devices = Device.objects.all()
	hosts = devices.values()
	for host in hosts:
		host['online'] = check_if_online(host['Ip'])
	return render('device_view.html',{'devices':hosts,'show_list_all':True},request)


@login_required()
def device_search(request):
	if request.method == "POST":
		keyword = request.REQUEST.get('keyword')
		devices = Device.objects.filter(Q(Ip__icontains=keyword) | Q(Cpu__icontains=keyword) | Q(Mem__icontains=keyword)
									| Q(Disk__icontains=keyword)| Q(Nic__icontains=keyword)| Q(Vga__icontains=keyword)
									| Q(Arch__icontains=keyword)| Q(Kernel__icontains=keyword)| Q(Position__icontains=keyword)
									| Q(State__icontains=keyword)| Q(Server__icontains=keyword)| Q(Owner__icontains=keyword)
									| Q(Os__icontains=keyword))
		if devices:
			return render('device_search.html',{'devices':devices,'show_search_all':True},request)
		else:
			return render('device_search.html',{'ERROR':True},request)
	return render('device_search.html',{'show_search_form':True},request)


@login_required()
def device_add(request):
	if request.method == "POST" and request.REQUEST.get('Type') == "AUTO_INPLEMENT":
		IP = request.REQUEST.get('ip')
		USERNAME = request.REQUEST.get('user')
		PASSWORD = request.REQUEST.get('pass')
		try:
			ssh = sshclient(IP,USERNAME,PASSWORD)
			server_tarfile = os.path.abspath(BASEROOT+'/cs/Server.tar')
			command = "mkdir -p /opt"
			ssh.exec_command(command)
			ssh.putfile(server_tarfile,'/opt/Server.tar')
			ret = ssh.exec_command("cd /opt; rm -rf Server/; tar -xvf Server.tar; /opt/Server/threading_server.py")
		except:
			return HttpResponse('ERROR')
		else:
			check_ip = SSH.objects.filter(Ip=IP)
			if not check_ip:
				p = SSH(Ip=IP,Username=USERNAME,Password=PASSWORD)
				p.save()
			return HttpResponse('OK')
	
	if request.method == "POST" and request.REQUEST.get('Type') == "ADD_IP":
		INFO = {}
		IP = request.REQUEST.get('IP')
		#check_ip = Device.objects.filter(Ip__icontains=IP)
		check_ip = Device.objects.filter(Ip=IP)
		if check_ip:
			return render('device_add.html',{'show_exists':True},request)
			
		Tuple = ('CPU','MEM','DISK','NIC','VGA','SYSINFO','PARTITION','VIRTUED')
		device = get_device_info(IP)
		for i in Tuple:
				device = get_device_info(IP)
				INFO[i] = device.do_exec(i)
				if 'Error' in INFO[i]:
					break
		try:
			sysinfo = INFO['SYSINFO']
			#if '\r\n' not in sysinfo:
			os1,os2,arch,kernel = sysinfo.split('\r\n')
		except:
			return render('device_add.html',{'ERROR_CONNECT':True,'IP':IP},request)
		OS=os1+' '+os2
		INFO['OS'] = OS
		INFO['ARCH'] = arch
		INFO['KERNEL'] = kernel
		INFO['IP'] = IP
		if INFO['VIRTUED'].strip() == '1':
			INFO['VIRTUED'] = '是'
		else:
			INFO['VIRTUED'] = '否'
		cpus = len(INFO['CPU'].split('\n'))
		INFO['CPU'] = INFO['CPU'].split('\n')[0] + '   ' + str(cpus) + ' cores'
		return render('device_add.html',{'DBDA':INFO,'show_device_form':True},request)	
		
	if request.method == "POST" and request.REQUEST.get('Type') == "ADD_ALL":
		INFO={}
		Tuple = ('IP','CPU','MEM','DISK','VIRTUED','NIC','VGA','OS','ARCH','KERNEL','POSITION','STATE','SERVER','OWNER')
		for i in Tuple:
			INFO[i] = request.REQUEST.get(i)
		DBDA = Device(Ip=INFO['IP'],Cpu=INFO['CPU'],Mem=INFO['MEM'],Disk=INFO['DISK'],
			Virtued=INFO['VIRTUED'],Nic=INFO['NIC'],Vga=INFO['VGA'],Os=INFO['OS'],Arch=INFO['ARCH'],
			Kernel=INFO['KERNEL'],Position=INFO['POSITION'],State=INFO['STATE'],Server=INFO['SERVER'],Owner=INFO['OWNER'])
		DBDA.save()
		return render('device_add.html',{'DBDA':INFO,'show_all_form':True},request)
		
	return render('device_add.html',{'show_ip_form':True},request)


@login_required()
def device_del(request):
	return HttpResponse('device_del')


@login_required()
def device_change(request):
	return HttpResponse('device_change')
