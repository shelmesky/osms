from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from lib.tools import render, do_command, upload
from admins.models import Device, Install_Package
from commands import getoutput
import os
from lib.tools import file_transfer
from lib.tools import ajaxterm_daemon
from lib.tools import check_if_online
from lib.tools import file_transfer, do_command
from settings import MEDIA_ROOT
import traceback



@login_required()
def system_main(request):
	return HttpResponse('system_main')

@login_required()
def system_status(request):
	return HttpResponse('system_status')


@login_required()
def system_autoinstall(request):
	if request.method == "POST" and request.REQUEST.get("Type") == "UPLOAD_FILE":
		try:
			fileobj = request.FILES['file']
			dst = request.REQUEST.get('dst')
			ip = request.REQUEST.get('ip')
			package_content = request.REQUEST.get('package_content')
		except:
			return render('system_autoinstall.html',{'form_empty_error':True},request)
		filepath = os.path.abspath(MEDIA_ROOT+'/'+str(fileobj))
		up = upload()
		error = up.upload_handler(fileobj,filepath)
		online = check_if_online(ip)
		if not error:
			p = Install_Package(package_name = dst,package_path = filepath,package_content = package_content)
			p.save()
		fileinfo = {'name':dst,'content':package_content,'path':filepath,'ip':ip,'online':online}
		return render('system_autoinstall.html',{'error':error,'fileinfo':fileinfo},request)
	
	if request.method == "POST" and request.REQUEST.get("Type") == "SEND_TO_REMOTE":
		name = request.REQUEST.get("name")
		contenet = request.REQUEST.get("content")
		path = request.REQUEST.get("path")
		ip = request.REQUEST.get("ip")
		cmd_putfile = 'putfile '+path+' /opt/Server/'+name+'.run'
		cmd_install_package = 'install /opt/Server/'+name+'.run'
		try:
			f = file_transfer(ip)
			f.file(cmd_putfile)
			c = do_command(ip)
			c.do_exec(str(cmd_install_package))
		except:
			return render('system_autoinstall.html',{'error_transfer':True},request)
		else:
			return render('system_autoinstall.html',{'success_transfer':True},request)
	
	return render('system_autoinstall.html',{'show_upload_form':True},request)


@login_required()
def system_autoinstall_package_management(request):
	return render('system_autoinstall_package_management.html',{},request)
	

@login_required()
def system_autoinstall_status(request):
	return render('system_autoinstall_status.html',{},request)


@login_required()
def system_run_command(request):
	if request.method == "POST":
		#try:
		host = request.REQUEST.get('choose_host')
		ajaxterm = ajaxterm_daemon(host,request)
		random_pass,random_port = ajaxterm.start_daemon()
		#except Exception:
		#	return render('system_run_command.html',{'ERROR_INIT_DAEMON':True},request)
		return render('system_run_command.html',{'random_pass':random_pass,'random_port':random_port,'meta':request.META},request)
	
	host_list = Device.objects.all()
	return render('system_run_command.html',{'devices':host_list,'show_hostlist_form':True},request)

@login_required()
def system_cron(request):
	if request.method == "POST" and request.REQUEST.get('Type') == "CRON_CHOOSE_HOST":
		choose_host = request.REQUEST.get('choose_host')
		files = os.path.join(os.path.dirname(__file__),'../files/'+choose_host)
		cron_files = files + '/cron'
		if not os.path.exists(files):
			os.mkdir(files)
			os.mkdir(cron_files)
		real_cron_file = os.path.abspath(cron_files)+'/crontab'
		if not os.path.exists(cron_files+'/crontab'):
			try:
				ftransfer = file_transfer(choose_host)
				ftransfer.file("getfile /etc/crontab "+real_cron_file)
			except Exception:
				return render('system_cron.html',{'ERROR_TRANSFER':True},request)
		try:
			fd = open(real_cron_file)
			data = fd.readlines()
		except Exception,e:
			return render('system_cron.html',{'ERROR_OPENFILE':True},request)
		lines = ''
		for line in data:
				lines += line
		fd.close()
		return render('system_cron.html',{'show_cron_delete_form':locals()},request)


	if request.method == "POST" and request.REQUEST.get('Type') == "CRON_MODIFY":
		host = request.REQUEST.get('host')
		cronfile = request.REQUEST.get('cronfile')
		cron_content = request.REQUEST.get('cron_content')
		try:
			os.rename(cronfile,cronfile+'_bak')
			fd = open(cronfile,'wb')
			fd.write(cron_content)
			fd.flush()
			fd.close()
			ftransfer = file_transfer(host)
			ftransfer.file('putfile '+cronfile+' /etc/crontab')
		except Exception:
			return render('system_cron.html',{'ERROR_WRITE_FILE':True},request)
		return render('system_cron.html',{'FINISHED_WRITE_FILE':True},request)

	
	host_list = Device.objects.all()
	return render('system_cron.html',{'devices':host_list,'show_hostlist_form':True},request)

@login_required()
def system_add_cron(request):
	return HttpResponse('system_add_cron')

@login_required()
def system_shutdown(request):
	host_list = Device.objects.all()
	real_list = []
	devices= {}
	for x in host_list:
		devices['IP'] = x.Ip
		rexec = do_command(x.Ip)
		devices['UPTIME'] = rexec.do_exec('getuptime')
		rexec = do_command(x.Ip)
		devices['LOADAVG'] = rexec.do_exec('getloadavg')
		real_list.append(devices)
		devices = {}
	return render('system_shutdown.html',{'devices':real_list},request)

@login_required()
def system_action(request,action,ip):
	if action == "reboot":
		cmd = "system shutdown -r now"
		rexec = do_command(ip)
		ret = rexec.do_exec(cmd)
	elif action == "halt":
		cmd = "system shutdown -h now"
		rexec = do_command(ip)
		ret = rexec.do_exec(cmd)
	if not "Error" in ret:
		return render('system_shutdown.html',{'action_finished':True},request)
	else:
		return render('system_shutdown.html',{'action_error':True},request)

@login_required
def system_whois(request):
	if request.method == "POST":
		name = request.REQUEST.get('NAME')
		result = getoutput('whois %s' % name )
		return render('system_whois.html',{'show_whois_result':result},request)
	return render('system_whois.html',{'show_whois_form':True},request)

@login_required
def system_dig(request):
	if request.method == "POST":
		name = request.REQUEST.get('NAME')
		type = request.REQUEST.get('type')
		dns_server = request.REQUEST.get('dns_server')
		result = getoutput('dig %s %s @%s' % (type,name,dns_server))
		return render('system_dig.html',{'show_dig_result':result},request)
	return render('system_dig.html',{'show_dig_form':True},request)

