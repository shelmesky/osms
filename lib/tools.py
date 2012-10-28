# coding: utf-8

import sys,os,re
from socket import *
from commands import getoutput
import struct
from django import get_version
from django.template import RequestContext
from django.shortcuts import render_to_response
from admins.models import User_Random,SSH
from random import random,randrange
import paramiko
import traceback
import zipfile, tarfile
import threading


#new thread for compress package
class threading_compress(threading.Thread):
    def __init__(self,cmd):
        threading.Thread.__init__(self)
        self.cmd = cmd
        
    def run(self):
        os.chmod(self.cmd,0755)
        output = getoutput(self.cmd)
        

def compress_main(cmd):
    t = threading_compress(cmd)
    t.setDaemon(True)
    t.start()

def check_if_online(ip):
    HOST = ip
    PORT = 12777
    ADDR = (HOST,PORT)
    tcpsock = socket(AF_INET,SOCK_STREAM)
    tcpsock.settimeout(1)
    try:
        tcpsock.connect(ADDR)
    except:
        return False
    else:
        return True
    finally:
        tcpsock.close()


class upload(object):
    def makeself(self,src_dir,dst_filename,package_name,init_script):
        makeself = getoutput('whereis makeself').split(':')[1].split(' ')[1]
        if not makeself:
            return "MAKESELF can not found!"
        cmd = makeself+' ' +src_dir+ ' ' +dst_fielname+ ' ' +package+ ' ' + init_script
        compress_main(cmd)
    
    
    def extract_tar_zip(self,f,dst):
        if tarfile.is_tarfile(f):
            fd = tarfile.open(f)
            names = fd.getnames()
            for name in names:
                fd.extract(name,path=dst)
            fd.close()
            return names
        elif zipfile.is_zipfile(f):
            fd = zipfile.ZipFile(f)
            names = fd.namelist()
            for filename in names:
                fd.extract(filename, dst)
            fd.close()
            return names

    def upload_handler(self,fileobj,filepath):
        try:
            fd = open(filepath,'wb')
            for line in fileobj.chunks():
                fd.write(line)
            fd.flush()
            fd.close()
            #names = self.extract_tar_zip(filename,MEDIA_ROOT+'/'+dst_dir)
            #return names
        except:
            info = sys.exc_info()
            for filename, lineno, function, text in traceback.extract_tb(info[2]):
                return (filename, " line:", lineno, " in", function,' ',text),info[:2],

class sshclient:
    def __init__(self,host,username,password,port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.addr = host,port
    
    def exec_command(self,command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(self.host,self.port,self.username,self.password)
            stdin,stdout,stderr = ssh.exec_command(command)
        except Exception:
            print traceback.print_exc()
        ret = dict()
        ret['stdin'] = stdin
        ret['stdout'] = stdout.readlines()
        ret['stderr'] = stderr
        ssh.close()
        return ret
    
    def putfile(self,local,remote):
        remote_path = remote
        local_path = local
        try:
            t = paramiko.Transport(self.addr)
            t.connect(None,self.username,self.password)
            sftp = paramiko.SFTPClient.from_transport(t)
            sftp.put(local_path,remote_path)
        except Exception:
            print traceback.print_exc()
        t.close()
        
    
    def getfile(self,remote,local):
        t = paramiko.Transport(self.addr)
        t.connect(None,self.username,self.password)
        sftp = paramiko.SFTPClient.from_transport(t)
        remote_path = remote
        local_path = local
        try:
            sftp.get(remote_path,local_path)
        except IOError,e:
            return "got error while get remote file from %s ! %s" % (self.addr[0],e)
            sys.exit(1)
        t.close()
        sys.exit(0)


class ajaxterm_daemon:
    def __init__(self,ip=None,request=None):
        self.ip = ip
        self.request = request

    def start_daemon(self):
        ajaxterm = os.path.abspath(os.path.join(os.path.dirname(__file__),'ajaxterm/ajaxterm.py'))
        pex = os.path.abspath(os.path.join(os.path.dirname(__file__),'ajaxterm/pe.py'))
        self.pid = os.path.abspath(os.path.join(os.path.dirname(__file__),'ajaxterm/pidfile/'+str(self.request.user)))
        self.pidfile = self.pid + '/ajaxterm.pid'
        if not os.path.exists(self.pid) : os.mkdir(self.pid)
        self.stop_daemon()
        p = SSH.objects.get(Ip=self.ip)
        username = p.Username
        password = p.Password
        p =  User_Random.objects.get(Username=self.request.user)
        random_pass = p.Random_Password
        random_port = p.Random_Port
        cmd = ajaxterm+' --port='+random_port+' --command=\"'+pex+' '+username+' '+password+' '+self.ip+' '+random_pass+'\" --daemon'
        output = getoutput(cmd)
        m = re.search('pid:\s(\d+)',output)
        pid = m.group(1)
        fd = open(self.pidfile,'wb')
        fd.write(pid)
        fd.flush()
        fd.close()
        return random_pass,random_port

    def stop_daemon(self):
        if self.request.user != None:
            self.pid = os.path.abspath(os.path.join(os.path.dirname(__file__),'ajaxterm/pidfile/'+str(self.request.user)))
            self.pidfile = self.pid + '/ajaxterm.pid'
        fd = open(self.pidfile)
        pid = fd.readline()
        if len(pid) > 0:
            try:
                os.kill(int(pid),9)
            except Exception:
                pass
        fd.close()


def init_random_pass(request):
    random_pass = User_Random.objects.filter(Username=request.user)
    if not random_pass:
        p=User_Random(Username=request.user,Random_Password=str(random())[6:-1],Random_Port=randrange(50000,65500))
        p.save()
    else:
        password = str(random())[6:-1]
        port = randrange(50000,65500)
        User_Random.objects.filter(Username=request.user).update(Random_Password=password,Random_Port=port)


class get_info():
    def get_python_version(self):
        return sys.version
        
    def get_sys_platform(self):
        return sys.platform
        
    def get_loadavg(self):
        return os.getloadavg()
        
    def get_django_version(self):
        return get_version()


def render(template_name,data=None,request=None):
    info = get_info()
    data['info'] = info
    return render_to_response(template_name, data, context_instance=RequestContext(request))


class get_device_info():
    def __init__(self,ip):
        self.ip = ip
        self.port = 12777
        self.addr = (self.ip,self.port)
        self.do_connect()

    def do_connect(self):
        self.SockClient = socket(AF_INET,SOCK_STREAM)
        self.SockClient.settimeout(2)

    def command_to_order(self,command):
        Tuple = {'CPU':'getcpu','MEM':'getmem','DISK':'getharddrive','PARTITION':'getparttion','VIRTUED':'getifvirtued',
                 'NIC':'getnic','VGA':'getvga','SYSINFO':'getsysinfo'}
        if Tuple.has_key(command):
            return Tuple[command]

    def do_exec(self,command):
        if not command:
            command = "help"
        command = self.command_to_order(command)
        BUF_SIZE = struct.calcsize('!1024s')
        command = struct.pack('!1024s',command)
        try:
            self.SockClient.connect(self.addr)
            self.SockClient.send(command)
        except Exception,e:
            return "Error! %s!" % e
        try:
            data = self.SockClient.recv(BUF_SIZE)
        except Exception:
            return "No data received!"
        else:
            return data.strip()
        finally:
            self.do_close()

    def do_close(self):
        self.SockClient.shutdown(SHUT_RDWR)
        self.SockClient.close()
        


class do_command():
    def __init__(self,ip):
        self.ip = ip
        self.port = 12777
        self.addr = (self.ip,self.port)
        self.do_connect()

    def do_connect(self):
        self.SockClient = socket(AF_INET,SOCK_STREAM)
        self.SockClient.settimeout(2)

    def do_exec(self,command):
        if not command:
            command = "help"
        BUF_SIZE = struct.calcsize('!1024s')
        command = struct.pack('!1024s',command)
        try:
            self.SockClient.connect(self.addr)
            self.SockClient.send(command)
        except Exception,e:
            return "Error! %s!" % e
        try:
            data = self.SockClient.recv(BUF_SIZE)
            if not data or len(data)<=0:
                return "No data received!"
            else:
                return data.strip()
        finally:
            self.do_close()

    def do_close(self):
        self.SockClient.shutdown(SHUT_RDWR)
        self.SockClient.close()
        
        
class file_transfer():
    def __init__(self,ip):
        self.ip = ip
        self.port = 12777
        self.addr = (self.ip,self.port)
        self.do_connect()

    def do_connect(self):
        self.SockClient = socket(AF_INET,SOCK_STREAM)
        self.SockClient.settimeout(3)
        self.SockClient.connect(self.addr)

    def file(self,cmd):
        cmd = str(cmd.strip())
        if "putfile" in cmd:
            filename = cmd.split(' ')[1]
            if not os.path.exists(filename):
                return "File not found!"
                self.close_socket()
            cmd = struct.pack('!1024s',cmd)
            self.SockClient.send(cmd)
            try:
            	fd = open(filename,'rb')
            except IOError,e:
            	return "Something wrong happend while open file! %s" % e
            	self.close_socket()
            buf = ""
            while True:
            	data = fd.read(1024)
            	if not data:
            		break
            	data = data.encode('hex')
            	self.SockClient.send(data)
            fd.close()
            self.close_socket()
            
            
        #filepath must be absolute path!
        BUF_SIZE1 = struct.calcsize('!128s')
        if "getfile" in cmd:
            cmd = str(cmd.strip())
            filename = cmd.split(' ')[2]
            #filename = cmd.split(' ')[1].split('/')[-1]
            cmd = struct.pack('!1024s',cmd)
            self.SockClient.send(cmd)
            rev = self.SockClient.recv(BUF_SIZE1)
            ret = struct.unpack('!128s',rev)[0].replace('\x00','')
            if "not" in ret:
                return ret
                self.close_socket()
            else:
                try:
                    fp = open(filename,'wb')
                except IOError,e:
                    return "errors happend while open %s! %s" % (filename,e)
                    fp.close()
                    self.close_socket()
                while True:
                    data = self.SockClient.recv(1024)
                    if not data:
                        break
                    fp.write(data.decode('hex'))
            fp.flush()
            fp.close()
            self.close_socket()

    def close_socket(self):
        self.SockClient.shutdown(SHUT_RDWR)
        self.SockClient.close()


