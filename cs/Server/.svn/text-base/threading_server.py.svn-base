#!/usr/bin/python
#coding:utf-8

import SocketServer
import os,sys
import logging
from commands import getoutput
import subprocess
#from Crypto.Cipher import AES
import struct
from lib.IPy import IP
import re,time
import threading


HOST=""
PORT=12777
ADDR=(HOST,PORT)
ALLOWED_HOSTS = "172.16.90.0/24","172.16.30.19","127.0.0.1","10.8.8.0/24","172.16.60.0/24","172.16.30.0/24","116.236.160.214","192.168.56.0/24",


#new thread for install package
class threading_install(threading.Thread):
    def __init__(self,cmd):
        threading.Thread.__init__(self)
        self.cmd = cmd

    def run(self):
        output = getoutput('/bin/bash '+self.cmd)
        logfile = self.cmd.split('/')[-1].split('.')[0]+'.log'
        fd = open(logfile,'wb')
        fd.write(output)
        fd.flush()
        fd.close()

def threading_main(cmd):   
    t = threading_install(cmd)
    t.setDaemon(True)
    t.start()



#insert iptables rule for myself
def insert_iptables_rule():
	IPT = "/sbin/iptables","/usr/sbin/iptables",
	for path in IPT:
		if os.path.exists(path):
			IPT_PATH = path
	if 'dpt:'+str(PORT) not in getoutput(IPT_PATH + ' -L -nv'):
		IPT_COMMAND = IPT_PATH + " -I INPUT  -m state --state NEW -m tcp -p tcp --dport " + str(PORT) + " -j ACCEPT"
		os.system(IPT_COMMAND)


#let current process become a daemon
def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):

    '''This forks the current process into a daemon. The stdin, stdout, and
    stderr arguments are file names that will be opened and be used to replace
    the standard file descriptors in sys.stdin, sys.stdout, and sys.stderr.
    These arguments are optional and default to /dev/null. Note that stderr is
    opened unbuffered, so if it shares a file with stdout then interleaved
    output may not appear in the order that you expect. '''

    # Do first fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)   # Exit first parent.
    except OSError, e: 
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/") 
    os.umask(0) 
    os.setsid() 

    # Do second fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)   # Exit second parent.
    except OSError, e: 
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Now I am a daemon!
    
    # Redirect standard file descriptors.
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


#AES 256 Encrypt
class mycrypt(object):
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CBC
        
    def myencrypt(self,text):
        cryptor = AES.new(self.key,self.mode)
        length = 16
        count = text.count('')
        if count < length:
            add = (length-count) + 1
            text = text + (' ' * add)
        elif count > length:
            add = (length-(count % length)) + 1
            text = text + (' ' * add)
        self.ciphertext = cryptor.encrypt(text)
        return self.ciphertext
    
    
    def mydecrypt(self,text):
        cryptor = AES.new(key,self.mode)
        plain_text  = cryptor.decrypt(text)
        return plain_text


#save formated log to file
def loginfo(info,level):
	logger = logging.getLogger()
	#handler = logging.FileHandler('/tmp/server.log')
	handler = logging.FileHandler('server.log')
	logflt = logging.Formatter("%(levelname)s [%(asctime)s]: %(message)s","%Y-%m-%d %H:%M:%S")
	handler.setFormatter(logflt)
	logger.addHandler(handler)
	levels = {"CRITICAL":50,"ERROR":40,"WARNING":30,"INFO":20,"DEBUG":10}
	for key in levels:
		if level == key:
			logger.setLevel(levels[key])
			eval("logging."+key.lower()+"("+'"'+info+'"'+")")
	logger.removeHandler(handler)


#loginfo('error info...','ERROR')


#class which process commands that receive from client
class commands(object):
	def __init__(self,cmd):
		self.cmd = cmd
		loginfo('Got Command: %s' % cmd,'INFO')
		print "Got Command: %s" % cmd
	
	def check_cmds(self):
		if self.cmd == "getsysinfo":
			return self.get_sysinfo()
		elif self.cmd =="help":
			return "::Valid commands are: getsysinfo getnic getvga getharddrive getparttion getcpu getmem getifvirtued system help"
		elif "system" in self.cmd:
			return self.system(self.cmd.split('system'))
		elif "gethardware" in self.cmd:
			return self.get_hardware()
		elif self.cmd == "getnic":
			return self.get_nic()
		elif self.cmd == "getvga":
			return self.get_vga()
		elif self.cmd == "getharddrive":
			return self.get_harddrive()
		elif self.cmd == "getparttion":
			return self.get_parttion()
		elif self.cmd == "getcpu":
			return self.get_cpu()
		elif self.cmd == "getmem":
			return self.get_mem()
		elif self.cmd == "getifvirtued":
			return self.get_virtualized()
		elif self.cmd == "getuptime":
			return self.get_uptime()
		elif self.cmd == "getloadavg":
			return self.get_loadavg()
		elif "install" in self.cmd:
			return self.install(self.cmd.split('install'))
		elif self.cmd == "":
			return ''
		else:
			return "::Please input legal command!"


	def get_sysinfo(self):
		r = '\r\n'
		issue = self.get_issue()
		os = getoutput('uname -o')
		machine = getoutput('uname -m')
		kernel = getoutput('uname -r')
		return issue+r+os+r+machine+r+kernel

	def get_hardware(self):
		return self.get_nic() + '\n' + self.get_vga().strip() + '\n' + self.get_harddrive().strip()
	
	def get_bin_path(self):
		lspci_path = "/usr/bin/lspci","/sbin/lspci","/usr/sbin/lspci",
		for bin in lspci_path:
			if os.path.exists(bin):
				self.lspci = bin
				break

	def get_pci(self):
		self.get_bin_path()
		return getoutput(self.lspci)
	
	def get_harddrive(self):
		if "SATA" in self.get_pci():
			return getoutput(self.lspci+" | awk -F ':' '/SATA/ {print $3}'")
		elif "RAID" in self.get_pci():
			return getoutput(self.lspci+" | awk -F ':' '/RAID/ {print $3}'")
	
	def get_nic(self):
		self.get_bin_path()
		ether_nic = getoutput(self.lspci+" | awk -F ':' '/Ether/ {print $3}'")
		return ether_nic
	
	def get_vga(self):
		self.get_bin_path()
		return getoutput(self.lspci+"| awk -F ':' '/VGA/ {print $3}'")
	
	def get_parttion(self):
		return getoutput("fdisk -l | awk '/\/dev\// {print}'")
	
	def get_cpu(self):
		return getoutput("cat /proc/cpuinfo | grep 'model name' | cut -d: -f2 | sed 's/^ //'")
	
	def get_virtualized(self):
		if "vmx" or "vme" or "svm" in getoutput("cat /proc/cpuinfo"):
			return 1
		else:
			return 0

	def get_mem(self):
		mem = int(getoutput("cat /proc/meminfo  | grep 'MemTotal' | cut -d: -f2 | sed 's/^\s*//' | cut -d' ' -f1"))/1024
		return "%s MB"  % mem
	
	def system(self,parms):
		if parms[1] != "":
			if "rm" in parms[1]:
				return "Dangerous! Make sure **the path** you specified!.\r\n"+getoutput(parms[1])
			return getoutput(parms[1])
		else:
			return ""
		
	def install(self,parms):
		if parms[1] != "":
			threading_main(parms[1].strip())
		
	def get_issue(self):
		issue_file = '/etc/issue'
		if not os.path.exists(issue_file):
			return getoutput('uname -o')
		f = open(issue_file)
		lines = f.readlines()
		f.close()
		for line in lines:
			if 'Arch' in line:
				return "ArchLinux"
			elif 'CentOS' in line:
				return "CentOS"
			elif 'Ubuntu' in line:
				return "Ubuntu"
			elif 'Fedora' in line:
				return 'Fedora'
			else:
				return "Linux"

	def get_uptime(self):
		return getoutput("uptime | cut -d',' -f 1").strip()
	
	def get_loadavg(self):
		load1,load2,load3 = os.getloadavg()
		return str(load1) + ' ' + str(load2) + ' ' + str(load3)

#Base Working Class, subclass of SocketServer.BaseRequestHandler
#override handle method to process request
class MyRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		"""
		login = False
		while login != True:
			try:
				self.request.send('Password: ')
			except Exception,e:
				loginfo('%s:%s Send failed! %s' % (self.client_address[0],self.client_address[0],e),'ERROR')
				break
			data = self.request.recv(10240)
			if data.strip() == "password":
				try:
					self.request.send("login_sucess\r\n")
				except Exception,e:
					loginfo('%s:%s Send failed! %s' % (self.client_address[0],self.client_address[0],e),'ERROR')
				login = True
			else:
				login = False
				loginfo('%s has input wrong password: [ %s ]' % (self.client_address[0],data.strip()),'CRITICAL')
				self.finish()
		"""

		#check if client's ip address is allowed
		ip_address = str(self.client_address[0])
		port = str(self.client_address[1])
		hosts = []
		cidr = []
		for host in ALLOWED_HOSTS:
			if '/' in host:
				cidr.append(host)
			else:
				hosts.append(host)
		for net in cidr:
			for ip in IP(net):
				hosts.append(str(ip))
		if ip_address in hosts:
			print '::Connected from: ',self.client_address
			loginfo("Connected from: %s:%s" %(ip_address,port),'INFO')
		else:
			self.request.send('Not Allowed Here!\n')
			print '::Forbidden Host from: ',self.client_address
			loginfo("Forbidden Host from: %s:%s" %(ip_address,port),'INFO')
			self.finish()
			
			
		while True:
			BUF_SIZE = struct.calcsize('!1024s')
			buffer = self.request.recv(BUF_SIZE)
			print len(buffer)
			if len(buffer)==1024:
				data = struct.unpack('!1024s',buffer)[0].replace('\x00','')
			else:
				self.finish()
				break
				
			if data.strip() == 'byebye':
				try:
					self.request.send("seeyou!")
				except Exception,e:
					loginfo('%s:%s Send failed! %s' % (ip_address,port,e),'ERROR')
				print("::%s:%s Leaving server.\r\n" % (ip_address,port))
				loginfo("%s:%s Leaving server." % (ip_address,port),'INFO')
				self.finish()
				break
			
			#if in putfile mode
			# cmd in client is like this: "putfile /client/side/file.jpg /server/side/file.jpg APPEDN_BIN"
			if "putfile" in data.strip():
				filename = data.split(' ')[2]
				try:
				    mod = data.split(' ')[3]
				    if mod == 'WRITE_BIN': mod = 'wb'
				    elif mod == 'WRITE_ASC': mod = 'w'
				    elif mod == "APPEND_BIN": mod = 'ab+'
				    elif mod == "APPEND_ASC": mod = 'a+'
				except:
				    mod = 'wb'
				fd = open(filename,mod)
				while True:
					content = self.request.recv(1024)
					if not content:
						break
					fd.write(content.decode('hex'))
				fd.flush()
				fd.close()
				self.finish()
				break
			
			#if in getfile mode
			if "getfile" in data.strip():
				filename = data.split(' ')[1]
				#if file not exist or filename is a directory, send error information to client
				if not os.path.exists(filename) or os.path.isdir(filename):
					self.request.sendall(struct.pack('!128s','File not found, please check the path!'))
				else:
					self.request.sendall(struct.pack('!128s','File Found! Will Transfer Now!'))
				print filename
				fd = open(filename,'rb')
				#send data in a loop
				while True:
					data = fd.read(1024)
					if not data:
						break
					self.request.send(data.encode('hex'))
				fd.close()
				self.finish()
				break
				
			#process command that receive from client
			cmd_output = commands(data.strip())
			try:
				lines = cmd_output.check_cmds()
				self.request.sendall('%s' % lines)
				self.finish()
				break
			except Exception,e:
				loginfo('%s:%s Send failed! %s' % (ip_address,port,e),'ERROR')
				self.finish()
				break


# main function
# Server can reuse listened address
def main():
	SocketServer.ThreadingTCPServer.allow_reuse_address = True
	tcpServ = SocketServer.ThreadingTCPServer(ADDR,MyRequestHandler)
	print '::waiting for connecting...'
	tcpServ.serve_forever()

if __name__=="__main__":
	#if os.getuid() != 0:
	#	print "This server process should be running by root!"
	#	sys.exit(1)
	#insert_iptables_rule()
	#daemon_log_path = os.getcwd()+"/daemon.log"
	#daemonize('/dev/null',daemon_log_path,daemon_log_path)
	main()


