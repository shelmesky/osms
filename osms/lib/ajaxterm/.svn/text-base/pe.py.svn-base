#!/usr/bin/python -d
#coding:utf-8

import pexpect
import sys
import os
import struct
import fcntl
import termios
import signal
import getpass,time


username = sys.argv[1]
password = sys.argv[2]
host = sys.argv[3]
console_pass = sys.argv[4]
shell_prompt = "~]#"
shell_prompt1 = "~ #"

if not username or not password or not host or not console_pass:
	print "not enough console arguments!"
	sys.exit(1)

PASSWORD = getpass.getpass(prompt="Please input password: ")
if PASSWORD != console_pass:
	print "Password Error!!!"
	time.sleep(2)
	sys.exit(1)

child = pexpect.spawn('ssh %s@%s' % (username,host))
index = child.expect(['Password','password','yes/no','Last Login'])

#simulating ssh login processes
try:
	if index == 0:
		child.sendline(password)
	elif index == 1:
		child.sendline(password)
	elif index == 2:
		child.sendline('yes')
		child.expect(['Password','password'])
		child.sendline(password)
	elif index == 3:
		pass
except Exception,e:
	print e

def sigwinch_passthrough(sig,data):
	s = struct.pack("HHHH",0,0,0,0)
	a = struct.unpack('hhhh',fcntl.ioctl(sys.stdout.fileno(),termios.TIOCGWINSZ,s))
	global child
	child.setwinsize(a[0],a[1])

signal.signal(signal.SIGWINCH, sigwinch_passthrough)
print "Will going to interact mode, press any key to get SHELL PROMPT."
child.interact()
child.close()
print "left interactive mode."
sys.exit(0)
