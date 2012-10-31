#coding: utf-8
#!/usr/bin/env python

import os, sys
import argparse
import platform
import shutil
import subprocess
import shelve

install_log = "install.log"
local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osms")


class Install(object):
    def install(self, dst=None):
        self.install_dir = dst
        self.check_platform()
        self.check_requires()
        
        if not os.path.exists(local_path):
            print "Error: main package does not exist!"
            sys.exit(1)
        
        if not os.path.exists(self.install_dir):
            print "Notice: %s does not exist, will be created." % self.install_dir
            try:
                os.makedirs(self.install_dir)
            except:
                print "Error: error occured while mkdir: %s , install program quit now." % self.install_dir
                sys.exit(1)
                
        shutil.rmtree(self.install_dir, onerror=self.raise_error)
        shutil.copytree(local_path, self.install_dir)
        self.record_log(self.install_dir, action="put")
    
    def uninstall(self):
        install_dir = self.record_log(action="get")
        shutil.rmtree(install_dir, onerror=self.raise_error)
        print "osms has been removed from your system."
    
    def raise_error(self, listdir_obj, path, exc_info):
        raise exc_info[1]
    
    def check_platform(self):
        if not sys.platform.startswith("linux"):
            print "Error: osms can only run in linux platform."
            sys.exit(1)
            
        dist = platform.dist()[0]
        if not dist in ("Ubuntu"):
            print "Notice: there may be some problem in %s" % dist
    
    def check_requires(self):
        pass

    def execute_command(self, command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.wait()
        returncode = process.returncode
        if returncode == 1:
            return False
        return True
    
    def record_log(self, content=None, action=None):
        try:
            db = shelve.open(install_log, flag='c')
        except:
            print "error ocurred while create log file."
            return False
        if action == "put" and len(content) > 0:
            try:
                db['install'] = content
                db.close()
            except:
                print "error ocurred while store log."
                return True
            else:
                return True
        elif action == "get":
            try:
                return db['install']
            except:
                print "error ocurred while get log."
                return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="osms install script")
    exclusive_group = parser.add_mutually_exclusive_group(required=False)
    
    exclusive_group.add_argument('--install', action="store_true",
                        dest='install', default=False, help="install osms to your system")
    exclusive_group.add_argument('--uninstall', action='store_true',
                        dest='uninstall', default=False, help="uninstall osms from your system")
    
    parser.add_argument('--install-dir', action='store', default="/usr/local/osms",
                        dest='install_dir', help="install directory, default is /usr/local/osms")
    
    sysargs = sys.argv[1:]
    args = parser.parse_args(args=sysargs)
    if len(sysargs) < 1:
        parser.print_help()
    else:
        install_handler = Install()
        if args.install:
            install_handler.install(args.install_dir)
        elif args.uninstall:
            install_handler.uninstall()

