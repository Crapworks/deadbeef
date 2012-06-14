#!/usr/bin/python2.6

import subprocess
import cmd
import sys
import signal
import os
import errno
import pickle
import httplib
import shutil

from stat import S_IXUSR

class ipv6suite(cmd.Cmd):
    """
    This Class provides the main interactive commandline interface for the ipv6 exploitation framework (deadbeef)
    Main function:
    * load als ipv6 modules locatet in the deadbeef_modules module
    * provide first level commandline interface
    * kill jobs running in background
    * enable / disable ipv6 forwarding
    """
    
    def __init__(self):
        cmd.Cmd.__init__(self)      

        # set version number
        self.version = "0.8"

        # set python path variable to find all modules in subdirectories
        self.mod_path = os.getcwd() + "/modules"
        self.lib_path = os.getcwd() + "/lib"
        
        sys.path.append(self.mod_path)
        sys.path.append(self.lib_path)

        #import deadbeef_modules (api file)
        import deadbeef_modules    
        
        # fancy colors!!1
        self.cc = deadbeef_modules.cc_msg()
        
        # cmdline overwrites
        self.prompt = self.cc.prompt("dead:beef::")     
        self.ruler = ""
        self.doc_header = "Available Modules:\n"        
        self.module_list = {}
        self.globals = []
        self.globals_set = {}
        self.process_id = os.getpid()
        
        # install signales handler 
        signal.signal(signal.SIGINT, self.__signal_handler)

        self.cc.ok("starting dead:beef:: ipv6 exploitation framework V" + self.version + "\n")
        self.cc.ok("(c) 2010 Christian Eichelmann - SySS GmbH\n")
        print ""

        if os.getuid():
            self.cc.err("you need to be r00t to use this fancy program\n")
            sys.exit(0)

        # automagicaly load saved globals
        path = os.path.expanduser('~') + "/.deadbeef"
        filename = path + "/" + self.__class__.__name__ + ".cfg"
        if os.path.isfile(filename):
            save_file = open(filename, "r")
            try:
                self.globals_set = pickle.load(save_file)
            except:
                self.cc.err("unable to load data from %s. delete the file to get rid of this error.\n" % (filename))

        # set python path variable to find all modules in subdirectories
        mod_path = os.getcwd() + "/modules"
        lib_path = os.getcwd() + "/lib"

        # load all ipv6 modules from subdirectory                                
        flist = os.listdir(mod_path)
        for module in flist:
            if module.endswith(".py"):
                module = module[:-3]
                
                # load module from path
                try:
                    exec("import " + module)
                except:
                    self.cc.err("unable to load module: %s. skipping." % (module, ))
                    
                for class_name in dir(eval(module)):
                    if class_name.startswith("ipv6_"):
                        mod_name = class_name.split("_")[1]
                        self.module_list[mod_name] = eval(module + "." + class_name + "()")
                        self.__class__.__dict__['do_'+ mod_name ]= self.module_list[mod_name].cmdloop
                        self.__class__.__dict__['help_'+ mod_name] = self.module_list[mod_name].help

                        # get a unique list of available module options (for global settings)
                        self.globals.extend(self.module_list[mod_name].valid_parameters)
                        
                        # set globals loaded from file
                        for opt, value in self.globals_set.iteritems():
                            # avoid global variable overwriting local module settings
                            if opt in self.module_list[mod_name].valid_parameters and not opt in self.module_list[mod_name].parameters:                     
                                self.module_list[mod_name].parameters[opt] = value

        self.globals = set(self.globals)

        # enable ipv6 forwarding
        if not self.__enable_ipv6_forwarding__():
            self.cc.warn("unable to enable ipv6 forwarding.\n")
        else:
            self.cc.ok("ipv6 forwarding enabled.\n")

    def __enable_ipv6_forwarding__(self):
        """ enable ipv6 forwarding via the proc filesystem """
        
        subprocess.Popen('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding', shell=True)
        forwarding = subprocess.Popen('cat /proc/sys/net/ipv6/conf/all/forwarding', stdout=subprocess.PIPE, shell=True).communicate()[0].rstrip("\n")
        if forwarding == "1":
            return True
        else:
            return False

    def __disable_ipv6_forwarding__(self):
        """ disable ipv6 forwarding via the proc filesystem """
        
        subprocess.Popen('echo 0 > /proc/sys/net/ipv6/conf/all/forwarding', shell=True)
        forwarding = subprocess.Popen('cat /proc/sys/net/ipv6/conf/all/forwarding', stdout=subprocess.PIPE, shell=True).communicate()[0].rstrip("\n")
        if forwarding == "0":
            return True
        else:
            return False

    def __signal_handler(self, signal, frame):
        """ signal handler for SIGINT """
        
        # child or parent?
        if self.process_id == os.getpid():              
            print ""
            self.cc.err("user interrupte (ctrl-c). cleaning up...\n")
            self.cleanup()
        
    def cleanup(self):
        """ cleanup stuff before exiting """

        # check for running modules
        for name, module  in self.module_list.iteritems():
            if module.get_pid():
                module.stop(None)           
        
        # disable ipv6 forwarding
        if not self.__disable_ipv6_forwarding__():
            self.cc.warn("unable to disable ipv6 forwarding.\n")
        else:
            self.cc.ok("ipv6 forwarding disabled.\n")               
                    
        self.cc.ok("exiting dead:beef:: ...\n")
        sys.exit(0)         
        
    def emptyline(self):
        pass

    def columnize(self, list, displaywidth=80):
        """ show available modules and their description """
        
        print "    %-20s%s" % ("Name", "Description")
        print "    %-20s%s" % ("----", "-----------")       
        for item in list:
            try:
                func = getattr(self, 'help_' + item)
                self.cc.ok("%-20s" % (item ,))
                func()
            except AttributeError:
                print item + " : (no description available)"
            
    def default(self, line):
        self.cc.err("unknown syntax\n")

    def do_jobs(self, cmdline):
        """ show currently running jobs """
        
        for name, module  in self.module_list.iteritems():
            if module.get_pid():
                self.cc.ok("module: " + self.cc.cc_text('red', name )+ " is running with pid: " + self.cc.cc_text('blue', str(module.get_pid())) + "\n")
    
    def help_jobs(self):
        print "show currently running jobs"
        
    def do_kill(self, cmdline):     
        """ kill a job running in background """
        
        if not cmdline:
            self.cc.err("unknown syntax. use: kill <pid>\n")
        else:
            for name, module  in self.module_list.iteritems():
                if module.get_pid() == int(cmdline.rstrip("\n")):               
                    module.stop(None)
                    return 

        self.cc.warn("unkown job pid: " + cmdline.rstrip("\n") + "\n")

    def help_kill(self):
        print "kill a running job (kill <pid>)"

    # global variables support
    def do_global(self, cmdline):
        if not cmdline:
            print "\nAvailable Globals:\n"
            print "    %-20s%s" % ("Name", "Current Value")
            print "    %-20s%s" % ("----", "-----------")
            for opt in self.globals:
                if opt in self.globals_set.keys():
                    self.cc.ok("%-20s%s\n" % (opt, self.globals_set[opt]))              
                else:
                    self.cc.ok("%-20s%s\n" % (opt, "(None)"))               
            print ""            
            
        else:
            try:
                opt = cmdline.split("=")[0]
                value = cmdline.split("=")[1]
            except IndexError:
                self.cc.err("invalid global syntax (global <option>=<value>)\n")
                return
        
            if not opt in self.globals:
                self.cc.err("unknown option: " + opt + "\n")
            else:
                self.globals_set[opt] = value
                for name, mod in self.module_list.iteritems():
                    if opt in mod.valid_parameters:
                        mod.parameters[opt] = value
    
    def complete_global(self, text, line, begidx, endidx):
        """ autocompletion for global options """
        
        return [i for i in self.globals if i.startswith(text)]  
    
    def help_global(self):
        print "set global options (global <option>=<value>, use with no parameters to see available options)"

    # update from sourceforge
    def do_update(self, cmdline):
        self.http_connection = httplib.HTTPConnection("dead-beef.sourceforge.net")
        self.http_connection.request("GET","/update/latest")
        response = self.http_connection.getresponse()
        
        if not response.status == 200:
            self.cc.err("unable to get latest version from sourceforge\n")
            return
        
        self.cc.ok("checking for updates... \n")

        latest = response.read(response.msg.getheader('content-length')).rstrip('\n')
        if float(latest) > float(self.version):
            # checkout new version
            self.cc.ok("found newer version: %s on sourceforge. retrieving updates...\n" % (latest,))
            self.http_connection = httplib.HTTPConnection("dead-beef.sourceforge.net")
            self.http_connection.request("GET","/update/" + latest + "/list")
            response = self.http_connection.getresponse()            

            if not response.status == 200:
                self.cc.err("unable to get list of files from sourceforge\n")
                return
                
            filelist = response.read(response.msg.getheader('content-length'))
            filelist = filelist.split('\n')
            
            for f_name in filelist:
                # garbage collector...
                if len(f_name) < 3:
                    continue
                    
                self.cc.ok("downloading " + f_name + "...\n")
                self.http_connection = httplib.HTTPConnection("dead-beef.sourceforge.net")
                self.http_connection.request("GET","/update/" + latest + f_name)
                response = self.http_connection.getresponse()            

                if not response.status == 200:
                    self.cc.err("unable to get " + f_name + " from sourceforge\n")
                    return                
            
                try:
                    tmp = open("update.tmp","w")
                    data_len = int(response.msg.getheader('content-length'))
                    data = response.read(data_len)
                    while len(data) < data_len:
                        data += response.read(data_len - len(data))
                    tmp.write(data)
                except:
                    self.cc.err("unable to create file update.tmp in current directory\n")
                    return
                
                # overwrite existing file
                shutil.move("update.tmp", f_name.lstrip("/"))

                #set executable bit for deadbeef.py
                os.chmod("deadbeef.py", S_IXUSR)
                
            self.cc.ok("update completed. restart deadbeef to use the updated version\n")
        else:
            self.cc.ok("your version is up-to-date\n")

    
    def help_update(self):
        print "search for updates on sourceforge"
    

    # save global variables
    def do_save(self, cmdline):
        # mkdir if not exists
        path = os.path.expanduser('~') + "/.deadbeef"
        try:
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else: 
                raise
                
        # open filename
        filename = path + "/" + self.__class__.__name__ + ".cfg"
        save_file = open(filename, "w")
        pickle.dump(self.globals_set, save_file)        
        save_file.close()
        
        self.cc.ok("saved options in file: %s\n" % (filename, ))
        
    def help_save(self):
        print "save global settings (loaded automagicaly at startup)"
        
    def do_exit(self, cmdline):
        self.cleanup()
        return True
        
    def help_help(self):
        print "show available modules"
        
    def help_exit(self):
        print "close dead:beef:: and return to system shell"
        
    do_quit = do_exit
    help_quit = help_exit

def main():
    """ praise the magic main function """    

    suite = ipv6suite()
    suite.cmdloop()

if __name__ == "__main__" :
    main()
