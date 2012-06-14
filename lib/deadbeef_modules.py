import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from multiprocessing import Process, Pipe
from select import select
from collections import deque

import cmd
import sys
import re
import os
import errno
import pickle

# maximum scrollback buffer size for ringbuffer
MAX_SCROLLBACK_BUFFER = 1000

# class to store output of modules in background
class RingBuffer(deque):
    """ ring buffer: stores output of modules runnning in background """
    def __init__(self, size_max):
        deque.__init__(self)
        self.size_max = size_max
        
    def __full_append(self, data):
        deque.append(self, data)
        self.popleft()
        
    def append(self, data):
        deque.append(self, data)
        if len(self) == self.size_max:
            self.append = self.__full_append
        
    def get(self, num):
        return list(self)[-num:]

class c_colors:
    """ provide some fancy colors on the commandline """
    
    def __init__(self):
        self.colors = {}
        self.colors['green'] = '\033[92m'
        self.colors['yellow'] = '\033[93m'
        self.colors['red'] = '\033[91m'
        self.colors['blue']='\033[94m'      
        self.colors['end'] = '\033[0m'

    def cc_text(self, color, text):
        if not color in self.colors:
            print "color " + color + " not defined"
        return self.colors[color] + text + self.colors['end'] 

class cc_msg(c_colors):
    """ prints some beautiful colored messages """
    
    def err(self, msg):
        sys.stdout.write("[" + self.cc_text('red', '*') + "] " + msg)
        
    def warn(self, msg):
        sys.stdout.write("[" + self.cc_text('yellow', '*') + "] " + msg)
        
    def ok(self, msg):
        sys.stdout.write("[" + self.cc_text('green', '*') + "] " + msg)
        
    def prompt(self, prompt, mod_prompt=None):
        if mod_prompt:
            return self.cc_text('blue', '[')  + prompt + self.cc_text('blue', ']') + self.cc_text('blue', ' (') + self.cc_text('red', mod_prompt) + self.cc_text('blue', ')')  + self.cc_text('blue', ' >> ') 
        else:
            return self.cc_text('blue', '[')  + prompt + self.cc_text('blue', ']') + self.cc_text('blue', ' >> ') 

# module parent class
class ipv6module(cmd.Cmd):
    """
    This Class provides the basic deadbeef module api.
    The following functions have to be overwritten:
    * start
    * init_module
    * help
    """
    
    def __init__(self):
        cmd.Cmd.__init__(self)      
        self.cc = cc_msg()
        self.prompt = "dead:beef::"
        self.running = False
        self.valid_parameters = []
        self.required_parameters = []
        self.help_parameters = {}
        self.parameters = {}
        self.thread = None
        self.ruler = ""
        self.doc_header = "Available Commands:\n"
        
        self.parent_pipe, self.child_pipe = Pipe()
        self.buf = RingBuffer(MAX_SCROLLBACK_BUFFER)
        self.init_module()
        
        # automagicaly load saved settings (if available)
        path = os.path.expanduser('~') + "/.deadbeef"
        filename = path + "/" + self.__class__.__name__ + ".cfg"
        if os.path.isfile(filename):
            save_file = open(filename, "r")
            self.parameters = pickle.load(save_file)
    
    # check config fir and return the path
    def __check_cfg_dir(self):
        # mkdir if not exists
        path = os.path.expanduser('~') + "/.deadbeef"
        try:
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else: 
                raise
                
        return path 
    
    # get mac address
    def __get_mac__(self, iface):
        """ get local mac addresss from given interface """

        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, "ifconfig")
            if not os.path.exists(executable):
                continue
            try:
                cmd = 'LC_ALL=C %s %s 2>/dev/null' % ("ifconfig", iface)
                pipe = os.popen(cmd)
            except IOError:
                continue

            for line in pipe:
                words = line.lower().split()
                if "hwaddr" in words:
                    return words[4]
        return None
    
    #write data to file
    def save_to_file(self, filename, data, append=True):
        """ save to file wrapper """
        
        path = self.__check_cfg_dir() + "/" + filename
        
        if append:
            fh = open(path, "a")
        else:
            fh = open(path, "w")            
            
        fh.write(data)
        
        fh.close()

    # log data to pipe
    def log(self, data):
        self.child_pipe.send(data)

    # create new job
    # valid arguments:
    # * cmd = function to call
    # * args = argument for cmd
    # * kwargs = keyword arguments for function
    def add_job(self, **kwargs):
        if not 'cmd' in kwargs.keys():
            self.cc.err("missing cmd argument for add_job function")
            return
        
        t_args = kwargs.get('args', [])
        t_kwargs = kwargs.get('kwargs', {})
        
        self.thread = Process(target = kwargs['cmd'], args = t_args, kwargs = t_kwargs)
        self.thread.start()     
                
        self.is_running()        

    # kill a running job
    def kill_job(self):
        self.thread.terminate()
        self.is_stopped()

    # set module running
    def is_running(self):
        self.prompt = self.prompt[:-7] + self.cc.cc_text('blue', '(') + self.cc.cc_text('green', 'running') + self.cc.cc_text('blue', ') >> ')
        self.running = True         
                        
    # set module stopped
    def is_stopped(self):
        self.prompt = self.prompt[:-41] + self.cc.cc_text('blue', ' >> ')
        self.running = False
    
    def get_pid(self):
        if self.running and self.thread:
            try:
                return self.thread.pid
            except:
                return None
        
        return None
        
    def default(self, line):
        self.cc.err("unknown command. type \"help\" to get a list of available commands.\n")

    def columnize(self, list, displaywidth=80):
        print "    %-20s%s" % ("Name", "Description")
        print "    %-20s%s" % ("----", "-----------")
        for item in list:
            try:
                func = getattr(self, 'help_' + item)
                self.cc.ok("%-20s" % (item ,))
                func()
            except AttributeError:
                print item + " : (no description available)"

    # show module options
    def do_show(self, cmdline):
        """ show available module options """
        
        # Show Module Options
        print "\nModule options:\n"
        
        # header 
        print "    %-20s %-30s %-50s %-10s" % ("Name", "Current Value", "Description", "Required")
        print "    %-20s %-30s %-50s %-10s" % ("----", "-------------", "-----------", "--------")
        
        for cmd in self.valid_parameters:
            
            if cmd in self.required_parameters:
                req = "yes"
            else:
                req = "no"
                
            if cmd in self.parameters.keys():
                if cmd in self.help_parameters.keys():
                    self.cc.ok("%-20s %-30s %-50s %-10s\n" % (cmd, self.parameters[cmd], self.help_parameters[cmd], req))
                else:
                    self.cc.ok("%-20s %-30s %-50s %-10s\n" % (cmd, self.parameters[cmd], "(None)", req))
            else:
                if cmd in self.help_parameters.keys():
                    self.cc.ok("%-20s %-30s %-50s %-10s\n" % (cmd, "(None)", self.help_parameters[cmd], req))   
                else:
                    self.cc.ok("%-20s %-30s %-50s %-10s\n" % (cmd, "(None)", "(None)", req))
        
        print ""

    def help_show(self):
        print "show available options"

    # set options
    def do_set(self, cmdline):
        """ set module options """
        
        try:
            cmd = cmdline.split("=")[0]
            value = cmdline.split("=")[1]
        except IndexError:
            self.cc.err("invalid set syntax (set <option>=<value>)\n")
            return
        
        if not cmd in self.valid_parameters:
            self.cc.err("unknown option: " + cmd + "\n")
        else:
            self.parameters[cmd] = value

    def help_set(self):
        print "set options (syntax: set <option>=<value>)"

    def complete_set(self, text, line, begidx, endidx):
        """ autocompletion for module options """
        
        return [i for i in self.valid_parameters if i.startswith(text)] 
    
    # watch log for module
    def do_watch(self, cmdline):
        self.cc.ok("logged data for this module:\n\n")
        
        while self.parent_pipe.poll():
            self.buf.append(self.parent_pipe.recv())
        
        lines = 20        
        if cmdline:
            lines = int(cmdline)

        for line in list(self.buf.get(lines)):
            self.cc.warn(line)
            
        print ""
    
    def help_watch(self):
        print "watch log for current modules (watch <numlines>, default=20)"
    
    # save setting
    def do_save(self, cmdline):
        # create condif dir if not exist
        path = self.__check_cfg_dir()
        
        # open filename
        filename = path + "/" + self.__class__.__name__ + ".cfg"
        save_file = open(filename, "w")
        pickle.dump(self.parameters, save_file)     
        save_file.close()
        
        self.cc.ok("saved options in file: %s\n" % (filename, ))
        
    def help_save(self):
        print "save module settings (loaded automagicaly at startup)"
        
    # start module execution
    def do_start(self, cmdline):
        for required in self.required_parameters:
            if not required in self.parameters.keys():
                self.cc.err("parameter " + required + " is required but not set.\n")
                return
        
        if self.running:
            self.cc.err("module is already running!\n")
            return
        
        self.start(cmdline)     
                
    def help_start(self):
        print "start module execution"  
        
    def do_stop(self, cmdline):
        if not self.running:
            self.cc.err("module is not started!\n")
            return 
            
        self.stop(cmdline)
        
    def help_stop(self):
        print "stop module execution"
        
    def emptyline(self):
        pass

    # overwrite this        
    def init_module(self):
        pass

    # overwrite this
    def help(self):
        pass
        
    # overwrite this
    def start(self, cmdline):
        pass    
    
    # overwrite this    
    def stop(self, cmdline):
        self.cc.err("Not implemented")
        
    def help_help(self):
        print "show available commands"     
    
    def do_exit(self, cmdline):
        return True
        
    def help_exit(self):
        print "exit current module"
    
    do_back = do_exit
    help_back = help_exit


#The one line Router Advertisement daemon killer
#send(IPv6(src=server)/ICMPv6ND_RA(routerlifetime=0), loop=1, inter=1)
