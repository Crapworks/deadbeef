from deadbeef_modules import ipv6module

import re
import time

from scapy.all import *

# somfy udp traffic analyser
class ipv6_somfy_module(ipv6module):
    """
    Somfy UDP traffic analyse toolkit
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "somfy")                       
        self.valid_parameters = ['iface']
        self.help_parameters['iface'] = "use this interface"
        self.required_parameters = ['iface']
        
    def help(self):
        print "analyse somfy udp traffic"

    def generate_payload(self,  orig, fieldname,  value):
        packet = orig
        packet[fieldname] = value
        return "%s#%s#%s#%s/%s%%%s" % (packet['type'], packet['serial'], packet['timestamp'], packet['const'], packet['incremental'], packet['checksum'])

    def __tcp_callback(self, pkt):      
        dst = pkt.getlayer("IP").dst
        src = pkt.getlayer("IP").src
            
        if pkt.getlayer("Raw"):
            payload = pkt.getlayer("Raw").load      
        else :
            return
            
        ### PONG#0201-0669-1699#1295963414#20/334%2B8AE917C9C4D0630D3728A41C58205167D6674E
        ### OPEN#0201-0669-1699#1296137642/528%0C3C71757A579298861266D68C01D24C40A06548
        regex = re.compile(r'^(?P<type>PONG|PING|OPEN)#(?P<serial>.*)#(?P<timestamp>.*)(?#.*)/(?P<incremental>.*)%(?P<checksum>.*)$')
        match = regex.match(payload)
        if match:
            data = match.groupdict()
            asctime = time.asctime(time.localtime(int(data['timestamp'])))
            self.cc.ok("%s -> %s [%s] PIN: %s Timestamp: %s [%s] ID: %s [Checksum:%s]\n" % (src,  dst,  data['type'],  data['serial'],  data['timestamp'], asctime,  data['incremental'], data['checksum']))
            #if data['type'] == 'PING':
            #    self.cc.ok('got PING packet: replaying...\n')
            #    conf.iface="eth3"
            #    new_pkt = Ether()/IP(dst=dst)/UDP(sport=pkt[UDP].sport,  dport=pkt[UDP].dport)/Raw(load=self.generate_payload(data,  'incremental', str(int(data['incremental']) + 1)))
            #    sendp(new_pkt,  inter=0,  loop=10, verbose=0)
        else:
            self.cc.warn("no match\n")
    def start(self, cmdline):
        self.cc.ok("waiting for somfy udp traffic...\n")        
        sniff(prn=self.__tcp_callback, filter="udp and port 18888", iface=self.parameters['iface'])
