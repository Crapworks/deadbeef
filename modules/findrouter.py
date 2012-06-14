from deadbeef_modules import ipv6module

from scapy.all import *

# route solicitation module
class ipv6_findrouter_module(ipv6module):
    """
    This Module send a router solicitation packet to get the available routers on the lan
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "router solicitation")                    
        self.valid_parameters = ['iface']
        self.required_parameters = ['iface']
        self.help_parameters['iface'] = "use this interface"

    def help(self):
        print "send router solicitation packets"

    def start(self, cmdline):
        router_solicitation_pkt = IPv6(dst="ff02::1")/ICMPv6ND_RS()
        router_advertisement_pkt = sr1(router_solicitation_pkt, verbose=0, timeout=3)

        if router_advertisement_pkt:
            self.cc.ok("router advertisment received:\n")
            self.cc.ok("src:    " + router_advertisement_pkt.src + "\n")
            self.cc.ok("link:   " + router_advertisement_pkt.lladdr +"\n")
            self.cc.ok("dns:   ")
            try:                
                for dns in router_advertisement_pkt.dns:
                    print dns,                              
            except:
                pass
                
            print ""
                        
            self.cc.ok("prefix: " + router_advertisement_pkt.prefix + "\n")
            
