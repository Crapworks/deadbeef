from deadbeef_modules import ipv6module

from scapy.all import *

# router advertisment module
class ipv6_discover_module(ipv6module):
    """
    This Module sends a multicast icmpv6 echo request to get all active ipv6 nodes on the lan
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "node discovery")                     
        self.valid_parameters = ['iface']
        self.required_parameters = ['iface']
        self.help_parameters['iface'] = "use this interface"

    def help(self):
        print "discover all active ipv6 nodes on the network"
        
    def start(self, cmdline):
        conf.iface6=self.parameters['iface']
        icmpv6_multicast = IPv6(dst="ff02::1")/ICMPv6EchoRequest()
        icmpv6_answers=sr(icmpv6_multicast, multi=1,timeout=3, verbose=0)
            
        for nodes in icmpv6_answers[0]:
            self.cc.ok(nodes[1][IPv6].src + "\n")
