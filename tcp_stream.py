from scapy.all import *
from network_stream import NetworkStream
from numpy import *
from entropy import kolmogorov, shannon

#We are assuming:
#1) Its an IP packet
#2) Its an TCP packet
class TCPStream(NetworkStream):
    def __init__(self,pkt): 
        super(TCPStream,self).__init__(pkt)
        self.flags = [pkt.sprintf("%TCP.flags%")]

    def unique_flags(self):
        seen = set()
        for item in self.flags:
            if item not in seen:
                seen.add( item )
            yield item

    def push_flag_ratio(self):
        return len([ f for f in self.flags if 'P' in f ]) / float(len(self.flags))

    def add(self,pkt):
        self.pkt_count += 1
        self.len += pkt.len
        self.inter_arrival_times.append(pkt.time - self.time)
        self.flags.append(pkt.sprintf("%TCP.flags%"))
        self.payload += str(pkt[TCP].payload)
        self.pkt = pkt
    
    def application(self):
       #expand it to a new python module
        if self.payload[0:4] in ["GET ", "POST", "HEAD"]:
            return "http"
        elif self.payload[0:4] in ["220 ","220-","USER"]:
            return "ftp"
        elif self.payload[0:4] in ["220 ", "220-", "HELO", "EHLO",".\n\n"]:
            if self.sport != 21 and self.dport != 21:
                return "smtp"
        elif self.payload[0:4] in ["SSH-"]:
            return "ssh"
        elif self.payload[0:4] in ["* OK"]:
            return "imap"
        elif self.payload[0:4] in ["USER","CAPA","AUTH","+OK "]:
            if self.sport not in (21,194,6667) and self.dport not in (21,194,6667):
                return "pop3"
        elif self.payload[0:4].encode('hex')[0:2] == 'ff':
            hex_payload = self.payload[0:4].encode('hex')
            if hex_payload[2:4] in ('fb','fc','fd','fe'):
                #default command
                next_cmd = 3
                if len(self.payload) > 3 and self.payload[0:4].encode('hex')[0+next_cmd*2:2+next_cmd*2] == 'ff':
                    return "telnet"
        if len(self.payload) >= 4:
            print "unknown",self.sport,self.dport,self.payload[0:4].encode('hex'),repr(self.payload[0:4])

        return "unknown"

