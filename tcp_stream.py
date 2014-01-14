from scapy.all import *
from network_stream import NetworkStream
from numpy import *
from entropy import kolmogorov, shannon
from application_detection import ApplicationDetection

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
        super(TCPStream,self).add(pkt)
        self.flags.append(pkt.sprintf("%TCP.flags%"))

    def application(self):
       appd = ApplicationDetection()
       app = appd.detect(self)
       if app:
           return app
       return "unknown"
