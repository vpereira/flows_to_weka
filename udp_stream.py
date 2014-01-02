from scapy.all import *
import network_stream
from network_stream import NetworkStream
#We are assuming:
#1) Its an IP packet
#2) Its an UDP packet
class UDPStream(NetworkStream):
    def __init__(self,pkt):
       super(UDPStream,self).__init__(pkt)
    def application(self):
       #trust on scapy?
       # exception, because NBTDatagram has one more layer above "RAW"
        if NBTDatagram in self.pkt:
            return "netbios"
        scapy_proto_list = list(self.scapy_dpi(self.pkt))
        if scapy_proto_list:
            #print repr(scapy_proto_list)
            scapy_proto = str(scapy_proto_list[-1]).lower()
            if scapy_proto and scapy_proto != "udp":
                return scapy_proto
        return "unknown"
    def scapy_dpi(self,pkt):
        while pkt.payload:
            pkt = pkt.payload
            yield type(pkt).__name__ 
