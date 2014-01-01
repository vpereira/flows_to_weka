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
        if DNS in self.pkt: 
            return "dns"
        if NBTDatagram in self.pkt:
            return "netbios"
        return "unknown"
