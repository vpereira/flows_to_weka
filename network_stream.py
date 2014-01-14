from scapy.all import *
from numpy import *
from entropy import kolmogorov, shannon

class NetworkStream(object):
    def __init__(self,pkt):
        self.src = pkt.src 
        self.dst = pkt.dst
        self.sport = pkt.sport
        self.dport = pkt.dport        
        self.time = pkt.time
        self.proto = pkt.proto
        self.payload = ""
        self.inter_arrival_times = [0]
        self.pkt_count = 1
        self.len = pkt.len
        if UDP in pkt:
            if pkt[UDP].payload: self.payload = str(pkt[UDP].payload)
        elif TCP in pkt:
            if pkt[TCP].payload: self.payload = str(pkt[TCP].payload)
        self.pkt = pkt

    def avrg_len(self):
        return self.len/self.pkt_count

    def kolmogorov(self):
        return round(kolmogorov(self.payload),4)

    def shannon(self):
        return round(shannon(self.payload),4)

    def avrg_payload_len(self):
        return len(self.payload)/self.pkt_count

    def avrg_inter_arrival_time(self):
        return round(mean(self.inter_arrival_times),4)

    #override it on tcp_stream
    def push_flag_ratio(self):
        return 0.0
    #override it on tcp stream
    def unique_flags(self):
        return  0.0

    def add(self,pkt):
        self.pkt_count += 1
        self.len += pkt.len
        self.inter_arrival_times.append(pkt.time - self.time)
  
        if UDP in pkt:
            if pkt[UDP].payload: self.payload += str(pkt[UDP].payload)
        elif TCP in pkt:
            if pkt[TCP].payload: self.payload += str(pkt[TCP].payload)
  
        self.pkt = pkt
    
    def application(self):
        return "unknown"


    def remove(self,pkt):
        raise Exception('Not Implemented')
