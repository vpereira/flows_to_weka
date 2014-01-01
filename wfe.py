#!/usr/bin/env python
import sys
import hashlib
from hashlib import md5
from scapy.all import *
from tcp_stream import TCPStream
from udp_stream import UDPStream

import argparse

#to test:
#add for every tcp flag a counter. accumulate it per flow
#do a chi square test to see if the number of flags are related with a protocol
#ex:
#http://hsc.uwe.ac.uk/dataanalysis/quantinfasschi.asp


def create_forward_flow_key(pkt):
    return "%s:%s->%s:%s:%s"%(pkt.src,pkt.sport,pkt.dst,pkt.dport,pkt.proto)
def create_reverse_flow_key(pkt):
    return "%s:%s->%s:%s:%s"%(pkt.dst,pkt.dport,pkt.src,pkt.sport,pkt.proto)
def create_flow_keys(pkt):
    return create_forward_flow_key(pkt),create_reverse_flow_key(pkt)

def lookup_stream(key,reverse_key):

    if key in flows.keys():
        return key,flows[key]
    elif reverse_key in flows.keys():
        return reverse_key,flows[reverse_key]
    else: 
        return key,None


parser = argparse.ArgumentParser(description='Process a pcap file, generating the flows and output it as arff or csv')
parser.add_argument('-i',help="pcap file to be readin",required=True)
parser.add_argument('-o',help="output file to be written")
parser.add_argument('-t',help="type of output arff or csv",default='arff',choices=['arff','csv'])
#parser.add_argument("-d", help="run DPI", action="store_true")
args = parser.parse_args()


pcap_file = args.i
output_type = args.t

flows = {}

attrs = ['src','sport','dst','dport','proto','push_flag_ratio','average_len','average_payload_len','pkt_count','flow_average_inter_arrival_time','kolmogorov','shannon']

#TODO check if its possible to pack it again in the original class, that we are able to call .conversations() on this array

myreader = PcapReader(pcap_file)
#use iterator
for pkt in myreader:
     if IP not in pkt: continue
     if pkt.proto not in (6,17): continue
     flow_tuple = reverse_flow_tuple = key_to_search = None
     flow_tuple,reverse_flow_tuple = create_flow_keys(pkt[IP])
     flow_key,network_stream = lookup_stream(flow_tuple,reverse_flow_tuple)

     if network_stream is None:
         if pkt.proto == 6:
             network_stream = TCPStream(pkt[IP])
         else:
             network_stream = UDPStream(pkt[IP])
     else:
       network_stream.add(pkt[IP])

     flows[flow_key] = network_stream

if output_type == "arff":
    print "@relation protocol_detection"
    print "@attribute protocol-name"

    for attr in attrs:
        if attr in ['pkt_count','average_len','flow_average_inter_arrival_time','push_flag_ratio','average_payload_len','kolmogorov','shannon']:
            print "@attribute",attr,"numeric"
        else:
            print "@attribute",attr,"string"
    print "@data"
else:
    attrs.insert(0,"protocol_name")
    print ','.join(attrs)

for flow in flows.values():
    print "%s,%s,%s,%s,%s,%s,%.3f,%s,%s,%s,%s,%s,%s"%(flow.application(),flow.src,flow.sport,flow.dst,flow.dport,flow.proto,flow.push_flag_ratio(),flow.avrg_len(),flow.avrg_payload_len(),flow.pkt_count,flow.avrg_inter_arrival_time(),flow.kolmogorov(),flow.shannon())
