#! /usr/bin/python
from scapy.all import *
print("SENDING SPOOFED ICMP PACKET...");
IPLayer = IP()
IPLayer.src="10.0.2.7"
IPLayer.dst="10.0.2.8"
ICMPpkt = ICMP()
pkt = IPLayer/ICMPpkt
pkt.show()
send(pkt,verbose=0)
