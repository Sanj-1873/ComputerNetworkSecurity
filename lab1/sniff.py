#!/usr/bin/python
from scapy.all import *
print("SNIFFING PACKETS...");
def print_pkt(pkt):
	pkt.show()
pkt = sniff(filter='tcp and (src host 10.0.2.7 and dst port 23)', prn=print_pkt)
