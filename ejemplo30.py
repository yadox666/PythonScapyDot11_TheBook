#!/usr/bin/python
# -*- coding: utf-8 -*-​
import sys, os, logging, time
from threading import Thread, Lock
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon='mon0'
count=5
verbose=0
broadcast=’ff:ff:ff:ff:ff:fff’

for ssid in open(sys.argv[1], ‘r’).readlines():
	pkt. = RadioTap() / Dot11(type=0, subtype=4, addr1=broadcast, addr2=RandMAC(), addr3=broadcast) / Dot11ProbeReq ()
	pkt /=  Dot11Elt(ID=0, info=ssid.strip()) / Dot11Elt(ID=1, info=”\x02\x04\x0b\x1” ) / Dot11Elt(ID=3, Info=”\x08”)
	print “Trying SSID %s” %ssid
	ans=srp1(pkt,iface=intfmon,timeout=1)
	if len(ans) > 0:
		print “Discovered ESSID: %s with BSSID: %s” %ans.info(), ans.addr3()
		exit()

