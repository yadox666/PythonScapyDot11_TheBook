#!/usr/bin/python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex

intfmon='mon0'
verbose=2

def PacketHandler(pkt):
	if pkt[Dot11].hasflag('type','Data'):
		if pkt[Dot11].hasflag('FCfield', 'to-DS'):
			active_mode = pkt[Dot11].hasflag('FCfield', 'pw-mgt')
			if active_mode:
				if verbose: print "Packet in active mode from client: %s and bssid: %s" %(pkt.addr2, pkt.addr3)
				if verbose > 1: pkt.show()

sniff(iface=intfmon, prn=PacketHandler, lfilter=lambda p:(Dot11 in p))
