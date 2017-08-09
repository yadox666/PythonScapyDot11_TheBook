#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = 'mon0'    ### Just monitor VAP interface (mon0)
mac2search = 'F8:63:94:9A:03:13'   ### BSSID of ap to search or client MAC

def insert_ap(pkt):
	if pkt.haslayer(Dot11Beacon):
		bssid = pkt[Dot11].addr3
		if bssid.upper() == mac2search.upper():
			essid = pkt[Dot11].info
			powervalues=[0,0,0]
			# power = (256 - ord(pkt.notdecoded[-4:-3]))  # Some radiotap headers
			power = (256 - ord(pkt.notdecoded[-2:-1]))  # other radiotap headers like Atheros
			if power > 0 <= 99:
				power = 100 - power
			elif power == 256:
				return  ## corrupt value

			print "ESSID: %s BSSID: %s PWR: %s" %(essid,bssid,power)

sniff(iface=intfmon, prn=insert_ap, store=False, lfilter=lambda pkt: (Dot11 in pkt))

