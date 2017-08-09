#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex

intfmon = 'mon0'    ### Just monitor VAP interface (mon0)
mac2search = '98:fc:11:b5:3c:b4'   ### BSSID of ap to search or client MAC
showall=True  ## show all APs (True or False)
avgcache=10    ### Number of elements to keep in cache for average calculation
maxpower=0  ; minpower=100 ; avgpower=0 ; avglist=[] ; essid='' ; channel=0

def PacketHandler(pkt):
	if pkt.haslayer(Dot11Beacon):
		bssid = pkt[Dot11].addr3
		if bssid.upper() == mac2search.upper() or showall:
			essid = pkt[Dot11].essid()
			channel = pkt[Dot11].channel() or pkt[RadioTap].Channel
			rates = pkt[Dot11].rates()
			powervalues=[0,0,0]
			if pkt[RadioTap].dBm_AntSignal:
				power = 100 - abs(int(pkt[RadioTap].dBm_AntSignal))
				powervalues=calcavg(power)
			else:
				return
			print "ESSID: %s BSSID: %s RATES: %s PWR: %s(%s<%s>%s)" \
			       %(essid,bssid,rates,power,powervalues[0],powervalues[1],powervalues[2])

def calcavg(power):
	# avg function
	global maxpower, minpower, avgpower, avglist
	if len(avglist) >= avgcache: avglist.pop(0)
	avglist.append(power)
	avgpower = sum(avglist) / len(avglist)
	if power > maxpower: maxpower = power
	if power < minpower: minpower = power
	return [ minpower, avgpower, maxpower ]

sniff(iface=intfmon, prn=PacketHandler, store=False,lfilter=lambda pkt: (Dot11 in pkt))
