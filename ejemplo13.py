#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = 'mon0'    ### Just monitor VAP interface (mon0)

def PacketHandler(pkt):
	if pkt.type == 0:  ## Management frame
		destination = '01(MGT)-sub:' + str(pkt.subtype)
		return
	elif pkt.type == 1:  ## Control frames
		destination = '01(CTRL)-sub:' + str(pkt.subtype)
		return
	elif pkt.type == 2:  ## Data frames
		DS = pkt.FCfield & 0x3
		toDS = int(DS & 0x1 != 0)
		fromDS = int(DS & 0x2 != 0)
		destination = '02(DATA)-sub:' + str(pkt.subtype) + ' - DS:' + str(DS) + '-FromDS:' + str(fromDS) + '-ToDS:' + str(toDS)
		if pkt.FCfield & 3 == 0:  ## direct
			## fromDS=0, toDS=0 is a pkt from STA to STA
			# smac,dmac = pkt.addr2 ,  pkt.addr1
			destination=destination + ' STA-STA'
			STA = pkt.addr2
		elif pkt.FCfield & 3 == 1:  ## to DS
			## fromDS=1, toDS=0 is a pkt sent by a station for an AP (destined to the DS)
			# smac,dmac = pkt.addr3 ,  pkt.addr1
			destination=destination + ' STA-DS'
			STA = pkt.addr2
		elif pkt.FCfield & 3 == 2:  ## from DS
			## fromDS=0, toDS=1 is a pkt exiting the DS for a station
			# smac,dmac = pkt.addr2 ,  pkt.addr3
			destination=destination + ' DS-STA'
			STA = pkt.addr1
		elif pkt.FCfield & 3 == 3:  ## WDS
			## fromDS=1, toDS=1 is a pkt from AP to AP (WDS)
			# smac,dmac = pkt.addr4 ,  pkt.addr3
			destination=destination + ' DS-DS'
			STA = pkt.addr1
		else:
			destination=pkt.type
	print pkt.command()
	print "Packet destination: %s" %(destination)

# We begin to sniff and capture
sniff(iface=intfmon, prn=PacketHandler, store=False, lfilter=lambda pkt: (Dot11 in pkt))

