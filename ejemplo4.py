#!/usr/bin/env python
# -*- coding: utf-8 -*-​
from scapy.all import *

verbose=0
intfmon='mon0'
ap_list = [ ]  ## list to avoid showing same ap many times

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8:  ## beacon frame
			if pkt.addr3 not in ap_list :
				ap_list.append(pkt.addr2)
				print "Found AP MAC %s with SSID:%s" %(pkt.addr2, pkt.info)
				if verbose >=1: pkt.show()
       		elif pkt.type == 0 and pkt.subtype == 4:   ## probe request
               		if pkt.info != '':   ## broadcast probe request
				print "STA with MAC %s asks for SSID:%s" %(pkt.addr2, pkt.info)
				if verbose >=1: pkt.show()

sniff(iface=intfmon, prn = PacketHandler)
