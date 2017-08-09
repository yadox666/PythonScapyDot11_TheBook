#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex

intfmon='mon0'
ap_list = [ ]

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8: ## beacon frame
			if pkt.addr2 not in ap_list :
				ap_list.append(pkt.addr2)
				essid = pkt.info
				hidden_essid = (not essid)
				if pkt.hasflag('cap', 'privacy'):
					elt_rsn = pkt[Dot11].rsn()
					if elt_rsn:
                   				enc = elt_rsn.enc
						cipher = elt_rsn.cipher
						auth = elt_rsn.auth
					else:
						enc = 'WEP'
						cipher = 'WEP'
						auth = ''
				else:
					enc = 'OPN'
					cipher = ''
					auth = ''

				print "AP MAC: %s with SSID: %s and security: %s %s %s" %(pkt.addr2, essid, enc, cipher, auth)

sniff(iface=intfmon, prn = PacketHandler)

