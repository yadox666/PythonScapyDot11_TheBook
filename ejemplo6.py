#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging,os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
	from scapy.all import *
except ImportError:
        logging.warning('Scapy not installed. Please install it!')
	exit(-1)

if os.geteuid() != 0:
	exit("You need to be root to run this script!")

intfmon='mon0'
aps = {}

def PacketHandler(pkt):
	bssid = pkt[Dot11].addr3
	if bssid in aps:
		return

	p = pkt[Dot11Elt]
	("{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
	crypto = set()
	cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
	while isinstance(p, Dot11Elt):
		if p.ID == 0:
			essid = p.info
		elif p.ID == 3:
			channel = ord(p.info)
		elif p.ID == 48:
			crypto.add("WPA2")
		elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
			crypto.add("WPA")
		p = p.payload
	if not crypto:
		if 'privacy' in cap:
			crypto.add("WEP")
		else:
			crypto.add("OPN")
	print "NEW AP: %r [%s], channel %d, %s" % (essid, bssid, channel, ' / '.join(crypto))
	aps[bssid] = (essid, channel, crypto)

sniff(iface=intfmon, prn=PacketHandler, store=False,lfilter=lambda pkt: (Dot11Beacon in pkt or Dot11ProbeResp in pkt))
