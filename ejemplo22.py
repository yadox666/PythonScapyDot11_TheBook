#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex

droppedCount=0

def sn(p):
	if p.haslayer(Dot11ProbeReq):
        	if p.Flags is not None:
            		if p.Flags & 64 != 0:
                		droppedCount += 1
		                fcs = 0
            		elif p.Flags & 64 == 0:
		                fcs = 1

        if fcs == 1 and p[Dot11Elt].info != '':
            ssid = p[Dot11Elt].info.decode('utf-8')
            ssid = re.sub("\n", "", ssid)
	    print "Probe Request: %s with fcs: %d" %(ssid, fcs)

cap=sniff(prn=sn,offline='proberequest.cap')

