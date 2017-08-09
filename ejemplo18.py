#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex

intfmon='mon0'
workdir='/tmp'
filename=workdir + '/' + 'ejemplo12.cap'

# Scapy packet handler function
def PacketHandler(pkt):
    global ap_list
    bssid = pkt.addr3
    essid = pkt.info
    print "Saving Probe Response of %s (%s) to file: %s" %(essid,bssid,filename)
    writer = PcapWriter(filename, append=True)
    writer.write(pkt)
    writer.close()

# We begin to sniff and capture
sniff(iface=intfmon, prn=PacketHandler, count=1, lfilter=lambda pkt:(Dot11ProbeResp in pkt))

