#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import logging, dpkt
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = "mon0"

def PacketHandler(pkt):
    rawdata = pkt.build()
    tap = dpkt.radiotap.Radiotap(rawdata)

    if hasattr(tap, "ant_sig"):
        signal = -(256 - tap.ant_sig.db)
    else:
        signal = 0

    bssid=pkt.addr3
    essid=pkt.info
    print "BSSID:%s ESSID:%s (%d dBm)" % (bssid, essid, signal)  

sniff(iface=intfmon, prn=PacketHandler, lfilter=lambda p: Dot11Beacon in p)
