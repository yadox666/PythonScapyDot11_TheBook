#!/usr/bin/python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon='mon0'

pkt=sniff(iface=intfmon, lfilter=lambda pkt: (Dot11Beacon in pkt),count=1)
print "\n Packet shown with scapy: \n"
pkt[0].show()

import scapy_ex

pkt=sniff(iface=intfmon, lfilter=lambda pkt: (Dot11Beacon in pkt),count=1)
print "\n Packet shown with scapy_ex imported: \n"
pkt[0].show()


