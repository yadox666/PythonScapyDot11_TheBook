#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon='mon0'
verbose=1
count=30

dst = 'ff:ff:ff:ff:ff:ff'
apssid='testAP'
bssid = src = '00:01:02:03:04:05'
apsecurity='wpa2'


if apsecurity == 'wep':
	beacon = Dot11Beacon(cap='ESS+privacy')
	rsn=''
elif apsecurity == 'wpa':
	beacon = Dot11Beacon(cap='ESS+privacy')
	rsn = Dot11Elt(ID='RSNinfo', info=(
	'\x01\x00'              # RSN Version 1
	'\x00\x0f\xac\x02'      # Group Cipher Suite : 00-0f-ac TKIP 
	'\x02\x00'              # 2 Pairwise Cipher Suites (next two lines)
	'\x00\x0f\xac\x04'      # AES Cipher
	'\x00\x0f\xac\x02'      # TKIP Cipher
	 '\x01\x00'              # 1 Authentication Key Managment Suite (line below)
	'\x00\x0f\xac\x02'      # Pre-Shared Key
	'\x00\x00'))            # RSN Capabilities (no extra capabilities)
elif apsecurity == 'wpa2':
	beacon = Dot11Beacon(cap='ESS+privacy')
	rsn = Dot11Elt(ID='RSNinfo', info=(
	 '\x01\x00'              # RSN Version 1
	 '\x00\x0f\xac\x02'      # Group Cipher Suite : 00-0f-ac TKIP 
	 '\x02\x00'              # 2 Pairwise Cipher Suites (next two lines)
	 '\x00\x0f\xac\x04'      # AES Cipher
	 '\x00\x0f\xac\x02'      # TKIP Cipher
	 '\x01\x00'              # 1 Authentication Key Managment Suite (line below)
	 '\x00\x0f\xac\x02'      # Pre-Shared Key
	 '\x00\x00'))            # RSN Capabilities (no extra capabilities)
else:
	rsn=''
	beacon=Dot11Beacon(cap='ESS')


essid  = Dot11Elt(ID='SSID',info=apssid, len=len(apssid))
dsset  = Dot11Elt(ID='DSset',info='\x01')
tim    = Dot11Elt(ID='TIM',info='\x00\x01\x00\x00')
rates  = Dot11Elt(ID='Rates',info="\x03\x12\x96\x18\x24\x30\x48\x60")

pkt = RadioTap()/Dot11(proto=0,type=0,subtype=8,addr1=dst,addr2=src,addr3=bssid)/beacon/essid/rsn/rates/dsset/tim

if verbose: print 'Sending %d frames (802.11 Beacon) with SSID=[%s], BSSID=%s, SEC=%s' % (count,apssid,bssid,apsecurity)
if verbose: print pkt.command() 

try:
	sendp(pkt,iface=intfmon,count=count,inter=0.100,verbose=1)
except:
	raise

