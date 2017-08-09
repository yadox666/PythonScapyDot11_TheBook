#!/usr/bin/env python
# -*- coding: utf-8 -*-​
from datetime import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon='mon0'
verbose=0
count=30

dst = bssid = 'ff:ff:ff:ff:ff:ff'
apssid='testAP'
src='00:01:02:03:04:05'
sc=-1
bootime=time.time()

class Dot11EltRates(Packet):
	name = "802.11 Rates Information Element"
	# Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
	supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
	fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
	for index, rate in enumerate(supported_rates):
		fields_desc.append(ByteField("supported_rate{0}".format(index + 1),rate))

def ProbeReq(src,count,apssid,dst,bssid):
	essid = Dot11Elt(ID='SSID',info=apssid, len=len(apssid))
	WPS_ID = "\x00\x50\xF2\x04"
	WPS_Elt = Dot11Elt(ID=221,len=9,info="%s\x10\x4a\x00\x01\x10" % WPS_ID)
	dsset = Dot11Elt(ID='DSset',info='\x01')
	pkt =  RadioTap()/Dot11(type=0,subtype=4,addr1=dst,addr2=src,addr3=bssid)\
	/Dot11ProbeReq()/essid/WPS_Elt/Dot11EltRates()/dsset
	i=0
	while i < count:
		# Update timestamp
		pkt.timestamp = current_timestamp()
		pkt.SC = next_sc()     ## Update sequence number
		if verbose: pkt.show()
		try:
			sendp(pkt,iface=intfmon,count=1,inter=0.1,verbose=verbose)
			i += 1
		except:
			raise


def current_timestamp():
	global bootime
	return (time.time() - bootime) * 1000000

def next_sc():
	global sc
	sc = (sc + 1) % 4096
	return sc * 16  # Fragment number -> right 4 bits


print 'Sending %d 802.11 Probe Request: ESSID=[%s], BSSID=%s' % (count,apssid,bssid)
ProbeReq(src,count,apssid,dst,bssid)
