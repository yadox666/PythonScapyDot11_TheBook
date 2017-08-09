#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os.path

# wepkey must be 5 chars or 13 chars long!
# wepkey can be introduced in ASCII (12345)
# wepkey can be introduced in HEX ("\x31\x32\x33\x34\x35")
wepkey='12345' 
wepfile="wepcap-01.cap"
savecap=1

if wepkey:
	print "Setting WEP key to: %s" %(wepkey)
	conf.wepkey=wepkey
else:
	print "Please supply WEP key!"

if os.path.isfile(wepfile):
	encryptedpkts=rdpcap(wepfile)
	decryptedpkts=Dot11PacketList(encryptedpkts).toEthernet()
	print "Decrypted %d packets of %d..." %(len(decryptedpkts),len(encryptedpkts))
	if savecap: 
		try:
			wrpcap(wepfile+'.dec.cap',decryptedpkts)
			print "Decryted packets saved to: %s" %wepfile+'.dec.cap'
		except:
			print "Could not save pcap file!"
else:
	print "Please supply a valid WEP pcap file!"
