#!/usr/bin/python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon='mon0'
station= client='00:01:00:01:00:01'
bssid='F8:63:94:9A:03:13'
apssid='ONO_E1F1'
broadcast='ff:ff:ff:ff:ff:ff'
client='00:01:00:01:00:01'

# probe request
pkt = RadioTap() /Dot11(addr1=broadcast,addr2=station, addr3=station)/Dot11ProbeReq()/Dot11Elt(ID='SSID', info=apssid, len=len(apssid))
print "\nSending Probe request to AP with name: " + apssid
res = srp1(pkt, iface=intfmon, timeout=2)
if res:
	res.summary()
	print "Got answer from " + res.addr2
else:
	print "Got no answer from " + apssid


# authentication with open system
pkt = RadioTap() /Dot11(subtype=0xb,addr1=bssid, addr2=station, addr3=bssid)/Dot11Auth(algo=0, seqnum=1, status=0)
print "\nSending authentication request to AP wiht BSSID: " + bssid
res = srp1(pkt, iface=intfmon, timeout=2)
if res:
	res.summary()
	print "Got answer from " + res.addr2
else:
	print "Got no answer from " + bssid


# association request
pkt = RadioTap() /Dot11(type=0, subtype=0 , addr1=bssid, addr2=station, addr3=bssid)
pkt /= Dot11AssoReq()/Dot11Elt(ID='SSID', info=apssid)/Dot11Elt(ID="Rates", info="x82x84x0bx16")
print "\nSending Association request to AP with SSID: " + apssid
res = srp1(pkt, iface=intfmon, timeout=2)
if res:
	res.summary()
	print "Got answer from " + res.addr2
else:
	print "Got no answer from " + apssid


# Deauthentication request
pkt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()   ## AP to STA deauth
pkt2 = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()  ## STA to AP deauth
print "\nSending both Deauth requests to AP and STA"
res = srp1(pkt, retry=5, iface=intfmon, timeout=2)
if res:
	res.summary()
else:
	print "Got no answer from Station: " + str(station)

res = srp1(pkt2, iface=intfmon, timeout=2)
if res:
	res.summary()
else:
	print "Got no answer from AP: " + apssid
