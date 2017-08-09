#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import os,time, datetime
from datetime import timedelta
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex
from netaddr import *
from netaddr.core import NotRegisteredError

intfmon='mon0'
workdir='/root'  ## directory where the captures pcap are stored
verbose=1
pcounter=0

# Parse information inside beacon frame
def ParsePacket(pkt):
	capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
	elt = pkt[Dot11Elt]
	crypto = set()
	channel=uptime=interval=timestamp=''

	if pkt.haslayer(Dot11Beacon):
		type='Beacon'
		interval = float(pkt.beacon_interval) / 1000   ## Get beacon interval value
		uptime=str(timedelta(microseconds=pkt.timestamp))  ## AP uptime
	elif pkt.haslayer(Dot11ProbeReq):
		type='Probe Request'

	# Get date of captured beacon frame
	capturetime=datetime.datetime.fromtimestamp(float(pkt.time)).strftime('%d-%m-%Y %H:%M:%S')
	while isinstance(elt, Dot11Elt):
		if elt.ID == 0:
			essid = elt.info
		elif elt.ID == 3:
			channel = int(ord(elt.info))
		elif elt.ID == 48:
			crypto.add("WPA2")
		elif elt.ID == 221 and elt.info.startswith('\x00P\xf2\x01\x01\x00'):
			crypto.add("WPA")
		elt = elt.payload

	if not channel:  channel=pkt[RadioTap].Channel

	if not crypto:
		if 'privacy' in capability:
			crypto.add("WEP")
		else:
			crypto.add("OPN")

	# Get packet BSSID and calculate manufacturer
	bssid = pkt.addr2
	mac = EUI(bssid)

	try:
		manuf = mac.oui.registration().org
        except NotRegisteredError:
                manuf = "Not available"

	print "\n%s: BSSID: %s(%s) SSID:%s ENC:%s in Channel:%s captured:[%s] uptime:[%s] Intval: %s" \
     		 %(type, bssid, manuf, essid, ' / '.join(crypto), channel,capturetime,uptime,interval)


# Select AP to use
caplist=[] ; i=0
for file in os.listdir(workdir):
	if file.endswith(".cap"):
		caplist.append(file)
		print "%s. %s" %(i,file)
		i+=1

selected = input("\nSelect file number to use: ")
if not selected in range(0,i):
	print "Sorry wrong index number..."
	exit()

pcapfile = workdir + '/' + caplist[selected]
pktreader = PcapReader(pcapfile)
print pcapfile

# Walk through the PCAP file packets
for pkt in pktreader:
	if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq):
		ParsePacket(pkt)
		if verbose >=1: print "Packet structuret:\n" + pkt.command()
	pcounter +=1

print "\nTotal packets in PCAP file: %d\n" % pcounter
