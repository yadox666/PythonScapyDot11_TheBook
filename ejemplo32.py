#!/usr/bin/python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from collections import defaultdict
from scapy.all import *
from scapy.layers.l2 import eap_types as EAP_TYPES
import sys, argparse
import thread
import subprocess

pcap_file = None
intfmon = 'mon0'
channel = '1'
md5challenge = {}
requser = {}
USER = {}
USERID = {}
USERNAME = {}
UserList = []
checked = []
bssids =  defaultdict(list)
bssids.update({'mac':"00:00:00:00:00:00", 'net':'testing'})

def eapol_header(packet):
	global USERID
	global USER
	global USERNAME
	for pkt in packet:
		get_bssid(pkt)
		try:
			if pkt.haslayer(EAP):
					if pkt[EAP].type==1: # Identified an EAP authentication 
						USERID=pkt[EAP].id
						if pkt[EAP].code == 2:  
							USER=pkt[EAP].identity

					# EAP-MD5 - Credit to EAPMD5crack for logic assistance
					if pkt[EAP].type==4:  # Found EAP-MD5
						EAPID=pkt[EAP].id
						if pkt[EAP].code == 1:   
							md5challenge[EAPID]=pkt[EAP].load[1:17]
							network = bssids[pkt.addr2]
							print " EAP-MD5 Authentication Detected"
							print " SSID:         " + (network)
							print " Auth ID:       " + str(USERID)
							print " User ID:       " + str(USER)
							print " MD5 Challenge: " + md5challenge[EAPID].encode("hex")
							addtolist(USER)
						elif packets[EAP].code == 2:
							md5response[EAPID]=packets[EAP].load[1:17]
							print "MD5 Response:  " + md5response[EAPID].encode("hex")

					# EAP-PEAP		 
					elif pkt[EAP].type==25:  # Found EAP-PEAP
						EAPID=pkt[EAP].id
						if pkt[EAP].code == 2: 
							# reverse as it is the destination mac (Client->Server Identify)
							network = bssids[pkt.addr1] 
							print " EAP-PEAP Authentication Detected"
							print " SSID:         " + (network)
							print" Auth ID:       " + str(USERID)
							print " User ID:       " + str(USER)
							addtolist(USER)

					# EAP-TLS
					elif pkt[EAP].type==1:  # Found EAP-TLS Response Identity
						EAPID=pkt[EAP].id
 						if pkt[EAP].code == 1:
							network = bssids[pkt.addr2]
							USER = str(USER).strip("{}")
							if USER is not '':
								print " EAP-TLS Response ID Detected"
								print " SSID:        " + (network)
								print " Auth ID:      " + str(USERID)
								print " User ID:      " + str(USER)
								addtolist(USER)

					elif pkt[EAP].type==13:  # Found EAP-TLS
				   		EAPID=pkt[EAP].id
 						if pkt[EAP].code == 2:  
							network = bssids[pkt.addr2]
							print " EAP-TLS 2 Authentication Detected"
		except:
			print " Something wasn't able to parse correctly, exection will continue.\n"	

def get_bssid(pkt):
	global bssids
	if pkt.haslayer(Dot11):
		if pkt.type==0 and pkt.subtype==8:
			for item in bssids.values():
				if pkt.info in item:	  
					break
				elif pkt.addr2 in item:
					break
				else:
					bssids.update({pkt.addr2:pkt.info})

def addtolist(USER):
	UserList.append(USER)
	global checked 
	checked = []
	for item in UserList:
		if item not in checked:
			checked.append(item)


def SetChannel(channel):
        cmd0 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
        cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
        try:
                os.system(cmd0)
                os.system(cmd1)
                print "Setting %s to channel: %s" %(intfmon,channel)
        except:
                print "Error setting channel for %s" %intfmon

# Main and EAPOL-HEADER
if pcap_file is not None:
	try:
		print " Searching for EAPOL packets from PCAP", pcap_file
		PCAP_EXTRACTED=rdpcap(pcap_file)
		eapol_header(PCAP_EXTRACTED)
	except:
		print " Issue reading PCAP.\n"
		sys.exit(0)
else:
	try:
		SetChannel(channel)
		print " Sniffing for EAPOL packets on " + intfmon + " channel " + channel + "... Ctrl+C to exit"
		sniff(iface=intfmon, prn=eapol_header)
		print " User requested interrupt, cleaning up monitor interface and exiting...\n"
	except:
		print " Exiting because exception received!"
		sys.exit(0)

print " Unique Harvested Users:" 
print checked
print "\n"	

