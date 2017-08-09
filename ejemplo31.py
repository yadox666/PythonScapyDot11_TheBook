#!/usr/bin/python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_contrib("wpa_eapol")

intfmon='mon0'
apbssid="" ## "00:18:39:AE:88:58"
duration=4  ## authentication nax duration in seconds
workdir = './capture'
filename = workdir +  "/wpa_handshake.cap"
verbose=1

beacons = []
ap_beacon_list = []
wpa_handshakes = {}
WPA_KEY_INFO_INSTALL = 64
WPA_KEY_INFO_ACK = 128
WPA_KEY_INFO_MIC = 256

def PacketHandler(pkt):
	# Got EAPOL KEY packet
        if pkt.haslayer(WPA_key):
                layer = pkt.getlayer (WPA_key)

		# Parse source and destination of packet
		if (pkt.FCfield & 1): 
			station = pkt.addr2  ## packet from station - FromDS=0, ToDS=1
		elif (pkt.FCfield & 2): 
			station = pkt.addr1  ## packet from AP - FromDS=1, ToDS=0
		else:
			return  ## packet from ad-hoc or WDS network
	
                # First, check that the access point is the one we want to target
                bssid = pkt.addr3.upper()
                if apbssid and bssid != apbssid.upper():
                        print "WPA handshake packets of other AP: %s from station: %s" %(bssid,station)
                        return

		if not wpa_handshakes.has_key(station):
			wpa_handshakes[station]= \
			{'ts':time.time(),'frame2': None,'frame3':None,'frame4':None,'replay_counter':None,'packets':[]}
		else:
			if time.time()-duration > wpa_handshakes[station]['ts']:
				wpa_handshakes.pop(station, None) ## Elimina anteriores paquetes
				wpa_handshakes[station] = \
				{'ts':time.time(),'frame2': None,'frame3':None,'frame4':None,'replay_counter':None,'packets':[]}
				if verbose >1: print "Resetting time for station %s" %station

		key_info = layer.key_info
		wpa_key_length = layer.wpa_key_length
		replay_counter = layer.replay_counter

		# check for frame 2
		if ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) \
		and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0)):
			print "Found Handshake packet 2 for AP: %s and station: %s" %(bssid,station)
			wpa_handshakes[station]['ts'] = time.time()
			wpa_handshakes[station]['frame2'] = 1
			wpa_handshakes[station]['packets'].append(pkt)

		# check for frame 3
		elif ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK) \
			and (key_info & WPA_KEY_INFO_INSTALL)):
			print "Found Handshake packet 3 for AP: %s and station: %s" %(bssid,station)
			wpa_handshakes[station]['ts'] = time.time()
			wpa_handshakes[station]['frame3'] = 1
			wpa_handshakes[station]['replay_counter'] = replay_counter  ## store the replay counter for this station
			wpa_handshakes[station]['packets'].append(pkt)

		# check for frame 4
		elif ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) \
			and (key_info & WPA_KEY_INFO_INSTALL == 0) \
			and wpa_handshakes[station]['replay_counter'] == replay_counter):
			print "Found Handshake packet 4 for AP: %s and station: %s" %(bssid,station)
			wpa_handshakes[station]['ts'] = time.time()
			wpa_handshakes[station]['frame4'] = 1
			wpa_handshakes[station]['packets'].append(pkt)

		# Check if all frames present
		if (wpa_handshakes[station]['frame2'] and wpa_handshakes[station]['frame3'] \
			and wpa_handshakes[station]['frame4']):
			print "Saving all packets of WPA handshake for AP: %s and station: %s" %(bssid,station)
			pktdump.write(wpa_handshakes[station]['packets'])
			if wpa_handshakes.has_key(station): wpa_handshakes.pop(station, None)

	elif pkt.haslayer(Dot11Beacon) and not pkt.addr3 in ap_beacon_list:
		if verbose: print pkt.summary()
		pktdump.write(pkt)
		ap_beacon_list.append(pkt.addr3)


# Start sniffing
pktdump = PcapWriter(filename, append=True, sync=True)
print "Sniffing on interface " + intfmon
print "Saving EAPOL packets and 1 beacon frame of each BSSID in: %s" %filename
sniff(iface=intfmon, prn=PacketHandler)
