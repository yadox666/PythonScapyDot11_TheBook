#!/usr/bin/python
# -*- coding: utf-8 -*-​
import sys, logging
import logging.handlers
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon='mon0'  ## monitor mode interface
intfmain='wlan0'  ## interface in managed mode connected to wifi APs
channel=8  ## default channel
bssid='00:18:39:AE:88:58'  ## your AP MAC address
macprotectlist=['12:93:2B:34:85:EE']   ## MAC addresses of your AP and clients
ssidprotect='MySSID'
notify=1  ## try to notify on gnome, dependent of libnotify
savecap=1  ## will save captured packets from attack
logging=1  ## will log to syslog
filename='/tmp/attack_pkts.cap' ## directory and file name to save captured packets
verbose=1
pktlist=set()
duration=6  ## attack duration in seconds to avoid be notified again
lastdeauth=lastassoc=lastauth=time.time()-duration
pktssaved=set()
macprotectlist.append(bssid)
[x.upper() for x in macprotectlist]  ## convert all MAC addreses to upercase

if notify:
	try:
		import gi
		gi.require_version('Notify', '0.7')
		from gi.repository import Notify
		Notify.init("WiFi Alert!")
	except:
		notify=0

def PacketHandler(pkt):
	global lastdeauth,lastassoc,lastauth,pktssaved,duration,savecap,risk

	if pkt.haslayer(Dot11Deauth):
		if (pkt.addr1.upper() in macprotectlist or pkt.addr2.upper() in macprotectlist or pkt.addr3.upper() in macprotectlist) and time.time() > (lastdeauth+duration):
			lastdeauth=time.time()
			if pkt.sprintf("%Dot11Deauth.reason%").startswith('class3-from-nonass'): risk="RISK: HIGH!\n"
			message=pkt.sprintf("Deauth detected! \n from: %Dot11.addr1% \n to: %Dot11.addr2% \n Reason: %Dot11Deauth.reason%\n")+risk
			if notify: notifypopup(message)
			if verbose: print message
			if logging: slogger.critical('WIFIMON:'+ message)
			if savecap: 
				try:
					writer = PcapWriter(filename, append=True)
					writer.write(pkt)
					writer.close()
				except:
					savecap=0

	elif pkt.haslayer(Dot11AssoReq):
		if (pkt.addr1.upper() in macprotectlist and not pkt.addr2.upper() in macprotectlist) and time.time() > (lastassoc+duration):
			lastassoc=time.time()
			risk="RISK: MEDIUM \n"
			message=pkt.sprintf("Association detected! \n Client %Dot11.addr2%  \n AP: %Dot11Elt.info% \n BSSID: %Dot11.addr1% \n ")+risk
			if notify and time.time() > (lastauth+duration): notifypopup(message)
			if verbose: print message
			if logging: slogger.warn('WIFIMON:'+ message)
			if savecap: 
				try:
					writer = PcapWriter(filename, append=True)
					writer.write(pkt)
					writer.close()
				except:
					savecap=0

	elif pkt.haslayer(Dot11Auth):
		if (pkt.addr1.upper() in macprotectlist and not pkt.addr2.upper() in macprotectlist) and time.time() > (lastauth+duration):
			lastauth=time.time()
			risk="RISK: MEDIUM \n"
			message=pkt.sprintf("Authentication detected! \n Client: %Dot11.addr2% \n AP: %Dot11.addr1% \n")+risk
			if verbose: print message
			if notify and time.time() > (lastassoc+duration): notifypopup(message)
			if logging: slogger.warn('WIFIMON:'+ message)
			if savecap: 
				try:
					writer = PcapWriter(filename, append=True)
					writer.write(pkt)
					writer.close()
				except:
					savecap=0

	elif pkt.haslayer(Dot11ProbeResp):   ### ojo
		if pkt.info():
			if not ssidprotect or ssidprotect != pkt.info(): return
		if (pkt.addr3.upper() in macprotectlist) and time.time() > (lastproberesp+duration):
			lastproberesp=time.time()
			risk="RISK: HIGH \n"
			message=pkt.sprintf("A possible FAKEAP detected! \n Client: %Dot11.addr2% \n AP: %Dot11.addr1% \n")+risk
			if verbose: print message
			if notify and time.time() > (lastproberesp+duration): notifypopup(message)
			if logging: slogger.warn('WIFIMON:'+ message)
			if savecap: 
				try:
					writer = PcapWriter(filename, append=True)
					writer.write(pkt)
					writer.close()
				except:
					savecap=0

def SetChannel(channel):
        cmd0 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
        cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
        try:
                os.system(cmd0)
                os.system(cmd1)
                if verbose: print "Setting %s to channel: %s" %(intfmon,channel)
        except:
                if verbose: print "Error setting channel for %s" %intfmon
		if logging: slogger.debug("Error setting channel for %s" %intfmon)

def notifypopup(message):
	try:
		popup=Notify.Notification.new('WiFi Alert:', message, "dialog-alert")
		popup.show()
	except:
		pass


# Start syslog handler
try:
	if logging:
		slogger = logging.getLogger('OBJLogger')
		slogger.setLevel(logging.ERROR)
		shandler = logging.handlers.SysLogHandler(address = '/dev/log')
		slogger.addHandler(shandler)
except:
	logging=0

# Start sniffer
if type(channel)=='int': channel=str(channel)
if channel: SetChannel(channel)

if savecap: print "Capture option enabled: saved cap stored in: %s" %(filename)
if logging: slogger.debug("WIFIMON: Starting scanning proccess in %s." %intfmon)

if verbose: print "Looking for suspicious packets in channel %s" %channel
sniff(iface=intfmon, prn=PacketHandler, store=False, lfilter=lambda pkt:Dot11 in pkt)
