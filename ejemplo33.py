#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import time,sys,datetime,re,csv,os,errno
import ctypes,ctypes.util
import threading
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import logging
import logging.handlers
from netaddr import *
from netaddr.core import NotRegisteredError

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# define variables
intfparent='wlan1'
intfmon='mon0'
workdir='./capture'
csvsummary= workdir + '/' + 'ap_summary.csv'
channel=''

clients = []
uni = 0
mach = []
manuf =''
ap_list = []
ap_plist = []
sysloglevel=4  ## (debug)7------0(not syslog)
first_pass = 1
lock = Lock()
DN = open(os.devnull, 'w')

# Scapy packet handler function
def PacketHandler(pkt):
    global ap_plist, ap_list,csvwriter
    if pkt.haslayer(Dot11):
        if pkt.haslayer(Dot11ProbeReq):  ## probe request
            mac = str(pkt.addr2)
            if pkt.haslayer(Dot11Elt):
                if pkt.ID == 0:
                    ssid = pkt.info
                if ssid and ssid not in clients:
		    manuf = get_oui(mac)
                    clients.append([mac,manuf,ssid])
                    print "CLIENT MAC: %s (%s) PROBING FOR AP: %s" %(mac,manuf,ssid)

        elif pkt.haslayer(Dot11ProbeResp):  ## probe responese
            bssid = pkt.addr3
            if bssid not in ap_plist:
                ap_plist.append(bssid)
                manuf = get_oui(bssid)
                capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                crypto = set()
                p = pkt[Dot11Elt]
                while isinstance(p, Dot11Elt):
                    if p.ID == 0:
                        essid = p.info
                    elif p.ID == 3:
                        if len(p.info) == 1:
                            channel = int(ord(p.info))
                        else:
                            channel=0
                    elif p.ID == 48:
                        crypto.add("WPA2")
                    elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                        crypto.add("WPA")
                    p = p.payload
                if not crypto:
                    if 'privacy' in capability:
                        crypto.add("WEP")
                    else:
                        crypto.add("OPN")

                print "AP ESSID: %s BSSID: %s (%s) ENC: %s CHANNEL: %s - PROBE RESPONSE SAVED!" %(essid,bssid,manuf,' / '.join(crypto),channel)
                filename=workdir + '/' + pkt.info + '_' + bssid.replace(':','') + '.cap'
                writer = PcapWriter(filename, append=True)
                writer.write(pkt)
                writer.close()

        elif pkt.type == 0 and pkt.subtype == 8:  ## beacon
            bssid = pkt.addr3
            if bssid not in ap_list:
                ap_list.append(bssid)
                manuf = get_oui(bssid)
                capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                crypto = set()
                p = pkt[Dot11Elt]
                while isinstance(p, Dot11Elt):
                    if p.ID == 0:		
                        essid = p.info
                    elif p.ID == 3:
                        if len(p.info) == 1:
                            channel = int(ord(p.info))
                        else:
                            channel=0
                    elif p.ID == 48:
                        crypto.add("WPA2")
                    elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                        crypto.add("WPA")
                    p = p.payload
                if not crypto:
                    if 'privacy' in capability:
                        crypto.add("WEP")
                    else:
                        crypto.add("OPN")
		hidden_essid = (not essid)
 		if hidden_essid: essid = 'HiddenEssid!'
                print "AP ESSID: %s BSSID: %s (%s) ENC: %s CHANNEL: %s - BEACON SAVED!" %(essid, bssid, manuf, ' / '.join(crypto), channel)
                filename=workdir + '/' + pkt.info + '_' + bssid.replace(':','') + '.cap'
                writer = PcapWriter(filename, append=True)
                csvwriter.writerow([essid,bssid,manuf,'/'.join(crypto),channel])
                writer.write(pkt) ; writer.close()


def endsniff(d=False):
    return d


def get_oui(mac):
    global manuf
    maco = EUI(mac)
    try:
        manuf = maco.oui.registration().org.replace(',',' ')
    except NotRegisteredError:
        manuf = "Not available"
    return manuf


def ProbeReqBroadcast():
    sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3="ff:ff:ff:ff:ff:ff")/Dot11ProbeReq()/Dot11Elt(ID="SSID", info=""), iface=intfmon, count=10)


def ProbeReq(probessid,dst,bssid):
    src='00:00:de:ad:be:ef'   ## source ip from packets
    dst='ff:ff:ff:ff:ff:ff'   ## Destination address for beacons and probes
    bssid='00:11:22:33:44:55'   ## BSSID MAC address for fake AP
    count=10
    param = Dot11ProbeReq()
    essid = Dot11Elt(ID='SSID',info=probessid, len=len(probessid))
    dsset = Dot11Elt(ID='DSset',info='\x01')
    pkt = RadioTap()/Dot11(type=0,subtype=4,addr1=dst,addr2=src,addr3=bssid)/param/essid/Dot11EltRates()/dsset
    print '[*] 802.11 Probe Request: SSID=[%s], count=%d' % (probessid,count)

    try:
      sendp(pkt,count=count,inter=0.1,verbose=0)
    except:
      raise


def InitMon():
	# Check if monitor device exists
	if not os.path.isdir("/sys/class/net/" + intfmon):
	        if not os.path.isdir("/sys/class/net/" + intfparent):
	                print "WiFi interface %s does not exist! Cannot continue!" %(intfparent)
	                exit()
	        else:
			# create monitor interface using iw
			cmd = 'iw dev %s interface add %s type monitor >/dev/null 2>&1' % (intfparent, intfmon)
			cmd2 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
			try:
				os.system(cmd)
				time.sleep(0.3)
				os.system(cmd2)
			except:
				raise
	else:
	        print "Monitor %s exists! Nothing to do, just continuing..." %(intfmon)


def stop(signal, frame):
    print '  CTRL+C pressed, exiting...'
    endsniff(True)
    sys.exit('Closing')


def LoadAPlist():
    try:
        ifile  = open(csvsummary, "r")
        csvreader = csv.reader(ifile, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONE,escapechar='\\')
        for row in csvreader:
            ap_list.append(row[1])
        ifile.close()
    except Exception, e:
        return


def channel_hop(channel=''):
    global intfmon, first_pass
    channelNum = 0
    err = None

    while 1:
        if channel:
            with lock:
                monchannel = channel
        else:
            channelNum +=1
            if channelNum > 14:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', intfmon, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
            except OSError as e:
                print '['+R+'-'+W+'] Could not execute "iw"'
                os.kill(os.getpid(),SIGINT)
                sys.exit(1)
            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev shouldnt display output unless there's an error
                    err = 'Channel hopping failed: '+ line
        if channel:
            time.sleep(.05)
        else:
            if first_pass == 1:
                time.sleep(1)
                continue

def checkdir(dir):
    try:
        os.makedirs(dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


##### Main loop

# Init monitor mode device
InitMon()

# Check if workdir exists and create it
checkdir(workdir)

# Start channel hopping
hop = Thread(target=channel_hop, args=channel)
hop.daemon = True
hop.start()

# Signal handler init
signal(SIGINT, stop)

# We need a CSV file to save the summary of captured files
LoadAPlist()
ofile  = open(csvsummary, "a")
csvwriter = csv.writer(ofile, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONE,escapechar='\\')

# We begin to sniff and capture
try:
	sniff(iface=intfmon, prn=PacketHandler, stop_filter=endsniff())
except:
	print "Some error avoid sniffing with %s device!" %intfmon

ofile.close()
