#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import os,time, datetime
from datetime import timedelta
import logging
import logging.handlers
from netaddr import *
from netaddr.core import NotRegisteredError
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# define variables
intfmon='mon0'
workdir='./capture'   ## directory where cap files are stored
number2send=1000   ## number of packets to send after selecting AP
verbose=1  ## verbosity level (0-4)

modify_header=False  ## Insert a new radiotap header or use original
boottime = time.time()   ## to generate uptime or timestamp
sc = -1     ## first frame sequence counter
channel='1'  ## default channel to use
interval=0.1
pcounter=0
bssid = ''
essid = ''
capability=''
crypto = []
essid = ''
capturetime=''
uptime=''
manuf=''


def SetChannel(channel):
  cmd = '/usr/sbin/iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
  try:
    os.system(cmd)
  except:
    raise


def current_timestamp():
    global bootime
    return (time.time() - boottime) * 1000000


def next_sc():
    global sc
    sc = (sc + 1) % 4096
    temp = sc
    return temp * 16  # Fragment number -> right 4 bits


def get_radiotap_header():
    global channel
    radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + chr(channel) + '\xc0\x00\xc0\x01\x00\x00')
    return radiotap_packet


# Parse information inside beacon frame
def ParseBeacon(p):
    global capability,crypto,essid,channel,interval,capturetime,uptime,bssid,manuf

    # Get packet encryption and RSN
    capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    crypto = set()
    elt = p[Dot11Elt]
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
    if not crypto:
        if 'privacy' in capability:
            crypto.add("WEP")
        else:
            crypto.add("OPN")

    # Get beacon interval value
    interval = float(p.beacon_interval) / 1000

    # Get date of captured beacon frame and AP uptime
    capturetime=datetime.datetime.fromtimestamp(float(p.time)).strftime('%d-%m-%Y %H:%M:%S')
    uptime=str(timedelta(microseconds=p.timestamp))

    # Get packet BSSID and calculate manufacturer
    bssid = p.addr2
    manuf = get_oui(bssid)


def get_oui(mac):
    global manuf
    maco = EUI(mac)
    try:
        manuf = maco.oui.registration().org.replace(',',' ')
    except NotRegisteredError:
        manuf = "Not available"
    return manuf


# Show information inside beacon
def ShowBeacon(p):
    global capability,crypto,essid,channel,interval,capturetime,uptime,bssid,manuf

    if verbose >= 1:
	    print("\nScapy command to gen packet:")
	    print p.command()

    if verbose >= 2:
	    print("\nPacket structure:")
	    p.show()

    if verbose >= 3:
	    print("\nFields parsed in the frame:")
	    ls(p)

    if verbose >= 3:
	    print("\nHexdump of frame:")
	    hexdump(p)

    if verbose >= 4:
	    print("\nOpening Wireshark...")
	    wireshark(p)

    print "\nGoing to send %s beacons for BSSID: %s (%s) SSID: %s ENC: %s in Channel: %s [%s][%s] Intval: %s" \
          %(number2send, bssid, manuf, essid, ' / '.join(crypto), channel,capturetime,uptime,interval)
    raw_input("\nPress enter to start\n")


# Send beacon frame n times
def SendBeacon(p):
    global intfmon,interval,number2send
    SetChannel(channel)
    sendp(p, iface=intfmon, inter=interval, count=number2send)


# Update beacon fields with new generated ones
def ModifyBeacon(p):
    # Update sequence number
    p.SC = next_sc()

    # Update timestamp
    p.timestamp = current_timestamp()

    # Insert new radiotap header?
    if modify_header:
        p=get_radiotap_header()/p.payload
	if verbose >=2:
	        print("\nmodified header:")
	        print p.command()
    return(p)


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


######## Main loop
# Select AP to use
caplist=[]
i=0

try:
	for file in os.listdir(workdir):
	    if file.endswith(".cap"):
	        caplist.append(file)
	        print "%s. %s" %(i,file)
	        i+=1
except:
	print "No files or directory found, exiting!"
	exit()

selected = input("\nSelect file number to use: ")
pcapfile = workdir + '/' + caplist[selected]
pktreader = PcapReader(pcapfile)
print "Reading capture file: %s" %pcapfile

# Init monitor mode (if necessary)
InitMon()

# Walk through the PCAP file packets
for p in pktreader:
    if p.haslayer(Dot11Beacon):
        ParseBeacon(p)
        if modify_header and verbose >=2:
		print("\noriginal packet:")
	        print p.command()
        ModifyBeacon(p)
        ShowBeacon(p)
        SendBeacon(p)
	quit()
    elif  p.haslayer(Dot11ProbeResp):
        # ParseProbeResp(p)
        break
    pcounter+=1

# No result of packet parsing
print "\nNo valid packets in capture file: %s" %pcapfile

