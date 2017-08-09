#!/usr/bin/python
import sys,logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = "mon0"
verbose=1
workdir="./capture"
filename=workdir+"/"+"wepcap.cap"
max_pkts = 50000
pkts = []

# This function will be called for every sniffed packet
def PacketHandler(pkt):
    if pkt.haslayer(Dot11WEP):   ## Got WEP packet?
        pkts.append(pkt)
        if verbose: 
            print "Pkt-%d: %s IV:%s Keyid:%s ICV:%s" %(len(pkts),pkt[Dot11].addr2,str(pkt.iv),str(pkt.keyid),str(pkt.icv))
        if len(pkts) == max_pkts:   ## Got enough packets to crack WEP key? Save to pcap, and exit
	    print "Got %d packets, saving to PCAP file:%s and exiting!" %(max_pkts,filename)  
	    wrpcap(filename, pkts)
	    sys.exit(0)

# Scapy sniffer function
print "Starting sniff on interface %s" %intfmon
sniff(iface=intfmon, prn=PacketHandler)

