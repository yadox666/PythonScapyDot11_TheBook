#!/usr/bin/python
# -*- coding: utf-8 -*-​
import threading, os, time, sys
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

intfmon = 'mon0'    ### Just monitor VAP interface (mon0)
httpport=8000  ## port number for http server
avgcache=10    ### Number of elements to keep in cache for average calculation
atheros=False   ## Using Atheros chipset
verbose=0   ## verbosity

pfile='my.json'
if not atheros: import scapy_ex  ## scapy_ex does not parse well with Atheros cards
maxpower=0  ; minpower=100 ; avgpower=0 ; avglist=[] ; essid='' ; channel=0
aps=[ ]  ## list to store aps
first_pass=1
lock = Lock()
DN = open(os.devnull, 'w')
i=0

def insert_ap(pkt):
	global i
        bssid = pkt[Dot11].addr3
        if any(bssid in sublist for sublist in aps):
                return
        elt = pkt[Dot11Elt]
        ("{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        crypto = set()
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        while isinstance(elt, Dot11Elt):
                if elt.ID == 0:
                        essid = elt.info
                elif elt.ID == 3:
                        channel = ord(elt.info)
                elif elt.ID == 48:
                        crypto.add("WPA2")
                elif elt.ID == 221 and elt.info.startswith('\x00P\xf2\x01\x01\x00'):
                        crypto.add("WPA")
                elt = elt.payload
        if not crypto:
                if 'privacy' in cap:
                        crypto.add("WEP")
                else:
                        crypto.add("OPN")
        print "%d. AP: %r [%s], channel %d, %s" % (i,essid, bssid, channel, ' / '.join(crypto))
	i+=1
        aps.append([bssid, essid, channel, '/'.join(crypto)])


def PacketHandler(pkt):
    # global radiotap_formats,essid, channel
    if pkt[Dot11].addr3 and (Dot11Beacon in pkt or Dot11ProbeResp in pkt):
        bssid = pkt[Dot11].addr3.upper()
        if bssid == mac2search.upper() and not bssid == 'ff:ff:ff:ff:ff:ff':
            if pkt.type == 0:
                if not atheros:   ## parsing with scapy_ex
                   essid = pkt[Dot11].essid()
                   if not essid: essid = 'Hidden'
                   channel = pkt[Dot11].channel() or pkt[RadioTap].Channel
                   rates = pkt[Dot11].rates()
                   rates.extend(pkt[Dot11].extended_rates())
                   crypto=[]
                   if pkt.hasflag('cap', 'privacy'):
                      elt_rsn = pkt[Dot11].rsn()
                      if elt_rsn:
                          enc = elt_rsn.enc
                          cipher = elt_rsn.cipher
                          auth = elt_rsn.auth
                      else:
                          enc = 'WEP'
                          cipher = 'WEP'
                          auth = ''
                   else:
                      enc = 'OPN'
                      cipher = ''
                      auth = ''
                   crypto=[enc,cipher,auth]
                   preffix=' ESSID: ' + essid + ' (' + enc + '/' + cipher + '/' + auth + ')' + ' in channel: ' + str(channel)

                else:  ## Atheros parsing without scapy_ex
                   if not pkt.haslayer(Dot11Elt): return
                   rates = []
                   p = pkt[Dot11Elt]
                   essid, channel = '', ''
                   crypto = set()
                   ("{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
                   cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                   while isinstance(p, Dot11Elt):
                       if p.ID == 0:
                          essid = p.info
                       elif p.ID == 1:
                          rates = str(p.info)
                       elif p.ID == 50:
                          exrates = p.info
                          rates = rates + exrates
                       elif p.ID == 3:
                          if len(p.info) == 1: channel = ord(p.info)
                       elif p.ID == 48:
                          crypto.add("WPA2")
                       elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                          crypto.add("WPA")
                       p = p.payload
                   if not crypto:
                      if 'privacy' in cap:
                          crypto.add("WEP")
                      else:
                          crypto.add("OPN")
                if not essid: essid = 'Hidden'
                if rates:
                   max_rate = max(rates)
                preffix=' ESSID: ' + essid + ' (' + '/'.join(crypto) + ')' + ' in channel: ' + str(channel) # + ' RATES: ' + str(rates)

            powervalues=[0,0,0]

	    if atheros:
                # pkt[RadioTap].show()
                # power = -(256 - ord(pkt.notdecoded[-4:-3]))  # Some radiotap headers
		power = (256 - ord(pkt.notdecoded[-2:-1]))  # other radiotap headers like Atheros
                if power > 0 <= 99:
			power = 100 - power
                        powervalues=calcavg(power)
                elif power == 256:
                        power = 0
            else:
                if pkt[RadioTap].dBm_AntSignal:
                    power = 100 - abs(int(pkt[RadioTap].dBm_AntSignal))
                    powervalues=calcavg(power)
                else:
		    power = 0

            if verbose: print "Packet: %s BSSID: %s SIGNAL: %s(%s<%s>%s)" %(preffix,bssid,power,powervalues[0],powervalues[1],powervalues[2])

	    ofile  = open(pfile, "w")
	    ofile.write('%03d\n' % powervalues[1])
	    ofile.close()

def calcavg(power):
	# avg function
	global maxpower, minpower, avgpower, avglist
	if len(avglist) >= avgcache: avglist.pop(0) 
	avglist.append(power)
	avgpower = sum(avglist) / len(avglist)
	if power > maxpower: maxpower = power
	if power < minpower: minpower = power
	return [ minpower, avgpower, maxpower ]

def channel_hop(channel=None):
        global intfmon, first_pass
        channelNum=0
        err = None
        while 1:
                if channel:
                        with lock: monchannel = channel
                else:
                        channelNum +=1
                        if channelNum > 14: channelNum = 1
                        with lock: first_pass = 0
                        with lock: monchannel = str(channelNum)
                try:
                        proc = Popen(['iw', 'dev', intfmon, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
                except OSError:
                        print 'Could not execute iw!'
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

def SetChannel(channel):
        cmd = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
        try:
                os.system(cmd)
                print "Setting %s to channel: %s (%s)" %(intfmon,channel,remote)
        except:
                print "Error setting channel for %s" %intfmon


#### Main
## Start SimpleHTTP server in a thread
HandlerClass = SimpleHTTPRequestHandler
ServerClass  = BaseHTTPServer.HTTPServer
Protocol     = "HTTP/1.0"
server_address = ('127.0.0.1', httpport)

HandlerClass.protocol_version = Protocol
httpd = ServerClass(server_address, HandlerClass)
sa = httpd.socket.getsockname()
thread = threading.Thread(target = httpd.serve_forever)
thread.daemon = True

try:
	# Start channel hopping
	channelseq=''
	hop = Thread(target=channel_hop, args=channelseq)
	hop.daemon = True
	hop.start()

	# Start sniffing for first pass
	print "Scanning for Wi-Fi APs... Press CTRL+C to stop..."
	sniff(iface=intfmon, prn=insert_ap, store=False,timeout=10000,lfilter=lambda pkt: (Dot11Beacon in pkt or Dot11ProbeResp in pkt))

except KeyboardInterrupt:
	raise

try:
	hop = None
	selected = input("\nSelect AP number to use: ")
	mac2search =  aps[selected][0]
	essid =  aps[selected][1]
	channel = aps[selected][2]
	crypto = aps[selected][3]

	# Start HTTP server
	print "Serving HTTP on", sa[0], "port", sa[1], "..."
	thread.start()

	# Start final sniffing
	SetChannel(channel)
	sniff(iface=intfmon, prn=PacketHandler, store=False,lfilter=lambda pkt:(Dot11 in pkt))

except KeyboardInterrupt:
	server.shutdown()
	sys.exit(0)


