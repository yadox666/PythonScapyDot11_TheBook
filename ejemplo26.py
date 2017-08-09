#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging,time,os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy_ex
import sqlite3
from netaddr import *
from netaddr.core import NotRegisteredError
from signal import SIGINT, signal
import threading, os, time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal

intfmon='mon0'
intfparent = 'wlan1'
workdir = './database'
channel=''   ### Define channel if not want to hop, and will stay in one channel
deleterecords=0
verbose = 1
first_pass=1
lock = Lock()
DN = open(os.devnull, 'w')
ap_list = [ ]
timestamp = str(int(time.time()))
stop = True


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
			if verbose >1: print "Setting %s interface to channel: %s" %(intfmon, monchannel)
		except OSError as e:
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


def stop_sniff(pkt):
	if stop:
		return False
	else:
		return True


def end_execution(signal, frame):
	global stop
	stop=True
	# Committing changes and closing the connection to the database file
	con.commit()
	# Make a query to the DB
	if len(ap_list) > 0:
		cursor.execute("SELECT * from AP")
		sys.stdout.write("\033[F") # Cursor up one line
		print '\nAP database records:'
		for row in cursor:
			print row
	con.close()
        sys.exit('CTRL+C pressed, exitting!')


def get_oui(mac):
        try:
                return EUI(mac).oui.registration().org
        except NotRegisteredError:
                return "N/A"


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


def PacketHandler(pkt) :
	if pkt.haslayer(Dot11Beacon):
		bssid=pkt.addr2.upper()
		if bssid not in ap_list :
			ap_list.append(bssid)
			manufacturer = get_oui(bssid)
			essid = pkt.info
			hidden = int((not essid))
			channel = pkt[Dot11].channel() or pkt[RadioTap].Channel
			channel = int(channel)
			lrates = pkt[Dot11].rates()
			rates=','.join(str(x) for x in lrates)
			signal = 100 - abs(int(pkt[RadioTap].dBm_AntSignal))
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
			security = "%s/%s/%s" %(enc,cipher,auth)
			wps=0
			p = pkt[Dot11Elt]
        		while isinstance(p, Dot11Elt):
				if pkt[Dot11Elt].ID == 221:
					if elt.info.startswith("\x00\x50\xF2\x04"):
						wps=1
				p = p.payload

			# Insert a row of data
			row=set()
			seen=int(time.time())
			row = bssid,seen,seen,essid,hidden,security,wps,rates,manufacturer,channel,signal
			cursor.execute("INSERT INTO AP VALUES (?,?,?,?,?,?,?,?,?,?,?)" ,row)
			if verbose: print "%s: AP BSSID:%s with ESSID:%s and SEC:%s/%s/%s WPS:%s %d SIGNAL:%s RATES:%s" %(timestamp,bssid, essid, enc, cipher, auth, wps, channel,signal,rates)
		else:
			seen=int(time.time())
			cursor.execute("UPDATE AP set LASTSEEN=? where BSSID=?",(seen,bssid,))


# Init monitor mode interface, if necessary
InitMon()

# Creating the sqlite DB file and populate it with new tables
if not os.path.exists(workdir):
	try:
		os.makedirs(workdir)
	except:
		print "Cannot create directory: " + workdir
		workdir="./"
dbfile = workdir + '/scan.sqlite'    # name of the sqlite database file
try:
	if not os.path.isfile(dbfile):
		con = sqlite3.connect(dbfile)  ## Connection object, if DB does not exist it'll be created now
		cursor = con.cursor()  ## Cursor object (DB will be handled with this object)
		con.text_factory = lambda x: unicode(x, 'utf-8', 'ignore')
		cursor.execute('''CREATE TABLE AP
			(bssid TEXT PRIMARY KEY NOT NULL,
			firstseen INTEGER NOT NULL,
			lastseen INTEGER NOT NULL,
			essid TEXT,
			hidden INTEGER,
			security TEXT,
			wps INTEGER,
			rates TEXT,
			manufacturer TEXT,
			channel INTEGER,
			signal INTEGER)''')
		print "Created SQlite DB file: %s successfully!" %dbfile
	else:
		con = sqlite3.connect(dbfile)  ## Connection object, if DB does not exist it'll be created now
		cursor = con.cursor()  ## Cursor object (DB will be handled with this object)
		con.text_factory = lambda x: unicode(x, 'utf-8', 'ignore')
		print "SQlite DB file: %s exists!" %dbfile
		if deleterecords:
			print "Requested to delete all records from DB!"
			cursor.execute("DELETE from AP")
		else:
			# Populate ap_list from DB
			cursor.execute("SELECT * from AP")
			for row in cursor:
				ap_list.append(row[0])
			
except Exception as e:
	print e.message, e.args
	print "Could not create %s Database!, exiting!" %dbfile
	exit(-1)



# Interrupt handler to exit
signal(SIGINT, end_execution)

# Start channel hopping
hop = Thread(target=channel_hop, args=channel)
hop.daemon = True
hop.start()

# Begin sniffing
sniff(iface=intfmon, prn = PacketHandler, stop_filter=stop_sniff, lfilter=lambda p:Dot11 in p)

