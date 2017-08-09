#!/usr/bin/python
# -*- coding: utf-8 -*-​
import threading, time, sys, base64, logging
from Crypto.Cipher import AES
from threading import Thread, Lock
from datetime import datetime
from random import randint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 

verbose=1
maxpayload=64
sc=randint(1,9999)
lastpacketsc=0
bootime=time.time()
count=10

def chatencrypt(message):
	message = username + '~' + message
	if len(message) < maxpayload:
		message = message.rjust(maxpayload)
	else:
		message = message[:maxpayload]
	encoded = base64.b64encode(cipher.encrypt(message))
	return encoded

def chatdecrypt(message):
	decoded = cipher.decrypt(base64.b64decode(message))
	decoded = decoded.strip()
	decoded = decoded.split('~')
	return decoded

def packetSniffer():
	sniff(iface=intfmon, prn=PacketHandler, store=False, lfilter=lambda pkt: (Dot11ProbeReq in pkt))
	return

def PacketHandler(pkt):
	global lastpacketsc
	if pkt.addr3.upper() == remote and pkt.SC != lastpacketsc:
		lastpacketsc = pkt.SC
		suffix='' 
		if verbose: suffix='(' + pkt.info + ')'
		decrypted = chatdecrypt(pkt.info)
                print "%s: %s %s" % (decrypted[0],decrypted[1], suffix)

def PacketSend(chat):
	global lastpacketsc
	encrypted = chatencrypt(chat)
	eltessid = Dot11Elt(ID=0,info=encrypted)
	dot11 = Dot11(type=0,subtype=4,addr1=remote, addr2=RandMAC(),addr3=remote)
	eltrates = Dot11Elt(ID=1,info="\x82\x84\x8b\x96")
        eltwps = Dot11Elt(ID=221,len=9,info="\x00\x50\xF2\x04\x10\x4a\x00\x01\x10")
        dsset = Dot11Elt(ID='DSset',info='\x01')
	pkt = RadioTap()/dot11/Dot11ProbeReq()/eltessid/eltwps/eltrates/dsset
	pkt.SC = next_sc()     ## Update sequence number
	pkt.timestamp = current_timestamp()  ## Update packet timestamp
	lastpacketsc = pkt.SC   ## Save this packet to not repeat showing it
	sendp(pkt, iface=intfmon, verbose=0, count=count)  ## Send packet several times

	suffix='' 
	if verbose: suffix='(' + encrypted + ')'
        print "%s: %s %s" %(username,chat,suffix)

def current_timestamp():
        global bootime
        return (time.time() - bootime) * 1000000

def next_sc():
        global sc
        sc = (sc + 1) % 4096
        temp = sc
        return temp * 16  # Fragment number -> right 4 bits

def SetChannel(channel):
        cmd0 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
        cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
        try:
                os.system(cmd0)
                os.system(cmd1)
	        print "Setting %s to channel: %s (%s)" %(intfmon,channel,remote)
        except:
		print "Error setting channel for %s" %intfmon

# Main loop
try:
	print "==============================================================="
	print "        SECRET AND HIDDEN CHAT VIA WI-FI COVERT CHANNEL        "
	print "==============================================================="
	print "Welcome to Hidden Wi-Fi Chat! Enter quit() to exit if you wish!"
	print "==============================================================="

	# Ask for monitor mode interface
        intfmon = raw_input("Enter your monitor interface: ")
	if intfmon == '': intfmon='mon0'

	# Define private IRC channel
        username = raw_input("Enter your User name or alias: ")
        privateirc = raw_input("Define private IRC channel name: ")
	privateirc = privateirc.ljust(16, '0')
	i=0 ; remote = []
	for i in range(0,6):
		letter = privateirc[i]
		if i == 5: channel=max(min(11, ord(letter)/10), 1)
		remote.append(letter.encode("hex"))
		i += 1
	remote=':'.join(remote).upper()

	# Cipher suite: never use ECB in strong systems obviously
	cipher = AES.new(privateirc,AES.MODE_ECB) 

	# Set channel and begin to sniff
	SetChannel(channel)
	sniffer = Thread(target=packetSniffer)
        sniffer.daemon = True
        sniffer.start()

	print "Just write and press enter to send!\n"
except KeyboardInterrupt:
	sys.stdout.write("\033[F") # Cursor up one line
	print "\n"
	exit()

try:
	while 1:
	        chat = raw_input()
	        if chat != "quit()":
			sys.stdout.write("\033[F") # Cursor up one line
			if chat != '':
				PacketSend(chat)
		else:
			sys.stdout.write("\033[F") # Cursor up one line
			PacketSend('bye!')
			exit()

except KeyboardInterrupt:
	sys.stdout.write("\033[F") # Cursor up one line
	PacketSend('bye!')
	exit()
