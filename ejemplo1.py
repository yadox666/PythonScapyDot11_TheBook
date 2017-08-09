#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import os, time, socket, fcntl, struct
from subprocess import call
from platform import system

# define variables
intfparent='wlan1'
intfmon='mon0'

def OScheck():
    osversion = system()
    print "Operating System: %s" %osversion
    if osversion != 'Linux':
        print "This script only works on Linux OS! Exitting!"
        exit(1)

def InitMon():
	if not os.path.isdir("/sys/class/net/" + intfmon):
		if not os.path.isdir("/sys/class/net/" + intfparent):
			print "WiFi interface %s does not exist! Cannot continue!" %(intfparent)
			exit(1)
		else:
			try:
				# create monitor interface using iw
				os.system("iw dev %s interface add %s type monitor" % (intfparent, intfmon))
				time.sleep(0.5)
				os.system("ifconfig %s up" %intfmon)
				print "Creating monitor VAP %s for parent %s..." %(intfmon,intfparent)
			except OSError as e:
				print "Could not create monitor %s" %intfmon
				os.kill(os.getpid(),SIGINT)
				sys.exit(1)
	else:
		print "Monitor %s exists! Nothing to do, just continuing..." %(intfmon)

def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    macaddr = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return macaddr


# Check if OS is linux:
OScheck()

# Check for root privileges
if os.geteuid() != 0:
	exit("You need to be root to run this script!")
else:
	print "You are running this script as root!"

# Check if monitor device exists
InitMon()

# Get intfmon actual MAC address
macaddr=GetMAC(intfmon).upper()
print "Actual %s MAC Address: %s" %(intfmon, macaddr)
