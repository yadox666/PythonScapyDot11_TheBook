#!/usr/bin/python
# -*- coding: utf-8 -*-​
import threading, os, time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal

intfmon='mon0'
channel=''   ### Define channel if not want to hop, and will stay in one channel
first_pass=1
lock = Lock()
DN = open(os.devnull, 'w')
verbose=1

def calc_freq(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)
    return str(freq)

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
			if verbose: print "Setting %s interface to channel: %s (%s MHz)" %(intfmon, monchannel, calc_freq(int(monchannel)))
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


# Start channel hopping
hop = Thread(target=channel_hop, args=channel)
hop.daemon = True
hop.start()

while 1:
	time.sleep(1)

