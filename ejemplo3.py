#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import threading, os, time, logging
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
from time import sleep

intfmon='mon0'
verbose=1
DN = open(os.devnull, 'w')

class Hopper(Thread):
    def __init__(self, interface, wait=4):
        Thread.__init__(self)
        Thread.daemon = True

        self.wait = wait
        self.iface = intfmon
        self.HOPpause = False
        # dwell for 3 time slices on 1 6 11
        # default is 3/10 of a second
        self.channellist = [1, 6, 11, 14, 2, 7, 3, 8, 4, 12, 9, 5, 10, 13,
        36, 38, 40, 42, 44, 46, 52, 56, 58, 60, 100, 104, 108, 112,
        116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        self.hopList = []
        self.current = 0
        self.check_channels()

    def check_channels(self):
        # try setting 802.11ab channels first
        # this may not work depending on 5ghz dfs
        # reverse so we start with 5ghz channels first
        if verbose: logging.debug('Gettings available channels...')
        for ch in self.channellist:
	    check=True
	    try:
	        proc = Popen(['iw', 'dev', self.iface, 'set', 'channel', str(ch)], stdout=DN, stderr=PIPE)
	    except:
	        if verbose: logging.debug('Could not execute iw!')
	        os.kill(os.getpid(),SIGINT)
		check=False
	    for line in proc.communicate()[1].split('\n'):
	        if len(line) > 2: # iw dev shouldnt display output unless there's an error
		    check=False
            if check == True:
                self.hopList.append(ch)
        if verbose: 
		logging.debug('Available channels for hopping:')
        	logging.debug(self.hopList)

    def pause(self):
        self.HOPpause = True

    def unpause(self):
        self.HOPpause = False

    def set_channel(self, channel, check=True):
        if verbose: print('[*] Switching channel to %s' % channel)

        if check and channel not in self.hopList:
            if verbose: logging.error('[!] Channel %s not inhop list' % channel)
            return False

        try:
            proc = Popen(['iw', 'dev', intfmon, 'set', 'channel', str(channel)], stdout=DN, stderr=PIPE)
        except OSError as e:
            print 'Could not execute iw!'
            os.kill(os.getpid(),SIGINT)
            return False
        for line in proc.communicate()[1].split('\n'):
            if len(line) > 2: # iw dev shouldnt display output unless there's an error
                return False

    def run(self):
        while True:
            for ch in self.hopList:
                if self.HOPpause is True:
                    continue

                if not self.set_channel(ch):
                    continue

                self.current = ch

                if ch in [1, 6, 11, 13]: ## dwell for 4/10 of a second, we want to sit on 1 6 11 and 13 a bit longer
                    sleep(.5)
                else:
                    sleep(.3)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    Hopper(intfmon).start()
    raw_input('Press enter to stop...')
