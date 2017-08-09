#!/usr/bin/env python
# -*- coding: utf-8 -*-​
# /overlay/upper/usr/lib/python2.7/site-packages/netaddr/eui/ieee.py to update
# /overlay/upper/usr/lib/python2.7/site-packages/netaddr/eui/oui.txt
from netaddr import *
from netaddr.core import NotRegisteredError

def get_oui(mac):
	maco = EUI(mac)
	try:
		manuf = maco.oui.registration().org
	except NotRegisteredError:
		manuf = "Not available"
	return manuf

mac = 'bc:ae:c5:3b:fc:5e'
print get_oui(mac)

