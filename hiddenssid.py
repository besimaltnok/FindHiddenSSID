#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse

hiddenlist = []
iface = 'wlan0'

helpme = """
Author : Besim ALTINOK ||| Team   : CanYouPwnMe
"""

parser = argparse.ArgumentParser(description=helpme)
parser.add_argument('-a', action='store', dest='bssid',
                    help='Hidden Access Point mac address')
parser.add_argument('-i', action='store', dest='iface',
                    help='Usable interface name\n') 
args = parser.parse_args()

hidden = args.bssid
iface  = args.iface
hiddenlist.append(hidden)

def FindHiddenSSID(pkt):
	if pkt.haslayer(Dot11ProbeResp) and (pkt.addr2).upper() in hiddenlist:
		print "Find Hidden SSID : \n", 
		print "  * Access point mac address : ", pkt.addr2
		print "  * Hidden SSID              : ", pkt.info
		exit(0)

sniff(iface=iface,count=0,prn=FindHiddenSSID)
