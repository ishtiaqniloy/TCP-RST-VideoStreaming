#!/usr/bin/python3

#running command: python Sniffer.py victimIP

import sys  #for command line argument
import time
import os
import shutil
import tempfile
from random import randint
from scapy.all import *
from scapy.layers.inet import *
import scapy



# srcIP = "192.168.0.103"
destIP = "192.168.0.105"

def func(pkt):
    print("PKT INFO:")
    print(pkt.__class__)
    print(pkt[IP].src)
    print(pkt[IP].dst)
    print(pkt[TCP].sport)
    print(pkt[TCP].dport)
    print()



# sniff(filter="ip", prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}"))
pkt = sniff(filter="TCP and dst host 192.168.0.105", prn=func, store=0)

