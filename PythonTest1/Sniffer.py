#!/usr/bin/python3

#running command: python Sniffer.py victimIP

import sys  #for command line argument
import time
from random import randint
from scapy.all import *
from scapy.layers.inet import *
import scapy

victim_ip = sys.argv[1]

def func(pkt):
    print("PKT INFO:")
    # print(pkt.__class__)

    print(pkt.summary())

    print(pkt[IP].src)
    print(pkt[IP].dst)

    print(pkt[TCP].sport)
    print(pkt[TCP].dport)
    print(pkt[TCP].ack)

    print()



# sniff(filter="ip", prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}"))
pkt = sniff(filter="tcp and dst host " + victim_ip, prn=func, store=0)

