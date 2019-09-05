import time
import sys
from scapy.all import *
from scapy.all import *
from scapy.all import send
from scapy.layers.inet import *
import scapy


srcIP = "192.168.0.107"
destIP = "192.168.0.105"

IPLayer = IP(dst=destIP, src=srcIP)

for i in range(1,100):
    TCPLayer = TCP(seq=i, dport=80, sport=30000)
    spoofpkt = IPLayer/TCPLayer
    send(spoofpkt, verbose=2)

    print("Spoofed Packet Sent...")


