import time
import sys
from scapy.all import *
from scapy.all import *
from scapy.all import send
from scapy.layers.inet import *
import scapy


# srcIP = "192.168.0.103"
destIP = "192.168.0.108"

def func(pkt):
    print("PKT INFO:")
    # print(pkt.__class__)
    print(pkt[IP].src)
    print(pkt[IP].dst)
    print(pkt[TCP].sport)
    print(pkt[TCP].dport)
    print()



# sniff(filter="ip", prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}"))
pkt = sniff(filter="TCP and dst host 157.240.7.35", prn=func, store=0)

