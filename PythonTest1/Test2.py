from scapy.all import send
from scapy.layers.inet import *

import uuid 
  
# printing the value of unique MAC 
# address using uuid and getnode() function  
# print (hex(uuid.getnode())) 

my_mac = str(':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
for ele in range(0,8*6,8)][::-1])) 

print(my_mac)
# # ip.send()
# for i in range(0, 100):
#     send(IP(src="192.168.0.105",dst="192.168.0.105")/ICMP()/"Hello World")
