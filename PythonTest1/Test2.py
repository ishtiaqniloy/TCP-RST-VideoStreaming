from scapy.all import send
from scapy.layers.inet import *

# ip.send()
for i in range(0, 100):
    send(IP(src="192.168.0.105",dst="192.168.0.105")/ICMP()/"Hello World")