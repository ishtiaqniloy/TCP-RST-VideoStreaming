from scapy.all import send
from scapy.layers.inet import *


print("Hello World")
ip = IP(dst="192.168.0.107")
print(ip.dst)

print(ip.show())

ip = ip/TCP()

print(ip.show())

# ip.send()
for i in range(0, 100):
    send(IP(src="192.168.0.101",dst="192.168.0.104")/ICMP()/"Hello World")