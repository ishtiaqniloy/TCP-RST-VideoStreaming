# TCP-RST-VideoStreaming
This repository contains the design and implementation (in python) of an attack tool to perform TCP reset attack on video streaming applications. This tool is tested on LAN as well as WAN.

Scapy 2.4.0 package needs to be installed prior to performing the attack. To install scapy: pip install scapy==2.4.0

First we need to perform MITM attack to be able to sniff packets from the victim. Then we will start sending TCP RST packets to the victim to disrupt the video stram.

Python Implementation folder contains the scripts to perform the attack. Commands:-
1. If server is outside the subnet, enable attacker to sniff all packets between the network gateway and the victim : python MITM.py victim_ip
2. If server is within the same subnet, enable attacket to sniff all packets between the server and the victim: python MITM.py victim_ip server_ip
3. Begin TCP RST attack: python RST.py victim_ip

Documentation folder contains the design and the implementation reports. It also inculdes diagrams and testing screenshots.

Tools/Technologies: Python, Scapy
