# CSE_406_TCP_Reset_Attack_Video_Streaming
This repository contains the design and implementation (in python) of an attack tool to perform TCP reset attack on video streaming applications. 

First we need to perform MITM attack to be able to sniff packets from the victim. Then we will start sending TCP RST packets to the victim to disrupt the video stram.

Python Implementation folder contains the scripts to perform the attack. Commands:-
1. If server is outside the subnet, enable attacker to sniff all packets between network gateway and the victim : python MITM.py victim_ip
2. If server is within the same subnet, enable attacket to sniff all packets between a local server and the victim: python MITM.py victim_ip server_ip
3. Begin TCP RST attack: python RST.py victim_ip

Documentation folder contains the design and the implementation reports. It also inculdes testing screenshots.
