# Author: Steven Bertolucci
# Course: CS 373 - Defense Against the Dark Arts
# Institution: Oregon State University
# Assignment: Homework 3 - Network Traffic Analysis

from CSVPacket import Packet, CSVPackets
from collections import defaultdict
import sys

# Check for the -stats and -countip flags
show_stats = '-stats' in sys.argv
count_ip = '-countip' in sys.argv

IPProtos = [0 for x in range(256)]
numBytes = 0
numPackets = 0

# Initialize counts for well-known ports (1-1024) for TCP and UDP
tcp_port_counts = {port: 0 for port in range(1, 1025)}
udp_port_counts = {port: 0 for port in range(1, 1025)}

# Dictionary to count IP address usage
ip_counts = defaultdict(int)

# Find the CSV file argument, which should be the first argument not being -stats
csv_filename = None
for arg in sys.argv[1:]:
    if arg not in ['-stats', '-countip']:
        csv_filename = arg
        break

csvfile = open(sys.argv[1], 'r')

for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    # print pkt
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1

    # Count the IP address usage
    ip_counts[pkt.ipsrc] += 1
    ip_counts[pkt.ipdst] += 1

    # Check for TCP (protocol number 6) and UDP (protocol number 17)
    if proto == 6:  # TCP
        if 1 <= pkt.tcpdport <= 1024:
            tcp_port_counts[pkt.tcpdport] += 1
    elif proto == 17:  # UDP
        if 1 <= pkt.udpdport <= 1024:
            udp_port_counts[pkt.udpdport] += 1

if show_stats:
    print("numPackets:%u numBytes:%u" % (numPackets, numBytes))
    for i in range(256):
        if IPProtos[i] != 0:
            print("%3u: %9u" % (i, IPProtos[i]))

    # Printing TCP Ports
    print("\nTCP Port Counts for well-known ports (1-1024):")
    for port, count in tcp_port_counts.items():
        if count > 0:
            print("Port %u: %u packets" % (port, count))

    # Printing UDP Ports
    print("\nUDP Port Counts for well-known ports (1-1024):")
    for port, count in udp_port_counts.items():
        if count > 0:
            print("Port %u: %u packets" % (port, count))

if count_ip:
    print("IP Address Usage Counts:")
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ip_counts:
        print(f"IP Address {ip}: {count} packets")
