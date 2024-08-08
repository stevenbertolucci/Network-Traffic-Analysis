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
gre_flag = '-gre' in sys.argv
ipsec_flag = '-ipsec' in sys.argv
ospf_flag = '-ospf' in sys.argv

# Determine the protocol filter based on the flags
protocol_filter = None
if gre_flag:
    protocol_filter = 47  # GRE (Generic Routing Encapsulation)
elif ipsec_flag:
    protocol_filter = 50  # IPSEC (Encapsulation Security Payload)
elif ospf_flag:
    protocol_filter = 89  # OSPF (Open Shortest Path First)

IPProtos = [0 for x in range(256)]
numBytes = 0
numPackets = 0

# Initialize counts for well-known ports (1-1024) for TCP and UDP
tcp_port_counts = {port: 0 for port in range(1, 1025)}
udp_port_counts = {port: 0 for port in range(1, 1025)}

# For debugging purposes
# print(sys.argv[0])
# print(sys.argv[1])
# print(sys.argv[2])

# Dictionary to count IP address usage
ip_counts = defaultdict(int)

# Dictionary to count network prefix usage
prefix_counts = defaultdict(int)

# Find the CSV file argument
csv_filename = None
for arg in sys.argv[1:]:
    if arg not in ['-stats', '-countip', '-gre', '-ipsec', '-ospf']:
        csv_filename = arg
        break

# Ensure the script is run with the necessary argument
if csv_filename is None:
    print("Usage: python scancsv.py <filename> [-stats] [-countip] [-gre] [-ipsec] [-ospf]")
    sys.exit(1)

csvfile = open(sys.argv[1], 'r')

for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    # print pkt
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1

    # Apply protocol filter if specified
    if protocol_filter is not None and proto != protocol_filter:
        continue

    # Count the IP address usage
    ip_counts[pkt.ipsrc] += 1
    ip_counts[pkt.ipdst] += 1

    # Extract and count /24 network prefixes
    src_prefix = '.'.join(pkt.ipsrc.split('.')[:3]) + '.0/24'
    prefix_counts[src_prefix] += 1

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

# Printing out the most popular IP addresses
if count_ip:
    print("IP Address Usage Counts:")
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ip_counts:
        print(f"IP Address {ip}: {count} packets")

# Determine and print the dominant network prefixes
print("\nNetwork Prefix Usage Counts:")
sorted_prefix_counts = sorted(prefix_counts.items(), key=lambda x: x[1], reverse=True)
for prefix, count in sorted_prefix_counts:
    print(f"Network Prefix {prefix}: {count} packets")
