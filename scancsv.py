# Author: Steven Bertolucci
# Course: CS 373 - Defense Against the Dark Arts
# Institution: Oregon State University
# Assignment: Homework 3 - Network Traffic Analysis

from CSVPacket import Packet, CSVPackets
from collections import defaultdict
import sys

# Check for the flags
show_stats = '-stats' in sys.argv
count_ip = '-countip' in sys.argv
gre_flag = '-gre' in sys.argv
ipsec_flag = '-ipsec' in sys.argv
ospf_flag = '-ospf' in sys.argv
count_connections = '-connto' in sys.argv

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

# Dictionary to track connections to each service
service_connections = defaultdict(lambda: defaultdict(set))

# Find the CSV file argument
csv_filename = None
for arg in sys.argv[1:]:
    if arg not in ['-stats', '-countip', '-gre', '-ipsec', '-ospf', '-connto']:
        csv_filename = arg
        break

# Ensure the script is run with the necessary argument
if csv_filename is None:
    print("Usage: python scancsv.py <filename> [-stats] [-countip] [-gre] [-ipsec] [-ospf] [-connto]")
    sys.exit(1)

# Open the file for reading
csvfile = open(sys.argv[1], 'r')

# Iterate through the file headers
for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    # print pkt
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1

    # 6. Apply protocol filter if specified i.e. if user entered the flags '-gre', '-ipsec', 'ospf'
    if protocol_filter is not None and proto != protocol_filter:
        continue

    # Count the IP address usage
    ip_counts[pkt.ipsrc] += 1
    # ip_counts[pkt.ipdst] += 1

    # Extract and count /24 network prefixes
    src_prefix = '.'.join(pkt.ipsrc.split('.')[:3]) + '.0/24'
    prefix_counts[src_prefix] += 1

    # Check for TCP (protocol number 6) and UDP (protocol number 17) and count them
    if proto == 6:  # TCP
        if 1 <= pkt.tcpdport <= 1024:
            tcp_port_counts[pkt.tcpdport] += 1

            # 9. Count the number of packets sent to each service ports on the network.
            if count_connections:
                service = f"tcp/{pkt.tcpdport}"
                service_connections[pkt.ipdst][service].add(f"{pkt.ipsrc}-{pkt.tcpsport:05d}")

    elif proto == 17:  # UDP
        if 1 <= pkt.udpdport <= 1024:
            udp_port_counts[pkt.udpdport] += 1

            # 9. Count the number of packets sent to each service ports on the network.
            if count_connections:
                service = f"udp/{pkt.udpdport}"
                service_connections[pkt.ipdst][service].add(f"{pkt.ipsrc}-{pkt.udpsport:05d}")

# If user included the '-stats' flag in the command line, print this only
if show_stats:
    print("numPackets:%u numBytes:%u" % (numPackets, numBytes))
    for i in range(256):
        if IPProtos[i] != 0:
            print("%3u: %9u" % (i, IPProtos[i]))

    # 1: Printing TCP Ports
    print("\nTCP Port Counts for well-known ports (1-1024):")
    for port, count in tcp_port_counts.items():
        if count > 0:
            print("Port %u: %u packets" % (port, count))

    #  1: Printing UDP Ports
    print("\nUDP Port Counts for well-known ports (1-1024):")
    for port, count in udp_port_counts.items():
        if count > 0:
            print("Port %u: %u packets" % (port, count))

# 3: Printing out the most popular IP addresses
if count_ip:
    print("IP Address Usage Counts:")
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ip_counts:
        print(f"IP Address {ip}: {count} packets")

# 3. Determine and print the dominant network prefixes
print("\nNetwork Prefix Usage Counts:")
sorted_prefix_counts = sorted(prefix_counts.items(), key=lambda x: x[1], reverse=True)
for prefix, count in sorted_prefix_counts:
    print(f"Network Prefix {prefix}: {count} packets")

# 7. Identify and print secondary network prefixes associated with the filtered traffic
if protocol_filter is not None:
    print("\nSecondary Network Prefixes Associated with Protocol Traffic:")
    for prefix, count in sorted_prefix_counts:
        # Exclude the most dominant prefix
        if count > 0 and prefix != sorted_prefix_counts[0][0]:
            print(f"Network Prefix {prefix}: {count} packets")

# 9. Print connections to services if -connto flag is set
if count_connections:
    print("\nConnections to Services:")
    for ipdst, services in service_connections.items():
        distinct_ipsrc_ports = set()
        for service, src_ports in services.items():
            distinct_ipsrc_ports.update(src_ports)
        print(f"{ipdst} has {len(distinct_ipsrc_ports)} distinct ipsrc on ports: {', '.join(services.keys())}")
