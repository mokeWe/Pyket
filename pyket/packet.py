import socket
import struct
from colorama import Fore
from pyket import network


def unpack(fmt, data):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, data[:size])


def print_data(data: str) -> None:
    try:
        print(f"Data: \n{Fore.LIGHTRED_EX}" + data.decode("utf-8") + f"{Fore.RESET}")
    except:
        pass


def IPv4(packet, eth_length, eth_protocol):
    if eth_protocol == 8:
        # Parse IP header
        ip_header = packet[eth_length : 20 + eth_length]

        # Unpack IP header
        iph = unpack("!BBHHHBBH4s4s", ip_header)

        # Version
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        # IP header length
        iph_length = ihl * 4
        ttl = iph[5]

        # Protocol
        protocol = iph[6]

        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        print("Version: " + str(version))
        print("IP Header Length: " + str(ihl))
        print("TTL: " + str(ttl))
        print("Protocol: " + str(protocol))
        print("Source Address: " + str(s_addr))
        print("Destination Address: " + str(d_addr))

        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t : t + 20]

            # Unpack the TCP header
            tcph = unpack("!HHLLBBHHH", tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]

            # Get sequence & acknowledgement number
            sequence = tcph[2]
            acknowledgement = tcph[3]

            # Bit shifting to get flags
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            # Get data
            h_size = eth_length + iph_length + tcph_length * 4
            data = packet[h_size:]

            print("Source Port: " + str(source_port))
            print("Destination Port: " + str(dest_port))
            print("Sequence Number: " + str(sequence))
            print("Acknowledgement: " + str(acknowledgement))
            print("TCP Header Length: " + str(tcph_length))

            print_data(data)

        # ICMP Packets
        elif protocol == 1:
            # Get ICMP type
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u : u + 4]

            # Unpack the ICMP header
            icmph = unpack("!BBH", icmp_header)

            # Get the type and code
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            # Get data
            h_size = eth_length + iph_length + icmph_length
            data = packet[h_size:]

            print("Type: " + str(icmp_type))
            print("Code: " + str(code))
            print("Checksum: " + str(checksum))

            print_data(data)

        # UDP packets
        elif protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u : u + 8]

            # Unpack the UDP header
            udph = unpack("!HHHH", udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            # Get data
            h_size = eth_length + iph_length + udph_length
            data = packet[h_size:]

            print("Source Port: " + str(source_port))
            print("Destination Port: " + str(dest_port))
            print("Length: " + str(length))
            print("Checksum: " + str(checksum))

            print_data(data)


def capture(interface: str) -> None:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((interface, 0))
    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]

        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        print(f"{Fore.GREEN}-{Fore.RESET}" * 60)
        print(
            f"{Fore.GREEN}Destination MAC: {Fore.RESET}" + network.eth_addr(packet[0:6])
        )
        print(
            f"{Fore.LIGHTRED_EX}Source MAC: {Fore.RESET}"
            + network.eth_addr(packet[6:12])
        )
        print(f"{Fore.BLUE}Protocol: {Fore.RESET}" + str(eth_protocol))

        IPv4(packet, eth_length, eth_protocol)
