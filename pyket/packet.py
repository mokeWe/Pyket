"""contains the packet class and functions to parse packets"""
import socket
import struct
from colorama import Fore
from pyket import network


def unpack(fmt, data):
    """unpacks data using the given format"""
    return struct.unpack(fmt, data[: struct.calcsize(fmt)])


def print_data(data: str) -> None:
    """prints the data of a packet"""
    try:
        print(f"Data: \n{Fore.LIGHTRED_EX}" + data.decode("utf-8") + f"{Fore.RESET}")
    except UnicodeDecodeError:
        pass


def print_header(packet):
    """prints the header of a packet"""
    print(f"{Fore.GREEN}-{Fore.RESET}" * 60)
    print(f"{Fore.GREEN}Destination MAC: {Fore.RESET}" + network.eth_addr(packet[:6]))
    print(
        f"{Fore.LIGHTRED_EX}Source MAC: {Fore.RESET}" + network.eth_addr(packet[6:12])
    )


def print_body(version, ihl, ttl, protocol, s_addr, d_addr):
    """prints the body of a packet"""
    print(
        f"{Fore.LIGHTRED_EX}Version: {Fore.RESET}{version}\n"
        f"{Fore.LIGHTRED_EX}IP Header Length: {Fore.RESET}{ihl}\n"
        f"{Fore.LIGHTRED_EX}TTL: {Fore.RESET}{ttl}\n"
        f"{Fore.LIGHTRED_EX}Protocol: {Fore.RESET}{protocol}\n"
        f"{Fore.LIGHTRED_EX}Source Address: {Fore.RESET}{s_addr}\n"
        f"{Fore.LIGHTRED_EX}Destination Address: {Fore.RESET}{d_addr}\n"
    )


def udp(packet, eth_length, protocol, iph_length):
    """parses udp packets"""
    if protocol == 17:
        u = iph_length + eth_length
        udph_length = 8
        udp_header = packet[u : u + 8]

        # Unpack the udp header
        udph = unpack("!HHHH", udp_header)

        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]

        # Get data
        h_size = eth_length + iph_length + udph_length
        data = packet[h_size:]

        print_header(packet)

        print("\nPACKET TYPE: UDP\n")

        # Defining these in every function is necessary, but ugly
        ip_header = packet[eth_length : 20 + eth_length]
        iph = unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print_body(version, ihl, ttl, protocol, s_addr, d_addr)

        print(
            f"{Fore.LIGHTRED_EX}Source Port: {Fore.RESET}{source_port}\n"
            f"{Fore.LIGHTRED_EX}Destination Port: {Fore.RESET}{dest_port}\n"
            f"{Fore.LIGHTRED_EX}Length: {Fore.RESET}{length}\n"
            f"{Fore.LIGHTRED_EX}Checksum: {Fore.RESET}{checksum}\n"
        )

        print_data(data)
    else:
        pass


def tcp(packet, eth_length, protocol, iph_length):
    """parses TCP packets"""
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

        print_header(packet)

        print("\nPACKET TYPE: TCP\n")

        # Version
        ip_header = packet[eth_length : 20 + eth_length]
        iph = unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print_body(version, ihl, ttl, protocol, s_addr, d_addr)

        print(
            f"{Fore.LIGHTRED_EX}Source Port: {Fore.RESET}{source_port}\n"
            f"{Fore.LIGHTRED_EX}Destination Port: {Fore.RESET}{dest_port}\n"
            f"{Fore.LIGHTRED_EX}Sequence Number: {Fore.RESET}{sequence}\n"
            f"{Fore.LIGHTRED_EX}Acknowledgement: {Fore.RESET}{acknowledgement}\n"
            f"{Fore.LIGHTRED_EX}TCP Header Length: {Fore.RESET}{tcph_length}\n"
        )

        print_data(data)
    else:
        pass


def ipv4(packet, eth_length, eth_protocol, filter_protocol):
    """parses IPv4 packets"""
    if eth_protocol == 8:
        # Parse IP header
        ip_header = packet[eth_length : 20 + eth_length]

        # Unpack IP header
        iph = unpack("!BBHHHBBH4s4s", ip_header)

        # Version
        version_ihl = iph[0]
        ihl = version_ihl & 0xF

        # IP header length
        iph_length = ihl * 4

        # Protocol
        protocol = iph[6]

        if filter_protocol == "all":
            udp(packet, eth_length, protocol, iph_length)
            tcp(packet, eth_length, protocol, iph_length)
        elif filter_protocol == "udp":
            udp(packet, eth_length, protocol, iph_length)
        elif filter_protocol == "tcp":
            tcp(packet, eth_length, protocol, iph_length)


def capture(interface: str, filter_protocol) -> None:
    """captures packets"""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((interface, 0))
    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]

        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        ipv4(packet, eth_length, eth_protocol, filter_protocol=filter_protocol)
