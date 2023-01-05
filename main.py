"""Pyket - A simple packet sniffer written in Python"""
import os
import argparse
from colorama import Fore
from pyket import network, packet


def main():
    """Main function"""
    if os.geteuid() != 0:
        print(Fore.RED + "[-] Root privileges are required to run this program")
        exit()

    parser = argparse.ArgumentParser(description="Pyket")
    parser.add_argument(
        "-i",
        "--interface",
        help="Interface to capture packets on, default is the first interface found",
        default=network.get_interface(),
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="Filter packets by protocol",
        default="all",
        choices=["all", "tcp", "udp"],
    )

    args = parser.parse_args()

    packet.capture(args.interface, args.filter)


if __name__ == "__main__":
    main()
