from pyket import network, packet
from colorama import Fore
import os
import argparse

# create argument parser
parser = argparse.ArgumentParser(description="Pyket")
parser.add_argument(
    "-i",
    "--interface",
    help="Interface to capture packets on",
    default=network.get_interface(),
)
parser.add_argument(
    "-f",
    "--filter",
    help="Filter packets by protocol",
    default="all",
    choices=["all", "tcp", "udp"],
)


def main():

    args = parser.parse_args()
    packet.capture(args.interface, args.filter)


if __name__ == "__main__":
    main()
