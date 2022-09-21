import uuid
import socket
import netifaces
import struct


# Main wireless interface
def get_interface() -> str:
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface == "lo":
            continue
        try:
            if netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"]:
                return interface
        except:
            continue


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5],
    )
    return b


# MAC address
def get_mac(self) -> str:
    mac = uuid.getnode()
    mac = hex(mac)[2:]
    mac = ":".join([mac[i : i + 2] for i in range(0, len(mac), 2)])
    return mac