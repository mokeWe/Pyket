import uuid
import netifaces


# Main wireless interface
def get_interface() -> str:
    for interface in netifaces.interfaces():
        if interface == "lo":
            continue
        try:
            if netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"]:
                return interface
        except KeyError:
            continue


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    """Convert a string of 6 characters of ethernet address into a dash separated hex string"""
    return ":".join(["%02x" % i for i in a])


# MAC address
def get_mac() -> str:
    """Returns the MAC address of the computer in the format 00:00:00:00:00:00"""
    return ":".join(
        [
            hex(uuid.getnode())[2:][i : i + 2]
            for i in range(0, len(hex(uuid.getnode())[2:]), 2)
        ]
    )
