from pyket import network, packet
from colorama import Fore
import os


def main():
    os.system("clear") if os.name != "nt" else os.system("cls")

    print(
        f"{Fore.LIGHTRED_EX}Welcome to Pyket!{Fore.RESET}"
        + "\n\nPyket is still in development, it lacks features.\n"
    )
    input(f"{Fore.LIGHTRED_EX}Press enter to begin capture... ")

    packet.capture(network.get_interface())


if __name__ == "__main__":
    main()
