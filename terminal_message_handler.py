"""
@author Merlin von der Weide
@version 2.0.0
@date 2025

"""
import sys

from colorama import Fore, init as colorama_init

# Initialize colorama for Windows support
colorama_init(autoreset=True)


def print_error(message, fatal=True):
    print(Fore.RED, "[!] ERROR: %s" % message)
    if fatal:
        sys.exit(1)


def print_warning(message):
    print(Fore.YELLOW, "[-] WARN: %s" % message)


def print_info(message):
    print(Fore.LIGHTBLUE_EX, "[+] INFO: %s" % message)

def print_success(message):
    print(Fore.GREEN, "%s" % message)


def print_found(message):
    """Print a 'found' message in green."""
    print(Fore.GREEN + "[✓] " + str(message) + Fore.RESET)


def print_not_found(message):
    """Print a 'not found' message in red."""
    print(Fore.RED + "[✗] " + str(message) + Fore.RESET)


def print_partial(message):
    """Print a 'partial/warning' message in yellow."""
    print(Fore.YELLOW + "[~] " + str(message) + Fore.RESET)