# Exploit Template for use in future

# https://github.com/Z3R013x/OSWE-Like-0Click
# https://pwnit.io/category/oswe-like-machines/

import requests
import argparse
from string import printable, ascii_lowercase
import random
import sys
from os import path
from threading import Timer
import socket


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_warning(text):
    print(f"{bcolors.WARNING}[-] {text}{bcolors.ENDC}")


def print_success(text):
    print(f"{bcolors.OKGREEN}[+] {text}{bcolors.ENDC}")


def print_info(text):
    print(f"{bcolors.OKCYAN}[*] {text}{bcolors.ENDC}")


def print_fail(text):
    print(f"{bcolors.FAIL}[!] {text}{bcolors.ENDC}")


def get_revshell():
    t = Timer(3, trigger_webshell, "URL_ARG")  # Delayed Call
    t.start()
    # Start Listener


def trigger_webshell(url):
    try:
        requests.get(f"{url}")
    except requests.exceptions.Timeout:
        pass  # expected one
    except Exception as e:
        print_fail(f"Unexpected exception occured: {str(e)}")


parser = argparse.ArgumentParser(description='exploit configuration',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-t', '--rhost', type=str, help="Target IP", required=True)
parser.add_argument('-rp', '--rport', type=int, help="Target Port", default="80", required=False)
parser.add_argument('-l', '--lhost', type=str, help="Local IP", required=True)
parser.add_argument('-lp', '--lport', type=int, help="Local Port", default="4444", required=False)
parser.add_argument('-pr', '--proto', type=str, help="Target Protocol", default="http", required=False)
parser.add_argument('-d', '--debug-proxy', type=str,
                    help="if passed, all requests will go trough proxy please provide ip:port", required=False,
                    default="")

args = parser.parse_args()

proxies = {"http": f"{args.debug_proxy}"}

if __name__ == "__main__":
    print_success("Do your magic!")