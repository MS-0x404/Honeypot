#!/usr/bin/env python3
import socket
import requests
import json 
import threading
import sys
import logging
from datetime import datetime
import time
import os

dirlog = "/var/log/honeypot_logs"
logging.basicConfig(filename=f"{dirlog}/log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log",
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                filemode='w', level=logging.INFO)    

if len(sys.argv) > 1:
    porta = int(sys.argv[2])
    host = sys.argv[1]

else:
    porta = 2323  
    host = "0.0.0.0"

# Handle Thread and Client 
workers = []
hackers = []
banner = {
    2222: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
    2121: "220 (vsftpd 2.3.4)\r\n",
    2323: "telnetd (BSD 2019) on Ubuntu\r\n"
}

# Best Practice for handling every thread
client_lock = threading.Lock()
client_event = threading.Event()

try:
    
    honey = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    honey.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    honey.bind((host,porta))
    honey.listen(3)

                
    print(f"Honeypot in ascolto --> {host}:{porta}")



except OSError as e:
    print(f"Error: {e}")
    if 'honey' in locals(): honey.close()
    sys.exit()

def detector(addr, logger):
    API_key = os.getenv("API_TOKEN")
    
    # [FIX] Gestione errori API per evitare crash del thread
    try:
        response = requests.get(f"https://vpnapi.io/api/{addr}?key={API_key}", timeout=10)
        response.raise_for_status() 
        data = json.loads(response.text)
        
        msg = ""
        if data['security']['vpn']:
            msg = f"\nVPN DETECTED: {data['security']['vpn']}\nCountry: {data['location']['country']}\nLatitude: {data['location']['latitude']}\nLongitude: {data['location']['longitude']}"
        elif data['security']['proxy']:
            msg = f"\nPROXY DETECTED: {data['security']['proxy']}\nCountry: {data['location']['country']}\nLatitude: {data['location']['latitude']}\nLongitude: {data['location']['longitude']}"
        elif data['security']['tor']:
            msg = f"\nTOR DETECTED: {data['security']['tor']}\nCountry: {data['location']['country']}\nLatitude: {data['location']['latitude']}\nLongitude: {data['location']['longitude']}"
        elif data['security']['relay']:
            msg = f"\nRELAY DETECTED: {data['security']['relay']}\nCountry: {data['location']['country']}\nLatitude: {data['location']['latitude']}\nLongitude: {data['location']['longitude']}"
        else:
            msg = f"\nIP CLEAN\nCity: {data['location']['city']}\nCountry: {data['location']['country']}\nNetwork: {data['network']['network']}\nLatitude: {data['location']['latitude']}\nLongitude: {data['location']['longitude']}"
        
        logger.info(msg)

    except Exception as e:
        logger.error(f"Errore nel detector per {addr}: {e}")

def shell(client,username,password,logger):
    while True:
        try:
            if porta == 2121:
                client.send("".encode())
                data = client.recv(1024)
                logger.info(f"{data}")
                cmd = data.decode(errors="ignore").strip()
                if cmd == "help":
                    client.send("""214-The following commands are recognized.
    ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD
    MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR
    RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD
    XPWD XRMD
    214 Help OK.\n""".encode())
                else:
                    client.send("500 Unknown command.\n".encode())
            elif porta == 2323:
                    client.send(f"[{username}@ubuntuOS ~]$ ".encode())  
                    data = client.recv(1024)
                    cmd = data.decode(errors="ignore").strip()
                    if cmd.split()[0] in ["wget", "curl", "python"]:
                        logger.critical(f"{cmd}")
                    else:
                        logger.info(f"{cmd}")
                    if cmd == "whoami":
                        client.send(f"{username}\n".encode())
                    elif cmd == "id":
                        client.send(f"uid=1005({username}) gid=1005({username}) groups=1005({username}),998(wheel)\n".encode())
                    elif cmd == "pwd":
                        client.send(f"/home/{username}\n".encode())
                    elif cmd == "ls":
                        client.send("Documents Desktop Downloads Pictures\n".encode())
                    elif cmd == "uname":
                        client.send("Linux\n".encode())
                    elif cmd == "uname -a":
                        client.send(f"Linux ubuntuOS 3.17-ubuntu #1 SMP PREEMPT_DYNAMIC Mon, {datetime.now().strftime('%d %m %Y %H:%M:%S')} +0000 x86_64 GNU/Linux\n".encode())
                    elif cmd == "exit" or cmd == "quit":
                        break
                    else:
                        client.send(f"bash: {cmd}: command not found\n".encode())
        except OSError as e:
            logger.error(f"Socket error: {e}")
            break
        except Exception as e:
            logger.error(f"Error General: {e}")
            break
        except BrokenPipeError:
            break

    with client_lock:
        if client in hackers: 
            hackers.remove(client)
            client.close()


        

def handle_client(client,logger):
    try:
        time.sleep(1)
        if porta == 2323:
            client.send(f"""Connection to {client.getpeername()[0]} 23 port [tcp/telnet] succeeded!

*********************************************************
* WARNING: AUTHORIZED ACCESS ONLY           *
* Disconnection is monitored and logged.           *
*********************************************************

""".encode())
        elif porta == 2121:
            client.send(f"Connection to {client.getpeername()[0]} 21 port [tcp/ftp] succeeded!".encode())

        client.send(banner[porta].encode())
        
        #fingerprinter_bytes = client.recv(1024)
        #client_fingerprinter_bytes = fingerprinter_bytes.decode(errors="ignore").strip()
        #print(f"[{datetime.now()}] Fingerprinter: {client_fingerprinter_bytes}")

        while True:
            try:
                first = datetime.now()
                if porta == 2323:
                    client.send("ubuntuOS Login: ".encode())
                elif porta == 2121:
                    client.send("USER ".encode())
                username = client.recv(1024)
                USER = username.decode(errors="ignore").strip()
                logger.critical(f"USER {USER}")
                if porta == 2121:
                    client.send("331 Please specify the password.\n".encode())
                
                if porta == 2323:
                    client.send("Password: ".encode())
                elif porta == 2121:
                    client.send("PASS ".encode())
                
                password = client.recv(1024)
                PASS = password.decode(errors="ignore").strip()
                if porta == 2121:
                    client.send("230 Login successful.\n".encode())
                last = datetime.now()

                delta = last - first          # timedelta
                seconds = delta.total_seconds()  # float in secondi

                logger.critical(f"PASS {PASS}")
                
                if seconds <= 0.2:
                    logger.info(f"Bot! Time {seconds} ")
                else:
                    logger.info(f"Human! Time {seconds}")

                time.sleep(3)

                shell(client,USER,PASS,logger)
                break
            except OSError as e:
                logger.error(f"Socket error: {e}")
                break
    except Exception as e:
        logger.info(f"Client disconnected: {e}")
    finally:
        client.close()


def main():
    try:
        while True:
            obj,addr = honey.accept()
            logger = logging.getLogger(f"{addr[0]}:{porta}")
            print(f"Connessione Rilevata {addr[0]}:{addr[1]}")
            logger.info(f"Connessione Rilevata {addr[0]}:{addr[1]}")
            try:
                hostname = socket.gethostbyaddr(addr[0])[0]
            except socket.herror:
                hostname = "unknown"
            logger.info(f"Hostname: {hostname}")


            with client_lock:
                hackers.append(obj)
                ip_handler = threading.Thread(
                    target=detector,
                    args=(addr[0],logger,)
                )
                client_handler = threading.Thread(
                    target=handle_client,
                    args=(obj,logger,)
                )
            ip_handler.daemon = True
            client_handler.daemon = True
            ip_handler.start()
            client_handler.start()
            workers.append(ip_handler)
            workers.append(client_handler)
            logger.info("----------------------")
    except KeyboardInterrupt:
        print("[!] Bye...")
        obj.close()
        honey.close()
        sys.exit()


if __name__ == "__main__":
    main()

