# Enhanced Backdoor Project

## Overview

This project demonstrates a simple, encrypted client-server backdoor for educational purposes. It allows remote command execution, file transfer, and keylogging between a server (controller) and a client (target) over a TCP connection.

## Required Libraries

- `cryptography`
- `pynput`
- `mss`
- `opencv-python (cv2)`
- `numpy`
- `pillow (PIL)`

## Core Features

- **Encrypted Communication:**  
  All data exchanged between the server and the client is encrypted using Fernet symmetric encryption.

- **Remote Shell:**  
  Execute arbitrary shell commands on the target machine and receive the output.

- **File Transfer:**  
  Upload and download files between the server and the target.

- **Keylogger:**  
  Start, stop, and retrieve logs from a keylogger running on the target.

- **Reliable Data Transmission:**  
  Uses JSON serialization and chunked data transfer for robust communication.

## Important Notice

This software is provided strictly for educational and research purposes. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The authors assume no responsibility for misuse.
