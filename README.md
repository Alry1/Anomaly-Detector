# Anomaly Detector

A simple and effective tool to monitor network traffic and detect suspicious connection attempts in real-time using the **Scapy** library.

## Features
* Monitors network traffic (IP/TCP).
* Detects connection attempts on sensitive ports (e.g., 22, 23, 4444, 6667).
* Detects network scanning (SYN Scan).

## Prerequisites
You need to install the `scapy` library to run the script:
```bash
pip install scapy


Usage
Note: This script requires Administrator/Root privileges to capture network packets.
1. Open your terminal with administrative privileges.
2. Run the script:

python Anomaly-Detector.py

Disclaimer
This tool is for educational and security research purposes only. Please ensure you have the necessary authorization to monitor the network you are working on.

