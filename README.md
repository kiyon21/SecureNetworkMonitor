# SecureNetworkMonitor
Monitors systems and networks to secure them against policy violations and attacks.

# C++ Nework Monitor

This is a basic Intrusion Detection System implemented in C++ that monitors network traffic, detects potential intrusions based on predefined rules, and generates alerts.

## Features

- Network packet capture and analysis
- Rule-based detection system
- Detection of common attack patterns:
  - IP blacklisting
  - Port scanning detection
  - SYN flood detection
  - Malicious payload pattern detection
- Logging and alerting system

## Requirements

- C++ compiler with C++11 support
- libpcap development library
- POSIX-compliant operating system (Linux, macOS)
   

## How This Works

Monitors network traffic and detects potential intrusions using several methods:

1. **Packet Capture**: Uses libpcap to capture network packets from a specified interface
2. **Traffic Analysis**: Examines packet headers and payloads for suspicious patterns
3. **Rule-Based Detection**: Applies predefined rules to identify potential threats
4. **Alerting System**: Logs alerts when suspicious activity is detected


### Detection Methods Implemented

1. **IP Blacklisting**: Blocks traffic from known malicious IP addresses
2. **Port Scan Detection**: Identifies when a single source IP attempts to connect to multiple ports in a short time
3. **SYN Flood Detection**: Detects potential DoS attacks using TCP SYN packets
4. **Payload Pattern Matching**: Searches packet payloads for known malicious patterns


### System Components

- **Logger**: Handles logging of events and alerts
- **Rule**: Defines detection rules and parameters
- **Alert**: Represents a security alert with relevant information
- **PacketInfo**: Stores parsed packet information
- **TrafficAnalyzer**: Analyzes traffic patterns for anomalies
- **IntrusionDetectionSystem**: Main class that coordinates all components


## Building and Running

To compile and run this IDS:

1. Install the libpcap development library:

```plaintext
sudo apt-get install libpcap-dev  
```


2. Compile the program:

```plaintext
g++ -o ids ids.cpp -lpcap -pthread -std=c++11
```


3. Run the program (requires root privileges):

```plaintext
sudo ./ids etn8  # Replace en8 with your network interface
```


This implementation provides a solid foundation for understanding how network intrusion detection systems work while demonstrating core C++ concepts like multithreading, object-oriented design, and network programming.