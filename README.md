# Network Scanner

A feature-rich Python-based Network Scanner developed for cybersecurity and network analysis. This tool supports host discovery, TCP/UDP port scanning, SYN scanning, banner grabbing, OS detection, multi-host scanning, and scan report generation.

## Features

* ARP Host Discovery
* TCP Connect Scan
* SYN (Half-Open) Scan
* UDP Scan
* Service Detection
* Banner Grabbing
* Basic OS Detection (TTL-based)
* Multi-Host Scanning
* Progress Bar
* Colored Terminal Output
* Scan Report Export (.txt)

## Technologies Used

* Python 3
* Scapy
* Socket Programming
* Multithreading
* Networking Concepts

## Installation

Clone the repository:

```bash
git clone https://github.com/sharadjangir/network-scanner.git
cd network-scanner
```

Install dependencies:

```bash
pip install scapy
```

## Usage

### ARP Host Discovery

```bash
sudo python3 network_scanner.py --discover -t 192.168.1.0/24
```

### TCP Connect Scan

```bash
python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000
```

### Banner Grabbing

```bash
python3 network_scanner.py --portscan -t 192.168.1.5 -p 22,80,443 --banner
```

### SYN Scan

```bash
sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --syn
```

### UDP Scan

```bash
sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 53,123,161 --udp
```

### OS Detection

```bash
sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --os
```

### Save Scan Report

```bash
python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --save
```

## Project Structure

```text
network-scanner/
│
├── network_scanner.py
├── README.md
└── requirements.txt
```

## Sample Features Implemented

* ARP-based live host discovery
* Multi-threaded TCP port scanning
* SYN stealth scanning
* UDP service probing
* Banner grabbing and service identification
* TTL-based operating system fingerprinting
* Exportable scan reports

## Future Improvements

* JSON Report Export
* CSV Report Export
* HTML Dashboard Reports
* GUI Version (Tkinter/PyQt)
* IPv6 Support
* Advanced OS Fingerprinting
* Vulnerability Detection Integration

## Author

**Sharad Jangir**

B.Tech (Cyber Security)
Government Engineering College, Ajmer
Bikaner Technical University

GitHub: https://github.com/sharadjangir

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Always obtain proper permission before scanning networks or systems that you do not own.
