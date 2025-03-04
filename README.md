# 🔨 HAMMER OF THE GODS - Extended Network Toolkit


## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Available Modules](#available-modules)
- [Security Notice](#security-notice)
- [License](#license)

## 🌐 Overview

HAMMER OF THE GODS is an advanced network toolkit designed for network administrators and security professionals. It offers a comprehensive set of features for network discovery, scanning, and security testing across both IPv4 and IPv6 networks. The toolkit includes various attack simulation capabilities like ARP spoofing, IPv6 ND spoofing, and network blackout features, making it perfect for authorized security assessments.

## ✨ Features

- Interactive CLI menu with 13 different scanning and testing options
- Combined IPv4 network scanning (ARP, Ping-Sweep, Nmap-Discovery, Service-Scan)
- Advanced IPv6 network scanning with OS fingerprinting
- Artistic terminal output including banner art
- Tabular display of discovered devices
- MAC vendor lookup (enhanced via maclookup.app)
- ARP spoofing (MITM/Block) for IPv4
- IPv6 ND-spoofing (MITM/Block) for IPv6
- DAI/Port-Security/WLAN-Isolation testing (ARP-based)
- DNS hostname lookup (Reverse DNS)
- Network blackout capabilities (IPv4 via ARP or iptables)
- IPv6 blackout via fake router advertisements
- Extensive logging (CSV) with log_level support
- Asynchronous operations and dynamic delays for increased scan speed and reduced detection

## 🔧 Requirements

- Python 3.7 or higher
- Root/Administrator privileges
- Linux operating system (some features might work on macOS, but iptables functions are Linux-specific)

## ⚙️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/hammer-of-gods.git
cd hammer-of-gods
```

2. Install the required dependencies:
```bash
pip install netifaces scapy python-nmap tabulate requests
```

OR use the requirements file:
```bash
pip install -r requirements.txt
```

### Dependencies

The project relies on several Python libraries:
- `netifaces`: Network interface information
- `scapy`: Packet manipulation
- `python-nmap`: Python interface to Nmap
- `tabulate`: Pretty-print tabular data
- `requests`: HTTP library for MAC vendor lookups

## 🚀 Usage

Run the script with root/sudo privileges:

```bash
sudo python3 script.py
```

The tool must be run with elevated privileges to access raw sockets and perform network operations.

## 📚 Available Modules

The toolkit offers the following modules through its interactive menu:

1. **IPv4 Network Scan**: Combined scan using ARP, Ping, and Nmap
2. **IPv6 Network Scan**: Advanced scanning for IPv6 networks
3. **Display Found Devices**: Shows discovered devices in a tabular format
4. **DAI/Port Security Test**: Tests for ARP-based security mechanisms
5. **IPv6 ND Traffic Sniffing**: Detects IPv6 neighbor discovery traffic
6. **ARP Spoofing**: Man-in-the-middle attack simulation for IPv4
7. **IPv6 ND Spoofing**: Man-in-the-middle attack simulation for IPv6
8. **Network Blackout (ARP)**: Blocks all network traffic using ARP spoofing
9. **MITM Techniques Tips**: Information about DNS spoofing, SSL-Strip, etc.
10. **Exit**: Quit the program
11. **Optimized Network Scan**: Asynchronous IPv4 scanning (faster)
12. **IPv6 Blackout**: Disables IPv6 connectivity via fake router advertisements
13. **iptables Blackout**: Blocks network traffic using iptables rules

## 🔍 Notable Functions

### Network Scanning
- `scan_network_enhanced()`: Comprehensive IPv4 network scan
- `scan_network_ipv6()`: IPv6 network scan with options for OS and service discovery
- `async_scan_network_optimized()`: Asynchronous IPv4 scanning for faster results

### Attack Simulation
- `ARPSpoofer`: Class for ARP spoofing attacks (IPv4 MITM)
- `NDspoofer`: Class for Neighbor Discovery spoofing (IPv6 MITM)
- `blackout()`: Blocks all IPv4 network traffic via ARP spoofing
- `ipv6_blackout()`: Disables IPv6 connectivity using fake router advertisements
- `blackout_iptables()`: Uses iptables rules to block traffic

### Security Testing
- `detect_arp_security_mechanisms()`: Tests for DAI/Port Security/WLAN isolation
- `detect_ipv6_neighbors()`: Sniffs and logs IPv6 neighbor discovery traffic

## ⚠️ Security Notice

**IMPORTANT**: This toolkit is designed for authorized security testing and educational purposes only. Using these tools against networks without explicit permission is illegal and unethical. Always ensure you have proper authorization before using any of these features.

The tool includes intentional delays and stealth features to minimize potential disruption, but should still be used with caution.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- The ASCII art banner was created for an epic network scanning experience
- Thanks to all the open-source libraries that make this project possible

---

Made by HackDevOli with ❤️ for networking enthusiasts and security professionals.