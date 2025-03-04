# 🔨 HAMMER OF THE GODS - Advanced Network Toolkit

<div align="center">
  
![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

</div>

## 📋 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Modules](#-modules)
- [Technical Details](#-technical-details)
- [Security and Educational Notice](#-security-and-educational-notice)
- [Performance Optimization](#-performance-optimization)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

## 🌐 Overview

HAMMER OF THE GODS is a comprehensive network toolkit designed for network administrators, security professionals, and penetration testers. It provides an extensive set of features for network discovery, scanning, and security testing across both IPv4 and IPv6 networks. The toolkit includes various attack simulation capabilities like ARP spoofing, IPv6 Neighbor Discovery spoofing, and network blackout features, making it valuable for authorized security assessments and educational purposes.

## ✨ Features

- **Comprehensive Scanning**
  - Combined IPv4 scanning (synchronous and asynchronous options)
  - Advanced IPv6 network scanning with OS fingerprinting
  - Optimized asynchronous scanning with caching for faster results
  - Parallel scanning over multiple interfaces
  - Masscan integration for ultra-fast network sweeps

- **Display & Analysis**
  - Tabular display of discovered devices with detailed information
  - MAC vendor lookup (enhanced via maclookup.app)
  - Artistic terminal output with color-coded logging
  - Comprehensive logging in CSV format with adjustable log levels

- **Attack Simulation**
  - ARP spoofing (MITM/Block) for IPv4 networks
  - IPv6 ND-spoofing (MITM/Block) for IPv6 networks
  - Network blackout simulations (multiple methods)

- **Security Testing**
  - DAI/Port-Security/WLAN-Isolation testing (ARP-based)
  - DNS hostname resolution
  - IPv6 neighbor discovery monitoring

- **Performance Features**
  - Scan result caching in JSON format
  - Memory optimization via chunk-based streaming
  - Dynamic delays for stealth operation
  - Asynchronous operations for reduced scan time

## 🔧 Requirements

- **Python 3.7+**
- **Root/Administrator privileges** (required for raw socket operations)
- **Linux operating system** (some features might work on macOS, but iptables functions are Linux-specific)
- **Python Libraries:**
  - netifaces: Network interface information
  - scapy: Packet manipulation
  - python-nmap: Python interface to Nmap
  - tabulate: Pretty-print tabular data
  - requests: HTTP library for MAC vendor lookups
  - colorama: Terminal text coloring (optional)
  - tqdm: Progress bars (optional)

## ⚙️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/hammer-of-gods.git
cd hammer-of-gods
```

2. Install required dependencies:
```bash
pip install netifaces scapy python-nmap tabulate requests colorama tqdm
```
   
   OR use the requirements file:
```bash
pip install -r requirements.txt
```

3. For faster scanning, install masscan (optional):
```bash
sudo apt-get install masscan  # Debian/Ubuntu
sudo yum install masscan      # CentOS/RHEL
```

## 🚀 Usage

The tool must be run with elevated privileges to access raw sockets and perform network operations:

```bash
sudo python3 script.py
```

Upon launching, the program will:
1. Display an ASCII art banner
2. Prompt you to select a network interface
3. Present the main menu with various scanning and testing options

## 📚 Modules

### 1. Network Scanning
- **IPv4 Network Scan**: Combined scan using ARP, Ping Sweep, and Nmap Discovery
- **Optimized IPv4 Scan**: Asynchronous with multi-threading for faster results
- **IPv6 Network Scan**: Advanced IPv6 discovery with OS fingerprinting options
- **Parallel Interface Scan**: Simultaneous scanning across multiple interfaces
- **Masscan**: Ultra-fast port scanning integration (requires masscan installation)

### 2. Spoofing & Security Tools
- **ARP Spoofing**: Man-in-the-middle attack simulation for IPv4
- **ARP Security Testing**: Detection of Dynamic ARP Inspection, Port Security, and WLAN Isolation
- **IPv6 ND Spoofing**: Man-in-the-middle attack simulation for IPv6
- **IPv6 ND Sniffing**: Detects and monitors IPv6 neighbor discovery traffic

### 3. Blackout Options
- **ARP Blackout**: Blocks all IPv4 traffic using ARP spoofing
- **IPv6 Blackout**: Disables IPv6 connectivity via fake router advertisements
- **iptables Blackout**: Blocks network traffic using iptables rules

## 🔍 Technical Details

### Caching System
The toolkit implements a JSON-based caching system to store scan results temporarily. This speeds up repeated scans of the same network and reduces network traffic.

### Stealth Features
- Dynamic delay calculations based on network response times
- Rate limiting for ARP and other packet operations
- Configurable aggressive and stealth modes

### Memory Optimization
- Chunk-based streaming for large subnets
- ThreadPoolExecutor for parallel operations
- Resource limitation for stable execution

## ⚠️ Security and Educational Notice

**IMPORTANT**: This toolkit is designed EXCLUSIVELY for:
- Authorized security testing
- Educational purposes in controlled environments
- Network administration and troubleshooting

**LEGAL DISCLAIMER**: Using these tools against networks without explicit permission is:
- Illegal in most jurisdictions
- Unethical and potentially harmful
- May violate computer fraud and abuse laws

**DO NOT USE THIS TOOL FOR**:
- Unauthorized penetration testing
- Any form of network disruption
- Attacks against systems you don't own or have authorization to test

The tool includes safeguards and intentional delays to minimize potential disruption, but should still be used with extreme caution. The authors and contributors of this toolkit accept no liability for misuse or damage caused by improper usage.

## 🚀 Performance Optimization

- **Caching**: Scan results are cached for 1 hour by default (configurable)
- **Parallel Execution**: Multiple operations run simultaneously
- **Asynchronous I/O**: Non-blocking operations where possible
- **Rate Limiting**: Prevents network flooding while maintaining effectiveness

## 🔧 Troubleshooting

- **Permission Issues**: Ensure you're running with sudo/root privileges
- **Missing Dependencies**: Check all required packages are installed
- **Interface Not Found**: Verify the interface name and that it's up
- **Slow Scanning**: Try the asynchronous scan mode or adjust rate limits
- **No Results**: Check that the interface has a valid IP address

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

Made with ❤️ for networking enthusiasts and security professionals.

**Remember**: With great power comes great responsibility. Always use this tool ethically and legally.