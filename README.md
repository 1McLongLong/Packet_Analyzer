# Network Traffic Analyzer

A Python-based network security tool for real-time detection of malicious network activity. Built as a portfolio project to demonstrate SOC analyst skills including packet analysis, threat detection, and security automation.

## 🎯 Overview

This packet analyzer monitors network traffic in real-time and detects various types of malicious activity including port scans, data exfiltration attempts, SYN floods, and TCP flag anomalies. It integrates with threat intelligence APIs to identify known malicious actors.

## ✨ Key Features

### Detection Capabilities

**Port Scan Detection**
- Identifies when a source IP probes multiple ports on a target system
- Configurable thresholds for unique ports and time windows
- Tracks connection patterns across TCP, UDP, and ICMP protocols

**Data Exfiltration Detection**
- Monitors outbound data volumes to detect data theft
- Alerts on high-volume transfers and sustained data exfiltration
- Tracks transfer rates and packet counts

**SYN Flood Detection**
- Detects DoS/DDoS attacks via excessive SYN packets
- Alerts when source sends 100+ SYNs within 10 seconds
- Helps identify network resource exhaustion attempts

**TCP Flag Anomaly Detection**
Catches suspicious TCP flag patterns used in reconnaissance and evasion:
- **XMAS Scan** — FIN+PSH+URG flags (reconnaissance)
- **NULL Scan** — No flags set (stealth reconnaissance)
- **FIN Scan** — Only FIN flag (stealth port scanning)
- **SYN+FIN** — Invalid flag combination (firewall evasion)
- **URG-only / PSH-only** — Unusual traffic patterns

**Threat Intelligence Integration**
- Real-time IP reputation checks using AbuseIPDB API
- Identifies known malicious IPs during port scans
- Flags data exfiltration to command & control servers
- Caches results to minimize API calls

### Additional Features

- **Centralized Configuration** — All thresholds and settings in `config.py`
- **Alert Logging** — Security events saved to JSON log files
- **Clean Architecture** — Modular design with separate analyzers for each detection type
- **Efficient Processing** — Periodic cleanup prevents memory buildup
- **Production Ready** — Error handling and graceful degradation

## 🏗️ Project Structure
```
packet_analyzer/
├── capture.py                    # Main packet capture and orchestration
├── config.py                     # Centralized configuration
├── analyzers/
│   ├── port_scan.py             # Port scan detection logic
│   ├── data_exfiltration.py     # Data exfiltration detection
│   └── tcp_anomaly.py           # SYN flood & TCP flag anomaly detection
└── utils/
    ├── threat_intel.py          # IP reputation checking (AbuseIPDB)
    └── reporting.py             # Alert logging and reporting
```

## 🚀 Installation

### Prerequisites

- Python 3.7+
- Root/Administrator privileges (required for packet capture)
- Network interface access

### Required Libraries
```bash
pip install scapy requests
```

### Optional: Threat Intelligence

1. Sign up for a free API key at [AbuseIPDB](https://www.abuseipdb.com/)
2. Add your API key to `config.py`:
```python
ABUSEIPDB_API_KEY = "your-api-key-here"
```

## 📖 Usage

### Basic Usage
```bash
# Capture packets on default interface (unlimited)
sudo python3 capture.py

# Capture 1000 packets
sudo python3 capture.py  # Set PACKET_COUNT=1000 in config.py

# Capture on specific interface
# Set NETWORK_INTERFACE="eth0" in config.py
sudo python3 capture.py
```

### Configuration

Edit `config.py` to customize detection thresholds:
```python
# Port Scan Detection
PORT_SCAN_UNIQUE_PORTS_THRESHOLD = 25    # Ports to trigger alert
PORT_SCAN_TIME_WINDOW = 60                # Time window in seconds

# Data Exfiltration Detection
EXFIL_VOLUME_THRESHOLD_MB = 50            # MB to trigger alert
EXFIL_TIME_WINDOW = 300                   # 5 minutes

# SYN Flood Detection
SYN_FLOOD_THRESHOLD = 100                 # SYN packets
SYN_FLOOD_TIME_WINDOW = 10                # 10 seconds

# Network Interface
NETWORK_INTERFACE = None                  # None = default, "lo" = localhost
PACKET_COUNT = 0                          # 0 = unlimited
```

## 🧪 Testing

### Test Port Scan Detection
```bash
# Terminal 1: Start analyzer
sudo python3 capture.py

# Terminal 2: Perform port scan
nmap -p 1-100 scanme.nmap.org
```

### Test TCP Flag Anomalies
```bash
# XMAS scan
nmap -sX -p 1-50 scanme.nmap.org

# NULL scan
nmap -sN -p 1-50 scanme.nmap.org

# FIN scan
nmap -sF -p 1-50 scanme.nmap.org
```

### Test Data Exfiltration
```bash
# Terminal 1: Start receiver
nc -l 8080 > /dev/null

# Terminal 2: Start analyzer (on loopback)
sudo python3 capture.py  # Set interface="lo" in config

# Terminal 3: Send data
dd if=/dev/urandom bs=1M count=10 | nc 127.0.0.1 8080
```

### Test SYN Flood
```bash
# Use hping3 or similar tool
sudo hping3 -S -p 80 --flood --rand-source target-ip
```

## 📊 Example Output
```
============================================================
⚠️  PORT SCAN DETECTED!
============================================================
Source IP:     192.168.1.100
Target IP:     scanme.nmap.org
Unique Ports:  47
Total Attempts: 94
⚠️  KNOWN MALICIOUS IP!
   Abuse Score: 85%
   Reports:     127
   Country:     CN
   ISP:         Example Hosting Ltd
------------------------------------------------------------

============================================================
🚨 TCP FLAG ANOMALY DETECTED!
============================================================
Type:          XMAS Scan
Source IP:     192.168.1.100
Target IP:     10.0.0.50
Packets:       23
Flags:         FIN+PSH+URG
Time:          2024-02-16 14:23:45
------------------------------------------------------------
```

## 🛠️ Technical Details

### Detection Algorithms

**Port Scan Detection**
- Tracks unique destination ports per source-target pair
- Uses sliding time window analysis
- Configurable thresholds prevent false positives

**Data Exfiltration Detection**
- Monitors actual packet sizes (not estimated)
- Calculates transfer rates (MB/min)
- Distinguishes between high-volume bursts and sustained transfers

**SYN Flood Detection**
- Counts SYN packets without corresponding ACK
- Time-windowed analysis prevents memory buildup
- Baseline threshold of 100 SYNs per 10 seconds

**TCP Flag Anomaly Detection**
- Validates flag combinations against RFC standards
- Identifies reconnaissance techniques (NULL, FIN, XMAS)
- Detects evasion attempts (SYN+FIN, URG-only)

### Performance Optimizations

- **Caching**: Threat intelligence results cached for 1 hour
- **Cleanup**: Automatic removal of expired tracking data
- **Periodic Checks**: Detection runs every N packets (configurable)
- **Memory Efficient**: Sliding windows prevent unbounded memory growth

## 🎓 Skills Demonstrated

This project showcases key SOC analyst competencies:

- **Network Traffic Analysis**: Deep packet inspection using Scapy
- **Threat Detection**: Multiple detection techniques for various attack vectors
- **Security Automation**: Automated alerting and logging
- **Threat Intelligence**: API integration for IP reputation checks
- **Python Development**: Clean code, modular architecture, error handling
- **Security Mindset**: Understanding of attack techniques and defensive measures

## 🔒 Security Considerations

- Requires root privileges for packet capture
- Only captures packet headers, not payload data
- Threat intelligence queries skip private IP ranges
- Alert logs may contain sensitive IP addresses
- Rate limiting implemented for API calls
