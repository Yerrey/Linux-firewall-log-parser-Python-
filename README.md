# Linux Firewall Log Parser

A Python-based log parser that extracts structured network telemetry from Linux iptables firewall logs. This script parses a log file specifically tailored to
detect network scans using iptables and rsyslog. This is the start of this project, will be adding more.



## Overview

This project parses raw iptables logs and extracts:

- Source IP address
- Destination IP address
- Protocol (TCP, UDP, ICMP)
- Source Port
- Destination Port

The output is structured as a Python dictionary for further analysis, alerting, or SIEM ingestion.

## Architecture

1. iptables logs suspicious TCP flag patterns (SYN, NULL, FIN, XMAS).
2. rsyslog filters kernel log messages containing "NETWORK SCAN DETECTED".
3. Logs are written to /var/log/iptables.log.
4. Python parser extracts SRC/DST/FLAGS and outputs structured JSON.

## Example Log Line

2026-02-05T19:59:43.939150-06:00 raspberryPi kernel: [4524825.077151] NETWORK SCAN DETECTED: IN=wlan0 OUT= MAC=2c:cf:67:7f:4a:62:ba:cc:d5:e8:2f:37:08:00 SRC=192.0.2.10 DST=198.51.100.25 
LEN=44 TOS=0x00 PREC=0x00 TTL=46 ID=65427 PROTO=TCP SPT=36003 DPT=3971 WINDOW=1024 RES=0x00 SYN URGP=0

## Example Output

{
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.25",
  "proto": "TCP",
  "src_port": "36003",
  "dst_port": "3971"
}

## How It Works

- Uses Python `re` module with named capture groups
- Processes logs line-by-line
- Extracts structured network metadata
- Designed to support future alerting logic

## Future Enhancements

- JSON export
- Structured logging to file
- Port scan detection logic
- Alerting via webhook
- Integration with lightweight SIEM systems

## Author

Rey Maldonado  
Cybersecurity | Network Security | SOC Engineering
