# codealpha_tasks
My CodeAlpha Task Submissions
# CodeAlpha Task 1: Network Sniffer

A Python script to capture and analyze network traffic using Scapy.

## Features
- Captures HTTP/TCP traffic
- Shows source/destination IPs and ports
- Filters specific traffic (e.g., `tcp port 80`)

## How to Run
```bash
sudo python3 sniffer.py -i ens33 -f "tcp port 80"
