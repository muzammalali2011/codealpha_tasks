#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse

# Simple Banner (Bina pyfiglet ke)
def show_banner():
    print("""
    ==============================
    |   ADVANCED NETWORK SNIFFER  |
    ==============================
    """)

# Packet Processing
def process_packet(packet):
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"\n[ Ethernet ] Source MAC: {src_mac} → Destination MAC: {dst_mac}")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"[ IP ] Source IP: {src_ip} → Destination IP: {dst_ip}")

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"[ TCP ] Source Port: {src_port} → Destination Port: {dst_port}")

    if packet.haslayer(HTTPRequest):
        print("[ HTTP Request ]")
        print(f"URL: {packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}")
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"Payload (First 100 chars):\n{payload[:100]}...")

    if packet.haslayer(Raw) and not packet.haslayer(HTTPRequest):
        print("[ Raw Data ] Hex Dump:", packet[Raw].load[:20].hex())

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network Interface (e.g., ens33)", required=True)
    parser.add_argument("-f", "--filter", help="BPF Filter (e.g., 'tcp port 80')", default="")
    args = parser.parse_args()

    print(f"[*] Sniffing on {args.interface} (Filter: {args.filter})...")
    sniff(iface=args.interface, filter=args.filter, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
