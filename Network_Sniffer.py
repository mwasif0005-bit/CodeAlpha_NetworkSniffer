"""
============================================================================
CodeAlpha Internship - Cybersecurity Domain
Project: Basic Network Sniffer
Author: Muhammad Wasif
Date: 2026
Description:
    A professional network packet sniffer that captures live network traffic,
    extracts IP addresses, protocols, ports, and payloads, and saves
    the captured data to a structured text report.
============================================================================
"""

import os
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# ======================== CONFIGURATION ========================
PACKET_COUNT = 20          # Number of packets to capture
OUTPUT_FILE = "sniffer_report.txt"  # Report file name
# ================================================================

def log_message(message, output_file):
    """
    Writes a message to both console and output file.
    """
    print(message)
    output_file.write(message + "\n")

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Extracts and displays: Timestamp, Source/Destination IP,
    Protocol, Ports, and Payload (if available).
    """
    # Open file in append mode for each packet (ensures data isn't lost)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as report:
        separator = "=" * 60
        log_message(f"\n{separator}", report)

        # Timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_message(f"[{timestamp}] PACKET CAPTURED", report)

        # Check for IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl

            log_message(f"├── Source IP        : {src_ip}", report)
            log_message(f"├── Destination IP   : {dst_ip}", report)
            log_message(f"├── TTL              : {ttl}", report)

            # Identify Protocol
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                log_message(f"├── Protocol         : {protocol}", report)
                log_message(f"├── Source Port      : {src_port}", report)
                log_message(f"├── Destination Port : {dst_port}", report)
                log_message(f"├── TCP Flags        : {flags}", report)
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                log_message(f"├── Protocol         : {protocol}", report)
                log_message(f"├── Source Port      : {src_port}", report)
                log_message(f"├── Destination Port : {dst_port}", report)
            elif ICMP in packet:
                protocol = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                log_message(f"├── Protocol         : {protocol}", report)
                log_message(f"├── ICMP Type        : {icmp_type}", report)
                log_message(f"├── ICMP Code        : {icmp_code}", report)
            else:
                log_message(f"├── Protocol         : Other ({packet[IP].proto})", report)

            # Check for Raw payload
            if Raw in packet:
                payload_data = packet[Raw].load
                payload_hex = payload_data[:50].hex()
                try:
                    payload_text = payload_data[:50].decode('utf-8', errors='ignore')
                except:
                    payload_text = "[Non-printable]"
                log_message(f"├── Payload (Text)   : {payload_text}", report)
                log_message(f"├── Payload (Hex)    : {payload_hex}", report)
        else:
            log_message("├── Non-IP Packet (e.g., ARP)", report)

        log_message(f"{separator}", report)


def main():
    """
    Main function: Initializes the sniffer and captures network packets.
    """
    # Delete old report file if exists
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    # Header
    header = f"""
===========================================================
        COLDAPHA CYBERSECURITY INTERNSHIP              
        BASIC NETWORK SNIFFER                          
        Author: Muhammad Wasif                          
===========================================================
"""
    print(header)

    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(header + "\n")
        f.write(f"Analysis started at: {datetime.now()}\n")
        f.write(f"Total packets to capture: {PACKET_COUNT}\n")
        f.write("="*60 + "\n")

    print(f"[INFO] Capturing {PACKET_COUNT} packets...\n")
    print("[INFO] Press Ctrl+C to stop early.\n")

    try:
        sniff(prn=packet_callback, count=PACKET_COUNT, store=False)
    except PermissionError:
        print("\n[ERROR] Permission denied! Please run as Administrator/root.")
        print("[FIX]  Windows: Run CMD as Administrator")
        print("[FIX]  Linux/Mac: Use 'sudo python3 network_sniffer.py'")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[INFO] Sniffing stopped by user.")

    print(f"\n[SUCCESS] Report saved to: {OUTPUT_FILE}")
    print(f"[SUCCESS] Total packets captured: Check {OUTPUT_FILE}\n")


if __name__ == "__main__":
    main()
