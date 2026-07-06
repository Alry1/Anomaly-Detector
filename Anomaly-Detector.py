from scapy.all import sniff
from scapy.layers.inet import IP, TCP

# List of ports considered common targets for attackers
SUSPICIOUS_PORTS = {22, 23, 4444, 6667}

def analyze_packet(packet):
    """
    Analyzes network packets to detect suspicious connection attempts.
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Monitor connection attempts to sensitive ports
        if dst_port in SUSPICIOUS_PORTS:
            print(f"[!] Alert: Suspicious activity detected from {src_ip} on port {dst_port}")

        # Monitor for network scanning (SYN Scan)
        if flags == 'S':
            print(f"[*] New connection attempt (SYN) from {src_ip}")

def start_monitor():
    print("[*] Network monitor started...")
    # Sniff packets; store=0 to minimize memory consumption
    sniff(filter="ip", prn=analyze_packet, store=0)

if __name__ == "__main__":
    try:
        start_monitor()
    except PermissionError:
        print("[!] Error: Please run the script with root/administrator privileges.")