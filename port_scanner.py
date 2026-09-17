import socket
import logging
from concurrent.futures import ThreadPoolExecutor

# Suppress scapy warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sr1

# Configurations
TARGET_IP = "127.0.0.1"  # Change to your target IP
PORT_RANGE = range(1, 1025)  # Scans standard ports 1-1024
THREADS = 50  # Adjust for speed (higher means faster but noisier)

def grab_banner(ip, port):
    """Attempts to grab the service banner using socket."""
    try:
        # Create a standard TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((ip, port))
            
            # Send a generic request for HTTP/services, or just wait for raw banner
            if port in:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "Unknown Service (No Banner)"
    except Exception:
        # Common fallback: resolve well-known port names if banner grab times out
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "Unknown Service"

def scan_port_syn(ip, port):
    """Performs a TCP SYN Scan using Scapy."""
    try:
        # Craft IP and TCP SYN packets
        ip_pkt = IP(dst=ip)
        tcp_pkt = TCP(dport=port, flags="S")
        packet = ip_pkt / tcp_pkt
        
        # Send packet and wait for 1-second timeout response
        response = sr1(packet, timeout=1.0, verbose=0)
        
        if response is not None and response.haslayer(TCP):
            # Check flags: 0x12 is SYN-ACK (Open)
            if response.getlayer(TCP).flags == 0x12:
                # Send RST packet immediately to close the half-open connection nicely
                sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
                
                # Identify running service
                service_info = grab_banner(ip, port)
                print(f"[+] Port {port:<5} | Status: OPEN | Service: {service_info}")
                
    except Exception as e:
        pass  # Quietly pass on failed packets

def main():
    print("-" * 50)
    print(f"Scanning Target : {TARGET_IP}")
    print(f"Scanning Ports  : {PORT_RANGE[0]} to {PORT_RANGE[-1]}")
    print("-" * 50)
    
    # ThreadPool for managing concurrent Scapy packets
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(lambda p: scan_port_syn(TARGET_IP, p), PORT_RANGE)

if __name__ == "__main__":
    main()
