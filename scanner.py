import socket
import logging
from concurrent.futures import ThreadPoolExecutor

# Suppress scapy warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def grab_banner(ip, port):
    """Attempts to grab the service banner using socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((ip, port))
            
            if port == 80 or port == 443 or port == 8080:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "Unknown Service (No Banner)"
    except Exception:
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "Unknown Service"

def scan_port_socket(ip, port):
    """Fallback standard TCP Connect scan (Reliable for localhost/127.0.0.1)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:  # 0 means connection was successful
                service_info = grab_banner(ip, port)
                print(f"[+] Port {port:<5} | Status: OPEN | Service: {service_info}")
    except Exception:
        pass

def scan_port_syn(ip, port):
    """Performs a TCP SYN Scan using Scapy (Best for remote IPs)."""
    try:
        ip_pkt = IP(dst=ip)
        tcp_pkt = TCP(dport=port, flags="S")
        packet = ip_pkt / tcp_pkt
        
        response = sr1(packet, timeout=0.8, verbose=0)
        
        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                # Send RST packet immediately to close the half-open connection nicely
                sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=0.3, verbose=0)
                
                service_info = grab_banner(ip, port)
                print(f"[+] Port {port:<5} | Status: OPEN | Service: {service_info}")
    except Exception:
        pass

def main():
    print("=" * 50)
    print("      MULTI-THREADED HYBRID PORT SCANNER        ")
    print("=" * 50)
    
    target = input("Enter Target IP or Domain (e.g., 127.0.0.1): ").strip()
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Error: Could not resolve hostname.")
        return

    try:
        start_port = int(input("Enter START port (e.g., 1): "))
        end_port = int(input("Enter END port (e.g., 1024): "))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        print("[-] Error: Invalid port range selection (Must be 1 - 65535).")
        return

    port_range = range(start_port, end_port + 1)
    threads = 100  
    
    is_localhost = target_ip in ("127.0.0.1", "::1", "localhost") or target_ip.startswith("127.")
    scan_method = scan_port_socket if (is_localhost or not SCAPY_AVAILABLE) else scan_port_syn
    method_name = "TCP Connect (Socket Engine)" if scan_method == scan_port_socket else "TCP SYN (Scapy Engine)"

    print("\n" + "-" * 50)
    print(f"Scanning Target : {target_ip} ({target})")
    print(f"Scanning Ports  : {start_port} to {end_port}")
    print(f"Scan Engine     : {method_name}")
    print(f"Threads Active  : {threads}")
    print("-" * 50 + "\n")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(lambda p: scan_method(target_ip, p), port_range)
        
    print("\n[+] Scan Complete.")

if __name__ == "__main__":
    main()
