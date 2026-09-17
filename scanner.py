# Multi-Threaded Hybrid Port Scanner

A fast, concurrent network tool built in **Python** that combines the raw packet control of **Scapy** with the reliability of standard **Sockets**. 

The tool features an intelligent **Hybrid Engine** that automatically toggles the scanning technique depending on the target location. This bypasses the traditional limitations of raw-packet injection over local loopback interfaces on Linux systems.

---

## 🚀 Features
* **Hybrid Scanning Modes:** Uses high-speed **TCP SYN stealth scanning** for remote targets and seamlessly drops back to standard **TCP Connect** for local addresses (`127.0.0.1`).
* **Service Banner Grabbing:** Extracts application and protocol header information from discovered open ports to identify running services.
* **Highly Concurrent:** Leverages a multi-threaded `ThreadPoolExecutor` to scan hundreds of ports simultaneously.
* **Interactive CLI:** Prompts for target domains or IP addresses and customizable port ranges.

---

## 🛠️ Requirements & Installation

This script requires Python 3 and administrative privileges to send raw packets (via Scapy).

### 1. Clone the repository
```bash
git clone https://github.com
cd YOUR-REPO-NAME
```

### 2. Install dependencies
Because the scanner uses advanced packet crafting, you must install the dependencies into your root environment:
```bash
sudo pip3 install scapy
```

---

## 💻 Usage

Run the scanner utilizing administrative privileges (`sudo`). This is mandatory so `Scapy` can hook into the operating system network stack to inject raw Layer 3 packets.

```bash
sudo python3 port_scanner.py
```

### Example Input/Output Sequence:
```text
==================================================
      MULTI-THREADED HYBRID PORT SCANNER        
==================================================
Enter Target IP or Domain (e.g., 127.0.0.1): 127.0.0.1
Enter START port (e.g., 1): 20
Enter END port (e.g., 1024): 1000

--------------------------------------------------
Scanning Target : 127.0.0.1 (127.0.0.1)
Scanning Ports  : 20 to 1000
Scan Engine     : TCP Connect (Socket Engine)
Threads Active  : 100
--------------------------------------------------

[+] Port 22    | Status: OPEN | Service: OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
[+] Port 80    | Status: OPEN | Service: Apache/2.4.52 (Ubuntu)
[+] Port 631   | Status: OPEN | Service: ipp

[+] Scan Complete.
```

---

## 🔍 How the Hybrid Engine Works

| Scanning Type | Target Type | Protocol | Strategy Details |
| :--- | :--- | :--- | :--- |
| **TCP SYN Scan (Scapy)** | Remote Hosts | Raw L3/L4 | Sends a stealthy single `SYN` packet. Parses response flags without opening a full three-way handshake (`SYN-ACK` represents open, then rapidly sends an immediate `RST` packet to close it). |
| **TCP Connect Scan (Socket)** | Local Host / Loopback | L4 OS Native | Interacts directly via standard kernel sockets. Avoids the packet dropping issues native to local Linux firewall handling of loopback loop interfaces. |

---

## ⚠️ Disclaimer
This tool is created strictly for **educational purposes** and **authorized security auditing**. Scanning infrastructure without prior explicit permission from the system owner is strictly illegal. The developer assumes no liability for misuse or damage caused by this program.
