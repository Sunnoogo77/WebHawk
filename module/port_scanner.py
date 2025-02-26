# Scan des ports ouverts

import socket
import os
import concurrent.futures


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    135: "RPC",
    139: "NETBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    3306: "MYSQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-PROXY",
    }

def scan_port(target, port):
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                print(f"Port {port} ({service}) is open")
                return port, service
    except Exception as e:
        pass
    return None

def scan_ports(target, ports=COMMON_PORTS.keys()):
    """Scanne une liste de ports en parallèle sur une cible"""

    print(f"\n\t==============Scan des ports sur -->{target}<-- 🔍 ==============\n")
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        print(f"\n✅ SCAN TERMINÉ : Ports ouverts détectés : {open_ports}\n")
    else:
        print("\n❌ Aucun port ouvert détecté.\n")
    return open_ports