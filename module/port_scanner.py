# Scan des ports ouverts

import socket

from urllib.parse import urlparse

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
    587:"SMTPs",
    465: "SMTPs1",
    443: "HTTPS",
    1521: "OracleDB",
    3306: "MYSQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-PROXY",
    }


def scan_port(target, port):
    print(f"[+] Tentative de connexion sur le port {port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                print(f"\t[+] Port {port} ({service}) est ouvert")
                return port, service
    except Exception as e:
        pass
    return None

def scan_ports(target, ports=COMMON_PORTS.keys()):
    """Scanne une liste de ports en parallèle sur une cible"""

    print(f"\n\t==============Scan des ports sur -->{target}<-- 🔍 ==============\n")
    
    open_ports = []
    
    for port in ports:
        result = scan_port(target, port)
        if result:
            open_ports.append(result)

    if open_ports:
        print(f"\n✅  SCAN TERMINÉ : Ports ouverts détectés : {open_ports}\n")
    else:
        print("\n[!][!][XXX] Aucun port ouvert détecté.\n")
    return open_ports