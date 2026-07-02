# Scan des ports ouverts

import socket
import concurrent.futures
from core.config import DEFAULT_TIMEOUT, DEFAULT_THREADS

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
    465: "SMTPS",
    587: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "OracleDB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT",
    9090: "HTTP-ALT2",
    27017: "MongoDB",
}


def scan_port(target, port, timeout=2):
    """Scan a single port on the target."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                print(f"\t[+] Port {port} ({service}) est ouvert")
                return port, service
    except (socket.timeout, OSError):
        pass
    return None


def scan_ports(target, ports=None, threads=DEFAULT_THREADS):
    """Scanne une liste de ports en parallèle sur une cible."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print(f"\n\t==============Scan des ports sur -->{target}<-- 🔍 ==============\n")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x[0])

    if open_ports:
        print(f"\n✅  SCAN TERMINÉ : {len(open_ports)} port(s) ouvert(s) détecté(s) : {open_ports}\n")
    else:
        print("\n[!] Aucun port ouvert détecté.\n")
    return open_ports