# Vérification des en-têtes HTTP

import requests
import os
from core.report_manager import update_report

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "expected": "max-age=63072000; includeSubDomains",
        "description": "Forcer HTTPS pour éviter les attaques MITM"
    },
    "X-Frame-Options": {
        "expected": "DENY",
        "description": "Empêcher le Clickjacking"
    },
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "description": "Empêcher le MIME Sniffing"
    },
    "X-XSS-Protection": {
        "expected": "1; mode=block",
        "description": "Activer la protection contre le XSS"
    },
    "Content-Security-Policy": {
        "expected": "default-src 'self'",
        "description": "Restreindre l'exécution de scripts (CSP)"
    },
    "Referrer-Policy": {
        "expected": "strict-origin-when-cross-origin",
        "description": "Limiter l'exposition des URLs référentes"
    },
    "Permissions-Policy": {
        "expected": "camera=(), microphone=(), geolocation=()",
        "description": "Restreindre les accès aux API du navigateur"
    }
}

def format_url(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    return target

def check_security_headers(headers):
    """Vérifie la présence et la bonne configuration des headers de sécurité"""
    missing_headers = []
    misconfigured_headers = []
    findings = {}

    for header, data in SECURITY_HEADERS.items():
        if header not in headers:
            missing_headers.append(header)
        else:
            value = headers[header]
            if data["expected"] not in value:
                misconfigured_headers.append((header, value, data["expected"]))
            findings[header] = value

    return findings, missing_headers, misconfigured_headers

def scan_headers(report_path, target):
    if not os.path.exists(report_path):
        print(f"❌ ERREUR : Le fichier de rapport {report_path} est introuvable AVANT le scan !")
        return

    print(f"\n\t==============Scan des en-tête HTTP sur -->{target}<-- 🔍 ==============\n")
    
    target = format_url(target)
    
    try :
        response = requests.get(target, timeout=5)
        headers = response.headers
        
        print("\n\t Headers de Securité Présent :")
        for key, value in headers.items():
            
            print(f" {key}: {value}")
            
        findings, missing_headers, misconfigured_headers = check_security_headers(headers)
        
        if missing_headers:
            print("\n\t Headers de Securité Manquants :")
            for header in missing_headers:
                print(f"-->{header} (Protection abscente)")
                
                
        update_report(report_path, "headers_scan", {
            "headers_received": dict(headers),
            "missing_headers": missing_headers,
            "misconfigured_headers": misconfigured_headers
        })
    
    except requests.exceptions.RequestException as e:
        print(f"\n Erreur dlors de la requête : {e}")
    
    print("\n✅ Analyse des headers terminée.")