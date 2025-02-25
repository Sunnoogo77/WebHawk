import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode
from core.report_manager import update_report

IDOR_PATTERNS = ["id", "user_id", "profile_id", "order_id", "account", "session", "token"]

IDOR_VALUES = [
    "1", "0001", "9999", "-1", "0", "123", "456", "789",
    "' OR '1'='1", "' OR '1'='2", "NULL", "true", "false"
]

def extract_idor_parameters(url):
    """Extrait les paramètres IDOR potentiels d'une URL"""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    potential_idor_params = {}
    for key in query_params:
        if any(pattern in key.lower() for pattern in IDOR_PATTERNS):
            potential_idor_params[key] = query_params[key][0]  # Prendre la première valeur

    return parsed_url, potential_idor_params

def scan_idor(target_url, formatted_target):
    """Scanne les vulnérabilités IDOR en modifiant les identifiants dans les paramètres"""
    
    print(f"\n🔍 Scan IDOR sur {formatted_target}...")

    parsed_url, idor_params = extract_idor_parameters(target_url)

    if not idor_params:
        print("⚠️ Aucun paramètre IDOR détecté dans l'URL.")
        return {}

    original_response = requests.get(target_url).text
    findings = {}

    for param, original_value in idor_params.items():
        for value in IDOR_VALUES:
            modified_params = idor_params.copy()
            modified_params[param] = value
            new_query = urlencode(modified_params)
            new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

            try:
                response = requests.get(new_url)
                if response.status_code == 200 and response.text != original_response:
                    print(f"🔥 IDOR détecté avec `{param}={value}` ➝ {new_url}")
                    findings[new_url] = "VULNERABLE"
                else:
                    print(f"✅ Pas vulnérable avec `{param}={value}`")

            except requests.exceptions.RequestException as e:
                print(f"❌ Erreur lors de la requête : {e}")

    if not findings:
        print("\n✅ Aucun IDOR détecté.")

    return findings
