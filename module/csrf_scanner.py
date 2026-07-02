import requests
from html import escape as html_escape
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.config import create_session, DEFAULT_TIMEOUT


def find_forms(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Détecte les formulaires sur une page cible."""
    print(f"[+] Recherche de formulaires sur {target}...")
    try:
        session = session or create_session()
        response = session.get(target, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')

        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action") or target
            method = form.attrs.get("method", "get").lower()
            inputs = {input_tag.attrs.get("name"): input_tag.attrs.get("value", "")
                      for input_tag in form.find_all("input") if input_tag.attrs.get("name")}

            full_action_url = urljoin(target, action)
            print(f"[+] Formulaire trouvé : {full_action_url} ({method.upper()})")
            detected_forms.append({"action": full_action_url, "method": method, "inputs": inputs})

        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return []


def check_csrf_protection(form):
    """Vérifie si un formulaire possède un token CSRF."""
    csrf_tokens = ["csrf_token", "token", "_csrf", "authenticity_token",
                   "csrfmiddlewaretoken", "_token", "anti_csrf_token",
                   "csrf", "xsrf_token", "_xsrf"]

    has_csrf_protection = any(token in form["inputs"] for token in csrf_tokens)
    return has_csrf_protection


def check_sensitive_requests(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Analyse les requêtes HTTP pour détecter un manque de protection CSRF."""
    print(f"[+] Vérification des protections CSRF dans les requêtes HTTP sur {target}...")
    try:
        session = session or create_session()
        response = session.get(target, timeout=timeout)
        referer = response.headers.get("Referer")
        origin = response.headers.get("Origin")

        parsed_target = urlparse(target)
        target_domain = parsed_target.netloc

        if not referer and not origin:
            print(f"[!] Aucune protection CSRF détectée sur {target} (Absence de headers Referer et Origin)")
            return {"url": target, "csrf_vulnerable": True}

        if origin and urlparse(origin).netloc != target_domain:
            return {"url": target, "csrf_vulnerable": True}

        return {"url": target, "csrf_vulnerable": False}
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return {}


def generate_csrf_poc(form):
    """Génère une preuve de concept (PoC) pour une vulnérabilité CSRF (sanitized)."""
    # Sanitize all values to prevent XSS in the PoC itself
    safe_action = html_escape(form['action'])
    safe_method = html_escape(form['method'])

    poc = f"""<html>
<body>
<h1>CSRF PoC - WebHawk</h1>
<form action="{safe_action}" method="{safe_method}">
"""
    for name, value in form['inputs'].items():
        safe_name = html_escape(str(name))
        safe_value = html_escape(str(value))
        poc += f'    <input type="hidden" name="{safe_name}" value="{safe_value}">\n'
    poc += """    <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>"""
    return poc


def scan_csrf(target, formated_target, session=None, timeout=DEFAULT_TIMEOUT):
    """Effectue un scan CSRF sur le site."""
    print(f"\n\t==============Scan CSRF sur -->{formated_target}<-- 🔍 ==============\n")

    if not session:
        session = create_session()

    results = {"forms": [], "requests": []}

    # 1. Tester les formulaires
    forms = find_forms(target, session, timeout)
    if not forms:
        print("[~] Aucun formulaire détecté.")
    else:
        print("[+] Test des formulaires pour protection CSRF...")
        for form in forms:
            has_csrf = check_csrf_protection(form)
            if not has_csrf:
                print(f"[!!!] Formulaire potentiellement vulnérable (pas de CSRF token) : {form['action']}")
                results["forms"].append({
                    "form_action": form["action"],
                    "csrf_protected": False,
                    "poc": generate_csrf_poc(form)
                })

            if form["method"] == "get":
                print(f"[!] Le formulaire {form['action']} utilise GET pour une action sensible !")

    # 2. Tester les requêtes HTTP sensibles
    print("[+] Vérification des protections CSRF dans les requêtes HTTP...")
    request_check = check_sensitive_requests(target, session, timeout)
    if request_check and request_check.get("csrf_vulnerable"):
        results["requests"].append(request_check)

    print("\n✅ Scan CSRF terminé.\n")
    return results
