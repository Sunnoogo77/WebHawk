# Détection des CSRF
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def find_forms(target):
    """Détecte les formulaires sur une page cible"""
    try:
        response = requests.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_forms = []
        for form in soup.find_all('form'):
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get").lower()
            inputs = [input_tag.attrs.get("name") for input_tag in form.find_all("input") if input_tag.attrs.get("name")]
            
            full_action_url = urljoin(target, action) if action else target
            detected_forms.append({"action": full_action_url, "method": method, "inputs": inputs})
        
        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de la requête : {e}\n")
        return []

def check_csrf_protection(target, form):
    """Vérifie si un formulaire possède un token CSRF"""
    csrf_tokens = ["csrf_token", "token", "_csrf", "authenticity_token"]
    
    has_csrf_protection = any(token in form["inputs"] for token in csrf_tokens)
    return has_csrf_protection

def check_sensitive_requests(target):
    """Analyse les requêtes HTTP pour détecter un manque de protection CSRF"""
    try:
        response = requests.get(target, timeout=5)
        referer = response.headers.get("Referer")
        origin = response.headers.get("Origin")
        
        if not referer or not origin:
            print(f"⚠️ Aucune protection CSRF détectée sur {target} (Absence de headers `Referer` et `Origin`)")
            return {"url": target, "csrf_vulnerable": True}
        
        return {"url": target, "csrf_vulnerable": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de la requête : {e}\n")
        return {}

def scan_csrf(target, formated_target):
    """Effectue un scan CSRF sur le site"""
    print(f"\n\t==============Scan CSRF sur -->{formated_target}<-- 🔍 ==============\n")

    results = {"forms": [], "requests": []}

    # 1️⃣ Tester les formulaires
    forms = find_forms(target)
    if not forms:
        print("\n✅ Aucun formulaire détecté. Ignoré.")
    else:
        print("\n🚀 Test des formulaires pour protection CSRF...")
        for form in forms:
            has_csrf = check_csrf_protection(target, form)
            if not has_csrf:
                print(f"⚠️ Formulaire potentiellement vulnérable (pas de CSRF token) : {form['action']}")
                results["forms"].append({"form_action": form["action"], "csrf_protected": False})
    
    # 2️⃣ Tester les requêtes HTTP sensibles
    print("\n🚀 Vérification des protections CSRF dans les requêtes HTTP...")
    request_check = check_sensitive_requests(target)
    if request_check and request_check["csrf_vulnerable"]:
        results["requests"].append(request_check)
    
    print("\n✅ Scan CSRF terminé.\n")

    return results
