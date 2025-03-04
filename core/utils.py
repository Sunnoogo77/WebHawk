# Fonctions utilitaires
from urllib.parse import urlparse
import requests
import re
from bs4 import BeautifulSoup

def extract_domain_or_ip(target):
    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        if hostname:
            # Vérification IPv4
            ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            if ipv4_pattern.match(hostname):
                return hostname

            # Vérification IPv6
            ipv6_pattern = re.compile(r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")
            if ipv6_pattern.match(hostname):
                return hostname
    except ValueError:
        pass  
    return None
    
def is_ip(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            # Vérification IPv4
            ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            if ipv4_pattern.match(hostname):
                return True

            # Vérification IPv6
            ipv6_pattern = re.compile(r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")
            if ipv6_pattern.match(hostname):
                return True
    except ValueError:
        pass  
    return False

def normalize_target(target):
    """
    Prend une URL sous n'importe quelle forme et extrait le domaine + ajoute le bon scheme.
    """
    if not target.startswith("http://") and not target.startswith("https://"):
        if is_ip(target):
            target = "https://" + extract_domain_or_ip(target)
        else:
            target = "https://" + target
            print(f"------{target}")
            return normalize_target(target)
            
    else:
        if is_ip(target):
            target = "https://" + extract_domain_or_ip(target)
    
    parsed_url = urlparse(target)
    
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    
    # return parsed_url.scheme + "://" + domain, domain
    return  target, domain

def find_forms(target):
    """Scanne une page pour détecter les formulaires et leurs champs"""
    
    session = requests.Session()
    session.verify = False
    
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        detected_forms =  []
        
        for form in forms:
            form_details = {
                "action": form.attrs.get("action"),
                "method": form.attrs.get("method", "get").lower(),
                "inputs" :[]
            }
            
            for input_tag in form.find_all("input"):
                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")
                form_details["inputs"].append({"name": input_name, "type": input_type})
            
            detected_forms.append(form_details)
            
        return detected_forms
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de la requête : {e}")
        return []

def get_csrf_token(session, target):
    try:
        response = session.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        token = soup.find("input", {"name": "_csrf"})
        return token["value"] if token else None
    except Exception as e:
        print(f"⚠️ Erreur lors de la récupération du CSRF token : {e}")
        return None
    
def check_allowed_methods(target_url):
    try:
        get_response = requests.get(target_url, timeout=5)
        post_response = requests.post(target_url, timeout=5)

        allowed_methods = []
        if get_response.status_code != 405:
            allowed_methods.append("GET")
        if post_response.status_code != 405:
            allowed_methods.append("POST")

        return allowed_methods
    except Exception as e:
        print(f"⚠️ Erreur lors de la vérification des méthodes autorisées : {e}")
        return []

def detect_hidden_sqli_errors(response_text):
    
    SQLI_SIGNATURES = [
        "You have an error in your SQL syntax",
        "Warning: mysql_fetch",
        "Unclosed quotation mark",
        "Microsoft OLE DB Provider",
        "SQLSTATE[",
        "ODBC SQL Server Driver",
        "Syntax error in string",
        "Unknown column",
        "Fatal error",
        "MySQL server version",
        "PostgreSQL query failed",
        "syntax error",  
        "mysql_fetch", 
        "database error", 
        "unterminated string", 
    ]
    
    for signature in SQLI_SIGNATURES:
        if signature.lower() in response_text.lower():
            return True
    return False

