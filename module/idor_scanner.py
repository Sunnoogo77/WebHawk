import requests
import re
from pprint import pprint
from bs4 import BeautifulSoup
from core.config import create_session, DEFAULT_TIMEOUT

IDOR_KEYS = [
    "id", "user_id", "account_id", "profile_id", "customer_id",
    "order_id", "transaction_id", "payment_id", "invoice_id",
    "message_id", "document_id", "file_id", "folder_id",
    "record_id", "session_id", "token", "reservation_id",
    "user", "account", "profile", "customer", "order",
    "transaction", "payment", "invoice", "message", "document",
    "file", "folder", "record", "session", "reservation",
    "reference", "ref", "code", "number", "no", "entry",
    "item", "element", "object", "resource", "data",
    "key", "value", "param", "parameter",
    "client", "vendor", "supplier", "product", "service",
    "event", "post", "comment", "review", "upload",
]


def find_id_in_urls(target, timeout=DEFAULT_TIMEOUT):
    """Search for potential ID parameters in page URLs."""
    print(f"[~] Recherche d'ID dans les URLs de {target}...")
    session = create_session()
    try:
        response = session.get(target, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')

        detected_ids = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            url_lower = url.lower()
            if any(key in url_lower for key in IDOR_KEYS):
                print(f"[!!!] ID potentiel détecté dans {url}")
                detected_ids.append(url)

        return detected_ids
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return []


def analyze_api_requests(target, timeout=DEFAULT_TIMEOUT):
    """Analyze API responses for potential ID exposure."""
    print(f"[~] Analyse des requêtes API sur {target}...")
    session = create_session()
    try:
        response = session.get(target, timeout=timeout)
        if "application/json" not in response.headers.get("Content-Type", ""):
            return []

        data = response.json()
        detected_ids = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in [k.lower() for k in IDOR_KEYS] and isinstance(value, (int, str)):
                    print(f"[!!!] ID potentiel détecté dans la réponse API : {key}: {value}")
                    detected_ids.append((key, value))

        return detected_ids
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête API : {e}")
        return []
    except (ValueError, KeyError):
        return []


def check_cookies_and_headers(target, timeout=DEFAULT_TIMEOUT):
    """Check cookies and headers for exposed IDs."""
    session = create_session()
    try:
        response = session.get(target, timeout=timeout)

        cookies = response.cookies.get_dict()
        headers = response.headers

        detected_ids = {}

        for key, value in cookies.items():
            if key.lower() in [k.lower() for k in IDOR_KEYS] or (isinstance(value, str) and value.isdigit()):
                detected_ids[f"Cookie: {key}"] = value

        for key, value in headers.items():
            if key.lower() in [k.lower() for k in IDOR_KEYS]:
                detected_ids[f"Header: {key}"] = value

        return detected_ids
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
        return {}


def test_idor(target_url, id_param, test_values, timeout=DEFAULT_TIMEOUT):
    """Test IDOR by modifying ID values."""
    session = create_session()
    exploitable = []
    for value in test_values:
        test_url = target_url.replace(str(id_param), str(value))
        try:
            response = session.get(test_url, timeout=timeout)
            if response.status_code == 200:
                print(f"[!!!] Potentielle faille IDOR détectée sur {test_url} !")
                exploitable.append(test_url)
            else:
                print(f"[~] Aucun accès non autorisé sur {test_url}")
        except requests.exceptions.RequestException:
            pass
    return exploitable


def scan_idor(target, formated_target, timeout=DEFAULT_TIMEOUT):
    """Perform IDOR scan on the target."""
    print(f"\n\t==============Scan IDOR sur -->{formated_target}<-- 🔍 ==============\n")

    results = {
        "urls_with_ids": [],
        "api_detected_ids": [],
        "cookies_headers_with_ids": {},
        "exploitable_urls": []
    }

    urls_with_ids = find_id_in_urls(target, timeout)
    if urls_with_ids:
        print(f"[+] {len(urls_with_ids)} ID potentiel(s) détecté(s) dans les URLs")
        results["urls_with_ids"] = urls_with_ids
    else:
        print("[~] Aucun ID potentiel détecté dans les URLs")

    detected_api_ids = analyze_api_requests(target, timeout)
    if detected_api_ids:
        print(f"[+] {len(detected_api_ids)} ID potentiel(s) détecté(s) dans les réponses API")
        results["api_detected_ids"] = detected_api_ids
    else:
        print("[~] Aucun ID potentiel détecté dans les réponses API")

    cookies_headers_with_ids = check_cookies_and_headers(target, timeout)
    if cookies_headers_with_ids:
        print(f"[+] ID potentiel(s) détecté(s) dans les cookies/headers")
        results["cookies_headers_with_ids"] = cookies_headers_with_ids
    else:
        print("[~] Aucun ID potentiel détecté dans les cookies ou headers")

    # Try IDOR exploitation on found URLs
    if urls_with_ids:
        print("[~] Tentative d'exploitation des ID dans les URLs...")
        for url in urls_with_ids:
            match = re.search(r'(\d+)', url)
            if match:
                id_to_test = int(match.group(1))
                test_values = [id_to_test - 1, id_to_test + 1, id_to_test + 100]
                exploitable = test_idor(url, id_to_test, test_values, timeout)
                if exploitable:
                    results["exploitable_urls"].extend(exploitable)

    print(f"\n✅  Scan IDOR terminé.\n")
    pprint(results)
    print()

    return results
