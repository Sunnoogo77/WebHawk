import requests
import re

from pprint import pprint
from bs4 import BeautifulSoup

IDOR_KEYS = [
    # Clés de base (déjà présentes)
    "id", "user_id", "account_id", "profile_id", "customer_id",
    "order_id", "transaction_id", "payment_id", "invoice_id",
    "message_id", "document_id", "file_id", "folder_id",
    "record_id", "session_id", "token", "reservation_id",

    # Variations de casse
    "Id", "UserID", "AccountId", "ProfileId", "CustomerId",
    "OrderId", "TransactionId", "PaymentId", "InvoiceId",
    "MessageId", "DocumentId", "FileId", "FolderId",
    "RecordId", "SessionId", "Token", "ReservationId",
    "ID", "USERID", "ACCOUNTID", "PROFILEID", "CUSTOMERID",
    "ORDERID", "TRANSACTIONID", "PAYMENTID", "INVOICEID",
    "MESSAGEID", "DOCUMENTID", "FILEID", "FOLDERID",
    "RECORDID", "SESSIONID", "TOKEN", "RESERVATIONID",

    # Autres termes courants
    "user", "account", "profile", "customer", "order",
    "transaction", "payment", "invoice", "message", "document",
    "file", "folder", "record", "session", "reservation",
    "usr", "acc", "prof", "cust", "ord", "trans", "pay", "inv", "msg", "doc",
    "fl", "fld", "rec", "sess", "resv",
    "userNum", "accountNum", "profileNum", "customerNum",
    "orderNum", "transactionNum", "paymentNum", "invoiceNum",
    "messageNum", "documentNum", "fileNum", "folderNum",
    "recordNum", "sessionNum", "reservationNum",
    "numUser", "numAccount", "numProfile", "numCustomer",
    "numOrder", "numTransaction", "numPayment", "numInvoice",
    "numMessage", "numDocument", "numFile", "numFolder",
    "numRecord", "numSession", "numReservation",
    "reference", "ref", "code", "number", "no", "entry",
    "item", "element", "object", "resource", "data",
    "key", "value", "val", "param", "parameter",
    "client", "vendor", "supplier", "product", "service",
    "event", "post", "comment", "review", "upload",
    "download", "share", "view", "edit", "delete",
    "update", "create", "add", "remove", "get", "set",
    "source", "target", "dest", "destination", "from",
    "to", "owner", "author", "creator", "modifier",
    "viewer", "editor", "deleter", "updater", "adder",
    "remover", "getter", "setter", "src", "tgt", "dst",
    "own", "auth", "createur", "modificateur", "visualiseur",
    "editeur", "suppresseur", "metteurAJour", "ajouteur",
    "supprimeur", "recuperateur", "definisseur",

    # Préfixes et suffixes
    "user-id", "account-id", "profile-id", "customer-id",
    "order-id", "transaction-id", "payment-id", "invoice-id",
    "message-id", "document-id", "file-id", "folder-id",
    "record-id", "session-id", "reservation-id",
    "id-user", "id-account", "id-profile", "id-customer",
    "id-order", "id-transaction", "id-payment", "id-invoice",
    "id-message", "id-document", "id-file", "id-folder",
    "id-record", "id-session", "id-reservation",
    "user_num", "account_num", "profile_num", "customer_num",
    "order_num", "transaction_num", "payment_num", "invoice_num",
    "message_num", "document_num", "file_num", "folder_num",
    "record_num", "session_num", "reservation_num",
    "num_user", "num_account", "num_profile", "num_customer",
    "num_order", "num_transaction", "num_payment", "num_invoice",
    "num_message", "num_document", "num_file", "num_folder",
    "num_record", "num_session", "num_reservation",

    # Abréviations
    "usr_id", "acc_id", "prof_id", "cust_id", "ord_id",
    "trans_id", "pay_id", "inv_id", "msg_id", "doc_id",
    "fl_id", "fld_id", "rec_id", "sess_id", "resv_id",
    "usrId", "accId", "profId", "custId", "ordId",
    "transId", "payId", "invId", "msgId", "docId",
    "flId", "fldId", "recId", "sessId", "resvId",
]

def find_id_in_urls(target):
    print(f"[!]~] Recherche d'ID dans les URLs de {target}...")
    try:
        response = requests.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'lxml')
        
        detected_ids = []
        for link in soup.find_all('a', href=True):
            url = link['href']
            if any(key in url for key in IDOR_KEYS):
                print(f"[!!!] ID potentiel détecté dans {url}")
                detected_ids.append(url)
        
        return detected_ids
    except requests.exceptions.RequestException as e:
        # print(f"[!][!][XXX] Erreur lors de la requête : {e}\n")
        return []

def analyze_api_requests(target):
    print(f"[!]~] Analyse des requêtes API sur {target}...")
    try:
        response = requests.get(target, timeout=5)
        if "application/json" in response.headers.get("Content-Type", ""):
            data = response.json()
        else:
            data = None
        
        
        detected_ids = []
        if data is None:
            pass
        else:
            for key, value in data.items():
                if key in IDOR_KEYS and isinstance(value, int):
                    print(f"[!!!] ID potentiel détecté dans la réponse API : {key}: {value}")
                    detected_ids.append((key, value))
        
        return detected_ids
    except requests.exceptions.RequestException as e:
        # print(f"[!][!][XXX] Erreur lors de la requête API : {e}\n")
        return []
    except ValueError:
        print("[!][!][XXX] La réponse n'est pas un JSON valide\n")
        return []

def check_cookies_and_headers(target):
    try:
        response = requests.get(target, timeout=5)
        
        cookies = response.cookies.get_dict()
        headers =  response.headers
        
        detectedd_ids = {}
        
        for key, value in cookies.items():
            if key in IDOR_KEYS or value.isdigit():
                detectedd_ids[f"Cookies: {key}"] = value
        
        for key, value in headers.items():
            if key in IDOR_KEYS or value.isdigit():
                detectedd_ids[f"Cookies: {key}"] = value
        
        return detectedd_ids
    except requests.exceptions.RequestException as e:
        # print(f"[!][!][XXX] Erreur lors de la requête : {e}\n")
        return {}

def test_idor(target_url, id_param, test_values):
    
    for value in test_values:
        test_url = target_url.replace(str(id_param), str (value))
        response = requests.get(test_url, timeout=5)
        
        if response.status_code == 200:
            print(f"[!!!] Potentielle faille IDOR détectée sur {test_url} !")
        else:
            print(f"[!]~] Aucun accès non autorisé sur {test_url}")

def scan_idor(target, formated_target):
    
    print(f"\n\t==============Scan IDOR sur -->{formated_target}<-- 🔍 ==============\n")
    
    results = {
        "urls_with_ids": [],
        "api_detected_ids": [],
        "cookies_headers_with_ids": {},
        "exploitable_urls": []
    }
    
    urls_with_ids = find_id_in_urls(target)
    if not urls_with_ids:
        print("[!]~] Aucun ID potentiel détecté dans les URLs...")
    else:
        print("[!]~] ID potentiel détecté dans les URLs...")
        for url in urls_with_ids:
            print(f"[!!!] ---> {url}")
        results["urls_with_ids"] = urls_with_ids
              
    
    detected_api_ids = analyze_api_requests(target)
    if not detected_api_ids:
        print("[!]~] Aucun ID potentiel détecté dans les réponses API...")
    else:
        print("[!]~] ID potentiel détecté dans les réponses API...")
        for key, value in detected_api_ids:
            print(f"[!!!] {key} --->:<--- {value}")
        results["api_detected_ids"] = detected_api_ids
    
    
    cookies_headers_with_ids = check_cookies_and_headers(target)
    if cookies_headers_with_ids:
        print("[!]~]  Aucun ID potentiel détecté dans les cookies ou headers...")
    else: 
        print("[!]~] ID potentiel détecté dans les cookies ou headers...")
        for key, value in cookies_headers_with_ids.items():
            print(f"[!!!] {key} --->:<--- {value}")
        results["cookies_headers_with_ids"] = cookies_headers_with_ids
    
    
    
    if urls_with_ids:
        print("[!]~] Tentative d'exploitation des ID dans les URLs...")
        for url in urls_with_ids:
            match = re.search(f'(\d+)', target)
            if match:
                id_to_test = int(match.group(1))
                
                exploitable_urls = []
                
                
                for value in [id_to_test-1, id_to_test+1]:
                    test_url = url.replace(str(id_to_test), str (value))
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        print(f"[!!!] Potentielle faille IDOR détectée sur {test_url} !")
                        exploitable_urls.append(test_url)
                    else:
                        print(f"[!]~] Aucun accès non autorisé sur {test_url}")
                
                if exploitable_urls :
                    results["exploitable_urls"].extend(exploitable_urls)
    print(f"\n✅  Scan IDOR terminé. Vulnérabilités trouvées : \n")
    
    print("[!][~]")
    print("[!][~]")
    pprint(results)
    print("\n")
    
    
    return results