print("Helloooooooooooooooo ça marcheeeeeeeee !!!!!!!!!!\n")


import requests
from bs4 import BeautifulSoup
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def find_id_in_urls(target):
    
    session = requests.Session()
    session.verify = False
        
    try:
        response = requests.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        detected_ids = []
        
        for link in soup.find_all('a', href=True):
            url = link['href']
            match = re.search(r'(\d{2,})', url)  # Détecter les nombres dans les URLs
            if match:
                detected_ids.append(url)
        
        return detected_ids
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de la requête : {e}")
        return []

target = "https://192.168.150.143:8080/chat?user_id=4"
urls_with_ids = find_id_in_urls(target)
print(urls_with_ids)  # 🔍 Affiche les URLs contenant des ID suspects
