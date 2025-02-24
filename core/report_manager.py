# Gestion globale du scanner
import json
import time
import os
from datetime import datetime

REPORT_PATH = "reports/webhaw_report.json"

def get_report_path(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = target.replace("http://", "").replace("https://", "").replace("/", "_")
    report_path = f"reports/{target_name}_{timestamp}.json"
    
    return report_path

def initialize_report(target):
    
    report_path = get_report_path(target)
    
    report_data = {
        "target": target,
        "scan_date" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": {}
    }
    
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)
        
    return report_path

def update_report(report_path, section, data):
    """Mise à jour du rapport spécifique avec les résultats d'un test"""

    # 🔄 Attente que le fichier de rapport soit bien disponible
    timeout = 5  # Maximum 5 secondes d'attente
    while not os.path.exists(report_path) and timeout > 0:
        print(f"⏳ Attente du fichier de rapport ({timeout} sec restantes)...")
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(report_path):
        print(f"❌ ERREUR : Le rapport {report_path} n'existe pas après 5 secondes d'attente !")
        return

    with open(report_path, "r") as f:
        report_data = json.load(f)
        
    report_data["results"][section] = data
    
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)
        
    # print(f"✅ Mise à jour du rapport : {report_path}")

def finalize_report(report_path):
    print(f"\n📄 Rapport final généré : {report_path}\n")
    

