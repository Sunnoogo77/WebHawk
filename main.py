# Point d’entrée du script (gestion du scanner)

import argparse
import time
import os
from core.report_manager import initialize_report, finalize_report, get_report_path
# from module.csrf_scanner import
from module.port_scanner import scan_ports
from module.headers_scanner import scan_headers

def run_all_scans(target, report_path, silent):
    
    # report_path = initialize_report(target)

    # if not os.path.exists(report_path):
    #     print(f"❌ ERREUR : Le fichier {report_path} n'a pas été créé !")
    #     return
    
    if not silent:
        print(f"\n🚀 Début du scan complet pour {target}")
        
    # 1️⃣ Scan des ports
    scan_ports(report_path, target)

    # 2️⃣ Scan des headers HTTP
    scan_headers(report_path, target)
    
    
    # Finalisation
    finalize_report(report_path)

def run_selected_scans(target, report_path, scan_port_flag, scan_headers_flag, silent):
    
    if not silent:
        print(f"\n\t============== Debut du Scan pour -->{target}<-- 🔍 ==============\n")
    
    if scan_port_flag:
        scan_ports(report_path, target)
    
    if scan_headers_flag:
        scan_headers(report_path, target)
    
    finalize_report(report_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebHawk - Scanner de vulnérabilités web")
    parser.add_argument("target", help="URL ou IP de la cible")
    
    #Scan complet
    parser.add_argument("--full", action="store_true", help="Exécuter un scn complet")
    
    #Modes individuels
    parser.add_argument("--ports", action="store_true", help="Scanner uniquement les ports")
    parser.add_argument("--headers", action="store_true", help="Scanner uniquement les en-têtes HTTP")
    
    
    #Mode Silencieux
    parser.add_argument("--silent" ,action="store_true", help="Mode silencieux (Affiche uniquement le rapport final)")
    
    
    args = parser.parse_args()
    
    report_path = initialize_report(args.target)

    # Gestion des scans demandés
    if args.full:
        run_all_scans(args.target, report_path, args.silent)
    elif args.ports or args.headers:
        run_selected_scans(args.target, report_path, args.ports, args.headers, args.silent)
    else:
        print("❌ Erreur : Vous devez spécifier un mode de scan (--full, --ports, --headers)")