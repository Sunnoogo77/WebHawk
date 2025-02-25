# Point d’entrée du script (gestion du scanner)

import argparse
import time
import os
from core.report_manager import initialize_report, finalize_report, get_report_path
# from module.csrf_scanner import
from module.port_scanner import scan_ports
from module.headers_scanner import scan_headers
from module.lfi_scanner import scan_lfi
from module.sql_scanner import scan_sqli

from core.utils import normalize_target
from core.report_manager import update_report

def run_all_scans(target, report_path, silent):
    
    # report_path = initialize_report(target)

    # if not os.path.exists(report_path):
    #     print(f"❌ ERREUR : Le fichier {report_path} n'a pas été créé !")
    #     return
    
    if not silent:
        print(f"\n🚀 Début du scan complet pour {target}")
        print(f"\n\n\t============== Debut du Scan pour -->{target}<-- 🔍 ==============\n")
        
    # 1️⃣ Scan des ports
    scan_ports(report_path, target)

    # 2️⃣ Scan des headers HTTP
    scan_headers(report_path, target)
    
    # 3️⃣ Scan LFI
    scan_lfi(report_path, target)
    
    #  Scan SQLi
    scan_lfi(re)
    
    
    # Finalisation
    finalize_report(report_path)

# def run_selected_scans(target, report_path, scan_port_flag, scan_headers_flag, scan_lfi_flag, silent):
    
#     if not silent:
#         print(f"\n\t============== Scan 🔍 ==============\n")
    
#     if scan_port_flag:
#         scan_ports(report_path, target)
    
#     if scan_headers_flag:
#         scan_headers(report_path, target)
    
#     if scan_lfi_flag:
#         scan_lfi(report_path, target)

    
#     finalize_report(report_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebHawk - Scanner de vulnérabilités web")
    parser.add_argument("target", help="URL ou IP de la cible")
    
    #Scan complet
    parser.add_argument("--full", action="store_true", help="Exécuter un scn complet")
    
    #Ajouter le rapport JSON
    parser.add_argument("--report", action="store_true", help="Générer le rapport JSON")
    
    #Modes individuels
    parser.add_argument("--ports", action="store_true", help="Scanner uniquement les ports")
    parser.add_argument("--headers", action="store_true", help="Scanner uniquement les en-têtes HTTP")
    parser.add_argument("--lfi", action="store_true", help="Scanner uniquement les inclusions de fichiers locaux")
    parser.add_argument("--sqli", action="store_true", help=" Scan de l'Injection SQL (SQLi)")
    
    
    #Mode Silencieux
    parser.add_argument("--silent" ,action="store_true", help="Mode silencieux (Affiche uniquement le rapport final)")
    
    
    args = parser.parse_args()
    
    formated_target, domain = normalize_target(args.target)
    

    if args.report:
        report_path = initialize_report(domain) if args.report else None
        
    # Gestion des scans demandés
    if args.full:
        run_all_scans(formated_target, report_path, args.silent)
    elif args.ports or args.headers or args.lfi or args.sqli:
        # run_selected_scans(formated_target, report_path, args.ports, args.headers, args.lfi, args.silent)
        if args.ports:
            try:
                result = scan_ports(domain)
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"❌ ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "port_scan", {"open_ports": result})
            except Exception as e:
                print(f"❌ ERREUR lors du scan des ports : {e}\n")
        
        if args.headers:
            try:
                header, missing_headers, misconfigured_headers = scan_headers(formated_target)
            
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"❌ ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "headers_scan", {
                        "headers_received": dict(header),
                        "missing_headers": missing_headers,
                        "misconfigured_headers": misconfigured_headers
                        })
            except Exception as e:
                print(f"❌ ERREUR lors du scan des en-têtes HTTP : {e}\n")
        
        if args.lfi:
            try:
                result = scan_lfi(args.target, formated_target)
                
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"❌ ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "lfi_scan", {"lfi_tests": result})
                    
            except Exception as e:
                print(f"❌ ERREUR lors du scan LFI : {e}\n")

        if args.sqli:
            try:
                result = scan_sqli(args.target, formated_target)
                
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"❌ ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "sqli_scan", {"sqli_tests": result})
            except Exception as e:
                print(f"❌ ERREUR lors du scan SQLI : {e}\n")
        
        if args.report:
            finalize_report(report_path)
            
    else:
        print("❌ Erreur : Vous devez spécifier un mode de scan (--full, --ports, --headers, --lfi, --sqli)")
        parser.print_help()
        exit(1)