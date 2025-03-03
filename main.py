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
from module.idor_scanner import scan_idor
from module.xss_scanner import scan_xss
from module.csrf_scanner import scan_csrf
# from module.ssrf_scanner import scan_ssrf
from module.ssrf_scanner import scan_ssrf
from module.rce_scanner import scan_rce
from module.dir_scanner import scan_dir

from core.utils import normalize_target
from core.report_manager import update_report


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
    parser.add_argument("--idor", action="store_true", help="Scan IDOR")
    parser.add_argument("--xss", action="store_true", help="Scan des vulnérabilités XSS")
    parser.add_argument("--csrf", action="store_true", help="Scan des vulnérabilité CSRF")
    parser.add_argument("--ssrf", action="store_true", help="Scan des vulnérabilité SSRF")
    parser.add_argument("--rce", action="store_true", help="Scan des vulnérabilité RCE")
    parser.add_argument("--dirs", action="store_true", help="Scan des répertoires cachés et fichiers sensibles")
    
    
    parser.add_argument("--ignore-ssl", action="store_true", help="Ignorer les erreurs SSL")
    #Mode Silencieux
    parser.add_argument("--silent" ,action="store_true", help="Mode silencieux (Affiche uniquement le rapport final)")
    
    
    args = parser.parse_args()
    
    formated_target, domain = normalize_target(args.target)
    
    report_path = ''
    
    if args.report:
        report_path = initialize_report(domain) if args.report else None
        
    # Gestion des scans demandés
    if args.full:
        if not args.silent:
            print(f"\n\n\t============== Debut du Scan Complet pour -->{domain}<-- 🔍 ==============\n")
            
        try:
            port = scan_ports(domain)
            header, missing_headers, misconfigured_headers = scan_headers(formated_target)
            # lfi = scan_lfi(args.target, formated_target)
            # sqli = scan_sqli(args.target, formated_target)
            lfi = scan_lfi(formated_target, domain)
            sqli = scan_sqli(formated_target, domain)
            idor = scan_idor(formated_target, domain)
            xss =  scan_xss(formated_target, domain)
            csrf = scan_csrf(formated_target, domain)
            ssrf = scan_ssrf(formated_target, domain)
            rce = scan_rce(formated_target, domain)
            dir = scan_dir(formated_target, domain)
            
            print(f"\n\n\t============== Fin du Scan Complet pour -->{domain}<-- 🔍 ==============\n")
            
            if args.report:
                if not os.path.exists(report_path):
                    print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                
                update_report(report_path, "port_scan", {"open_ports": port})
                update_report(report_path, "headers_scan", {
                    "headers_received": dict(header),
                    "missing_headers": missing_headers,
                    "misconfigured_headers": misconfigured_headers
                    })
                update_report(report_path, "lfi_scan", {"lfi_tests": lfi})
                update_report(report_path, "sqli_scan", {"sqli_tests": sqli})
                update_report(report_path, "idor_scan", {"idor_tests": idor})
                update_report(report_path, "xss_scan", {"xss_tests": xss})
                update_report(report_path, "csrf_scan", {"csrf_tests": csrf})
                update_report(report_path, "ssrf_scan", {"ssrf_tests": ssrf})
                update_report(report_path, "rce_scan", {"rce_tests": rce})
                update_report(report_path, "dir_scan", {"dir_tests": dir})
                    
        except Exception as e:
            # print(f"[!][!][XXX] ERREUR lors du scan des ports : {e}\n")
            pass

        # Finalisation
        if args.report:
            finalize_report(report_path)
        
    elif args.ports or args.headers or args.lfi or args.sqli or args.idor or args.xss  or args.csrf or args.ssrf or args.rce or args.dirs:
        
        if args.ports:
            try:
                result = scan_ports(domain)
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "port_scan", {"open_ports": result})
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan des ports : {e}\n")
                pass
            
        if args.headers:
            try:
                header, missing_headers, misconfigured_headers = scan_headers(formated_target)
            
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "headers_scan", {
                        "headers_received": dict(header),
                        "missing_headers": missing_headers,
                        "misconfigured_headers": misconfigured_headers
                        })
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan des en-têtes HTTP : {e}\n")
                pass
        
        if args.lfi:
            try:
                result = scan_lfi(args.target, formated_target)
                
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "lfi_scan", {"lfi_tests": result})
                    
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan LFI : {e}\n")
                pass

        if args.sqli:
            try:
                result = scan_sqli(args.target, formated_target)
                
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "sqli_scan", {"sqli_tests": result})
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan SQLI : {e}\n")
                pass
        
        if args.idor:
            try:
                result = scan_idor(args.target, formated_target)
                
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "idor_scan", {"idor_tests": result})
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan IDOR : {e}\n")
                pass
        
        if args.xss:
            try:
                result = scan_xss(args.target, formated_target)
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "xss_scan", {"xss_tests": result})
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan XSS : {e}\n")
                pass
        
        if args.csrf:
            try:
                result = scan_csrf(args.target, formated_target)
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "csrf_scan", {"csrf_tests": result})
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan CSRF : {e}\n")
                pass
        
        if args.ssrf:
            try:
                result = scan_ssrf(args.target, formated_target)
                if args.report:
                    if not os.path.exists(report_path):
                        print(f"[!][!][XXX] ERREUR : Le fichier de rapport {report_path} est introuvable APRES le scan !\n")
                    
                    update_report(report_path, "scan_ssrf", {"ssrf_tests": result})
            except Exception as e:
                # print(f"[!][!][XXX] ERREUR lors du scan SSRF : {e}\n")
                pass
        
        if args.rce:
            try:
                result = scan_rce(args.target, formated_target)
                if args.report:
                    update_report(report_path, "rec_scan", {"rce_found": result})
            except Exception as e:
                # print(f"❌ ERREUR lors du scan RCE : {e}\n")
                pass
        
        if args.dirs:
            try:
                result = scan_dir(args.target, formated_target)
                if args.report:
                    update_report(report_path, "dir_scan", {"directories_found": result})
            except Exception as e:
                # print(f"❌ ERREUR lors du scan des répertoires : {e}\n")
                pass


            
    else:
        print("\n[!][!][XXX] Erreur : Vous devez spécifier un mode de scan (--full, --ports, --headers, --lfi, --sqli, --idor, --xss, --csrf, --ssrf, --rce, --dirs)")
        parser.print_help()
        exit(1)

