# Point d'entrée du script (gestion du scanner)

import argparse
import sys
import os
import time
from core.report_manager import initialize_report, finalize_report
from core.config import DEFAULT_TIMEOUT, DEFAULT_THREADS
from module.port_scanner import scan_ports
from module.headers_scanner import scan_headers
from module.lfi_scanner import scan_lfi
from module.sql_scanner import scan_sqli
from module.idor_scanner import scan_idor
from module.xss_scanner import scan_xss
from module.csrf_scanner import scan_csrf
from module.ssrf_scanner import scan_ssrf
from module.rce_scanner import scan_rce
from module.dir_scanner import scan_dir

from core.utils import normalize_target
from core.report_manager import update_report
from colorama import init, Fore, Style

# Initialisation des couleurs
init(autoreset=True)

BANNER = f"""{Fore.CYAN}
        ██╗    ██╗███████╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
        ██║    ██║██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██║
        ██║ █╗ ██║█████╗  ██████╔╝███████║███████║██║ █╗ ██║████║
        ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██║
        ╚███╔███╔╝███████╗██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██║
         ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝ {Style.RESET_ALL}


{Fore.GREEN} \t\t    ----------------------
{Fore.YELLOW}WebHawk - Scanner de vulnérabilités web | Par {Fore.RED}@Sunnoogo77{Style.RESET_ALL}

{Fore.CYAN}Github:{Fore.RESET} https://github.com/Sunnoogo77/WebHawk

"""


def interactive_mode():
    """Mode interactif si aucun argument n'est fourni."""
    os.system("clear" if os.name == "posix" else "cls")
    print(f"\n\t{BANNER}")
    print(f"{Fore.GREEN}[+] Bienvenue dans WebHawk ! Entrez les paramètres du scan :{Style.RESET_ALL}")
    option_scan()

    target = input(f"{Fore.CYAN}[>] URL cible : {Style.RESET_ALL}").strip()
    if not target:
        print(f"{Fore.RED}[!] Erreur : Vous devez entrer une URL cible.{Style.RESET_ALL}")
        sys.exit(1)

    options = input(f"{Fore.CYAN}[>] Options (--full, --report, --xss, --sqli...) : {Style.RESET_ALL}").strip()

    args = ["webhawk", target] + options.split()
    return args


def option_scan():
    """Display available scan options."""
    print(f"\n{Fore.MAGENTA}Options de scan disponibles :{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}--full{Style.RESET_ALL}      → Scan complet (toutes les vulnérabilités)")
    print(f"  {Fore.GREEN}--ports{Style.RESET_ALL}     → Scan des ports ouverts")
    print(f"  {Fore.GREEN}--headers{Style.RESET_ALL}   → Analyse des en-têtes HTTP")
    print(f"  {Fore.GREEN}--lfi{Style.RESET_ALL}       → Test LFI (Local File Inclusion)")
    print(f"  {Fore.GREEN}--sqli{Style.RESET_ALL}      → Test SQLi (Injection SQL)")
    print(f"  {Fore.GREEN}--idor{Style.RESET_ALL}      → Test IDOR (Insecure Direct Object Reference)")
    print(f"  {Fore.GREEN}--xss{Style.RESET_ALL}       → Test XSS (Cross-Site Scripting)")
    print(f"  {Fore.GREEN}--rce{Style.RESET_ALL}       → Test RCE (Remote Code Execution)")
    print(f"  {Fore.GREEN}--ssrf{Style.RESET_ALL}      → Test SSRF (Server-Side Request Forgery)")
    print(f"  {Fore.GREEN}--csrf{Style.RESET_ALL}      → Test CSRF (Cross-Site Request Forgery)")
    print(f"  {Fore.GREEN}--dirs{Style.RESET_ALL}      → Scan des répertoires et fichiers sensibles")
    print(f"  {Fore.GREEN}--report{Style.RESET_ALL}    → Générer un rapport JSON")
    print(f"  {Fore.GREEN}--timeout N{Style.RESET_ALL} → Timeout des requêtes en secondes (défaut: {DEFAULT_TIMEOUT})")
    print(f"  {Fore.GREEN}--threads N{Style.RESET_ALL} → Nombre de threads (défaut: {DEFAULT_THREADS})")
    print(f"\n{Fore.CYAN}Exemple : webhawk https://example.com --full --report{Style.RESET_ALL}\n")


def run_scan(scan_name, scan_func, *args, **kwargs):
    """Run a scan with proper error handling and return results."""
    try:
        return scan_func(*args, **kwargs)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Erreur lors du scan {scan_name} : {e}{Style.RESET_ALL}\n")
        return None


def main():
    """Gestion du programme."""
    while True:
        if len(sys.argv) < 2:
            sys.argv = interactive_mode()

        parser = argparse.ArgumentParser(
            description="WebHawk - Scanner de vulnérabilités web",
            epilog="Exemple: python3 main.py https://example.com --full --report"
        )
        parser.add_argument("target", help="URL ou IP de la cible")

        # Scan complet
        parser.add_argument("--full", action="store_true", help="Exécuter un scan complet")

        # Rapport JSON
        parser.add_argument("--report", action="store_true", help="Générer le rapport JSON")

        # Modes individuels
        parser.add_argument("--ports", action="store_true", help="Scanner les ports ouverts")
        parser.add_argument("--headers", action="store_true", help="Scanner les en-têtes HTTP")
        parser.add_argument("--lfi", action="store_true", help="Scanner LFI (Local File Inclusion)")
        parser.add_argument("--sqli", action="store_true", help="Scanner SQLi (Injection SQL)")
        parser.add_argument("--idor", action="store_true", help="Scanner IDOR")
        parser.add_argument("--xss", action="store_true", help="Scanner XSS (Cross-Site Scripting)")
        parser.add_argument("--csrf", action="store_true", help="Scanner CSRF")
        parser.add_argument("--ssrf", action="store_true", help="Scanner SSRF")
        parser.add_argument("--rce", action="store_true", help="Scanner RCE")
        parser.add_argument("--dirs", action="store_true", help="Scanner répertoires et fichiers sensibles")

        # Options avancées
        parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                            help=f"Timeout des requêtes en secondes (défaut: {DEFAULT_TIMEOUT})")
        parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                            help=f"Nombre de threads pour le scan (défaut: {DEFAULT_THREADS})")
        parser.add_argument("--ignore-ssl", action="store_true", help="Ignorer les erreurs SSL")
        parser.add_argument("--silent", action="store_true", help="Mode silencieux")

        args = parser.parse_args()

        formated_target, domain = normalize_target(args.target)
        timeout = args.timeout
        threads = args.threads

        report_path = None

        os.system("clear" if os.name == "posix" else "cls")
        print(f"\n\t{BANNER}")
        print(f"{Fore.GREEN}[+] Cible détectée : {Fore.CYAN}{formated_target}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Timeout: {timeout}s | Threads: {threads}{Style.RESET_ALL}")
        time.sleep(0.5)

        if args.report:
            report_path = initialize_report(domain)

        # Determine which scans to run
        has_specific_scan = any([args.ports, args.headers, args.lfi, args.sqli,
                                 args.idor, args.xss, args.csrf, args.ssrf,
                                 args.rce, args.dirs])

        if not args.full and not has_specific_scan:
            print(f"\n{Fore.RED}[!] Erreur : Vous devez spécifier un mode de scan.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Utilisez --full pour un scan complet ou choisissez des scans individuels.{Style.RESET_ALL}\n")
            parser.print_help()
            sys.exit(1)

        run_full = args.full

        if not args.silent:
            scan_type = "complet" if run_full else "sélectif"
            print(f"\n\n\t============== Début du Scan {scan_type} pour -->{domain}<-- 🔍 ==============\n")

        # Run scans
        if run_full or args.ports:
            result = run_scan("ports", scan_ports, domain, threads=threads)
            if result is not None and report_path:
                update_report(report_path, "port_scan", {"open_ports": result})

        if run_full or args.headers:
            result = run_scan("headers", scan_headers, formated_target, timeout=timeout)
            if result is not None and report_path:
                headers, missing, misconfigured = result
                update_report(report_path, "headers_scan", {
                    "headers_received": dict(headers),
                    "missing_headers": missing,
                    "misconfigured_headers": misconfigured
                })

        if run_full or args.lfi:
            result = run_scan("LFI", scan_lfi, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "lfi_scan", {"lfi_tests": result})

        if run_full or args.sqli:
            result = run_scan("SQLi", scan_sqli, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "sqli_scan", {"sqli_tests": result})

        if run_full or args.idor:
            result = run_scan("IDOR", scan_idor, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "idor_scan", {"idor_tests": result})

        if run_full or args.xss:
            result = run_scan("XSS", scan_xss, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "xss_scan", {"xss_tests": result})

        if run_full or args.csrf:
            result = run_scan("CSRF", scan_csrf, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "csrf_scan", {"csrf_tests": result})

        if run_full or args.ssrf:
            result = run_scan("SSRF", scan_ssrf, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "ssrf_scan", {"ssrf_tests": result})

        if run_full or args.rce:
            result = run_scan("RCE", scan_rce, formated_target, domain, timeout=timeout)
            if result is not None and report_path:
                update_report(report_path, "rce_scan", {"rce_tests": result})

        if run_full or args.dirs:
            result = run_scan("directories", scan_dir, formated_target, domain, threads=threads)
            if result is not None and report_path:
                update_report(report_path, "dir_scan", {"dir_tests": result})

        print(f"\n\t============== Fin du Scan pour -->{domain}<-- 🔍 ==============\n")

        # Finalisation
        if report_path:
            finalize_report(report_path)

        choix = input(f"\n🔁 Voulez-vous scanner une autre cible ? ({Fore.GREEN}O{Style.RESET_ALL}/n) : ").strip().lower()
        if choix != "o":
            print(f"\n{Fore.RED}[!] Fin du programme. Merci d'avoir utilisé WebHawk ! {Style.RESET_ALL}\n")
            break
        else:
            print(f"\n{Fore.CYAN}🔄 Relance du scan...{Style.RESET_ALL}\n")
            sys.argv = interactive_mode()


if __name__ == "__main__":
    main()
