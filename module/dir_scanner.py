# Bruteforce des répertoires et fichiers cachés
import requests
import os
from urllib.parse import urljoin
import re
import concurrent.futures

# Wordlist de répertoires sensibles (étendue)
COMMON_DIRECTORIES = [
    "admin", "login", "dashboard", "uploads", "backup", "config", "db", "database",
    "api", "logs", "tmp", "cache", "private", "ftp", "hidden", "secrets", "test",
    "old", "files", "include", "inc", "lib", "library", "assets", "images", "scripts",
    "css", "js", "vendor", "modules", "plugins", "themes", "templates", "docs",
    "manual", "install", "setup", "update", "source", "src", "bin", "cgi-bin"
]

# Extensions de fichiers sensibles (étendue)
SENSITIVE_FILES = [
    "config.php", "config.json", "db.sql", "backup.zip", "admin.php", ".htaccess",
    ".env", "wp-config.php", "server-status", "config.ini", "config.yml", "config.xml",
    "database.sql", "backup.tar.gz", "backup.rar", "backup.7z", "debug.log", "error.log",
    "access.log", "passwd", "shadow", "id_rsa", "id_dsa", "known_hosts", "htpasswd",
    "sitemap.xml", "robots.txt", "package.json", "package-lock.json", "composer.json",
    "composer.lock", "requirements.txt", "Gemfile", "Gemfile.lock", "Dockerfile",
    "docker-compose.yml", "LICENSE", "README.md", "CHANGELOG.md", ".gitconfig",
    ".gitignore", ".htpasswd", ".htgroup", ".bash_history", ".bashrc", ".profile"
]

# Extensions de fichiers de sauvegarde
BACKUP_EXTENSIONS = [".bak", ".old", ".save", ".tmp", "~"]

# Mots-clés sensibles pour la détection de contenu
SENSITIVE_KEYWORDS = ["password", "secret", "api_key", "token", "database", "db_user", "db_pass"]

def scan_path(session, target, path):
    """Scan un répertoire ou un fichier."""
    url = urljoin(target, path)
    try:
        print(f"[~] Test de l'URL : {url}")
        response = session.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            if path.endswith(tuple(SENSITIVE_FILES)):
                
                response = session.get(url, timeout=5, allow_redirects=True)
                if any(keyword in response.text.lower() for keyword in SENSITIVE_KEYWORDS):
                    return f"Fichier sensible trouvé (avec contenu sensible) : {url}"
                else:
                    return f"⚠️ Fichier sensible trouvé : {url}"
            else:
                return f"⚠️ Trouvé : {url} ({response.status_code})"
        elif response.status_code == 403:
            return f"⚠️ Trouvé (interdit) : {url} ({response.status_code})"
    except requests.exceptions.RequestException as e:
        # print(f"[-][X] ERR")
        return None
    return None

def scan_dir(target, formated_target, use_threads=True):
    """Scan les répertoires et fichiers sensibles sur un serveur web."""
    print(f"\n\t==============Scan Directory Traversal sur --> {formated_target} <--  ==============\n")

    found_paths = []
    session = requests.Session()
    session.verify = False  # Ignore SSL warnings

    paths_to_scan = []
    paths_to_scan.extend(COMMON_DIRECTORIES)
    paths_to_scan.extend(SENSITIVE_FILES)
    for directory in COMMON_DIRECTORIES:
        for ext in BACKUP_EXTENSIONS:
            paths_to_scan.append(directory + ext)
    for file in SENSITIVE_FILES:
        for ext in BACKUP_EXTENSIONS:
            paths_to_scan.append(file + ext)

    if use_threads:
        print("[!][~] Utilisation de threads pour le scan...")
        print("[!][~]...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = [executor.submit(scan_path, session, target, path) for path in paths_to_scan]
            for future in concurrent.futures.as_completed(results):
                result = future.result()
                if result:
                    found_paths.append(result)
                    print(f"[+] {result}")
                    # print(result)
    else:
        for path in paths_to_scan:
            result = scan_path(session, target, path)
            if result:
                found_paths.append(result)
                print(f"[+] {result}")
                # print(result)

    if not found_paths:
        print("\n✅ Aucun répertoire ou fichier sensible trouvé.")

    # print("[!][~]")
    # print("[!][~]")
    # for items in found_paths:
    #     print(f"[!][~][+]{items}")
    return found_paths
