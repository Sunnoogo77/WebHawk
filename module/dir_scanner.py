# Bruteforce des répertoires et fichiers cachés
import requests
from urllib.parse import urljoin
import concurrent.futures
from core.config import create_session, DEFAULT_THREADS

# Wordlist de répertoires sensibles
COMMON_DIRECTORIES = [
    "admin", "login", "dashboard", "uploads", "backup", "config", "db", "database",
    "api", "logs", "tmp", "cache", "private", "ftp", "hidden", "secrets", "test",
    "old", "files", "include", "inc", "lib", "library", "assets", "images", "scripts",
    "css", "js", "vendor", "modules", "plugins", "themes", "templates", "docs",
    "manual", "install", "setup", "update", "source", "src", "bin", "cgi-bin",
    "wp-admin", "wp-content", "wp-includes", "phpmyadmin", "cpanel",
    "server-status", "server-info", ".git", ".svn", ".hg",
    "console", "debug", "monitoring", "metrics", "health",
]

# Extensions de fichiers sensibles
SENSITIVE_FILES = [
    "config.php", "config.json", "db.sql", "backup.zip", "admin.php", ".htaccess",
    ".env", "wp-config.php", "server-status", "config.ini", "config.yml", "config.xml",
    "database.sql", "backup.tar.gz", "backup.rar", "backup.7z", "debug.log", "error.log",
    "access.log", "passwd", "shadow", "id_rsa", "id_dsa", "known_hosts", "htpasswd",
    "sitemap.xml", "robots.txt", "package.json", "package-lock.json", "composer.json",
    "composer.lock", "requirements.txt", "Gemfile", "Gemfile.lock", "Dockerfile",
    "docker-compose.yml", ".gitconfig", ".gitignore", ".htpasswd", ".htgroup",
    "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    "phpinfo.php", "info.php", "test.php", "swagger.json", "openapi.json",
    ".well-known/security.txt", "security.txt",
]

BACKUP_EXTENSIONS = [".bak", ".old", ".save", ".tmp", "~", ".orig", ".copy", ".swp"]

SENSITIVE_KEYWORDS = ["password", "secret", "api_key", "token", "database",
                      "db_user", "db_pass", "private_key", "credential", "auth"]


def scan_path(session, target, path, timeout=10):
    """Scan un répertoire ou un fichier."""
    url = urljoin(target + "/", path)
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            if path.endswith(tuple(SENSITIVE_FILES)):
                response = session.get(url, timeout=timeout, allow_redirects=True)
                if any(keyword in response.text.lower() for keyword in SENSITIVE_KEYWORDS):
                    return {"url": url, "status": response.status_code, "type": "sensitive_file_with_content"}
                else:
                    return {"url": url, "status": response.status_code, "type": "sensitive_file"}
            else:
                return {"url": url, "status": response.status_code, "type": "directory"}
        elif response.status_code == 403:
            return {"url": url, "status": 403, "type": "forbidden"}
    except requests.exceptions.RequestException:
        return None
    return None


def scan_dir(target, formated_target, use_threads=True, threads=DEFAULT_THREADS):
    """Scan les répertoires et fichiers sensibles sur un serveur web."""
    print(f"\n\t==============Scan Directory sur --> {formated_target} <-- 🔍 ==============\n")

    found_paths = []
    session = create_session()

    paths_to_scan = []
    paths_to_scan.extend(COMMON_DIRECTORIES)
    paths_to_scan.extend(SENSITIVE_FILES)
    for directory in COMMON_DIRECTORIES:
        for ext in BACKUP_EXTENSIONS:
            paths_to_scan.append(directory + ext)
    for file in SENSITIVE_FILES:
        for ext in BACKUP_EXTENSIONS:
            paths_to_scan.append(file + ext)

    # Remove duplicates
    paths_to_scan = list(set(paths_to_scan))

    total = len(paths_to_scan)
    print(f"[~] {total} chemins à tester...")

    if use_threads:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_path, session, target, path): path for path in paths_to_scan}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_paths.append(result)
                    status_icon = "🔥" if result["type"] == "sensitive_file_with_content" else "⚠️"
                    print(f"[+] {status_icon} {result['type']}: {result['url']} ({result['status']})")
    else:
        for path in paths_to_scan:
            result = scan_path(session, target, path)
            if result:
                found_paths.append(result)
                print(f"[+] {result['type']}: {result['url']} ({result['status']})")

    if not found_paths:
        print("\n✅ Aucun répertoire ou fichier sensible trouvé.")
    else:
        print(f"\n[+] {len(found_paths)} résultat(s) trouvé(s)")

    print("\n✅ Scan de Directories terminé.\n")
    return found_paths
