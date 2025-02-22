# 1. Utiliser une image Linux légère avec Python
FROM python:3.10-slim

# 2. Installer les outils de base
RUN apt update && apt install -y curl wget nano vim nmap

# 3. Installer les bibliothèques Python nécessaires
RUN pip install requests beautifulsoup4

# 4. Définir le répertoire de travail
WORKDIR /app

# 5. Copier les fichiers du projet dans le conteneur
COPY . /app

# 6. Définir le point d’entrée
CMD ["python"]
