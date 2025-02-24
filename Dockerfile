FROM python:3.10-slim

RUN apt update && apt install -y curl wget nano vim nmap

RUN pip install requests beautifulsoup4

WORKDIR /app

COPY . /app/
CMD ["python"]
