FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better caching)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app

# Create non-root user for security
RUN useradd -m -s /bin/bash webhawk && \
    chown -R webhawk:webhawk /app
USER webhawk

ENTRYPOINT ["python3", "main.py"]
