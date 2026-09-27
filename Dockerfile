FROM python:3.11-slim

LABEL maintainer="Cyber Security Team"
LABEL description="Internal Network & Asset Discovery Scanner Agent"

# Install system dependencies (Nmap, arp-scan for L2 discovery, iproute2, network tools, cron)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    iproute2 \
    net-tools \
    curl \
    cron \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY scanner /app/scanner
COPY config /app/config
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/scanner/main.py

# Create output and state directories
RUN mkdir -p /app/output/state

VOLUME ["/app/output", "/app/config"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--auto-detect"]
