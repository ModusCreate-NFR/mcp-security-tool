# Security Tools API Server
# Uses pre-built binaries (no Go compilation required)

FROM python:3.11-slim

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    unzip \
    ca-certificates \
    nmap \
    masscan \
    whois \
    dnsutils \
    sslscan \
    && rm -rf /var/lib/apt/lists/*

# Download pre-built ProjectDiscovery tools (no compilation!)
RUN mkdir -p /usr/local/bin \
    # Nuclei
    && curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    # httpx  
    && curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ \
    # katana
    && curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.0.4/katana_1.0.4_linux_amd64.zip -o /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin/ \
    # ffuf
    && curl -sL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ \
    # amass
    && curl -sL https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip -o /tmp/amass.zip \
    && unzip -o /tmp/amass.zip -d /tmp/amass \
    && mv /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/ \
    # Clean up
    && rm -rf /tmp/*.zip /tmp/*.tar.gz /tmp/amass \
    && chmod +x /usr/local/bin/*

# Download simpler Go tools (single binaries)
RUN curl -sL https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz -o /tmp/assetfinder.tgz \
    && tar -xzf /tmp/assetfinder.tgz -C /usr/local/bin/ \
    && curl -sL https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz -o /tmp/waybackurls.tgz \
    && tar -xzf /tmp/waybackurls.tgz -C /usr/local/bin/ \
    && rm -rf /tmp/*.tgz \
    && chmod +x /usr/local/bin/assetfinder /usr/local/bin/waybackurls

# Update nuclei templates
RUN nuclei -update-templates || true

# Install sqlmap (Python-based)
RUN pip install --no-cache-dir sqlmap

# Create wordlists directory
RUN mkdir -p /usr/share/wordlists/dirb \
    && curl -L -o /usr/share/wordlists/dirb/common.txt \
    https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

# Set up Python application
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY tools/ ./tools/
COPY server.py .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the server
CMD ["python", "server.py"]
