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
    ruby \
    ruby-dev \
    build-essential \
    libcurl4-openssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    git \
    chromium \
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
    # shuffledns
    && curl -sL https://github.com/projectdiscovery/shuffledns/releases/download/v1.0.9/shuffledns_1.0.9_linux_amd64.zip -o /tmp/shuffledns.zip \
    && unzip -o /tmp/shuffledns.zip -d /usr/local/bin/ \
    # alterx
    && curl -sL https://github.com/projectdiscovery/alterx/releases/download/v0.0.4/alterx_0.0.4_linux_amd64.zip -o /tmp/alterx.zip \
    && unzip -o /tmp/alterx.zip -d /usr/local/bin/ \
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

# Download gowitness (needs chromium which is installed above)
RUN curl -sL https://github.com/sensepost/gowitness/releases/download/2.5.1/gowitness-2.5.1-linux-amd64 -o /usr/local/bin/gowitness \
    && chmod +x /usr/local/bin/gowitness

# Download cero for TLS cert domains (direct binary)
RUN curl -sL https://github.com/glebarez/cero/releases/download/v1.3.0/cero-linux-amd64 -o /usr/local/bin/cero \
    && chmod +x /usr/local/bin/cero

# Update nuclei templates
RUN nuclei -update-templates || true

# Install WPScan (Ruby-based)
RUN gem install wpscan --no-document

# Install Python-based security tools
RUN pip install --no-cache-dir \
    sqlmap \
    commix \
    arjun \
    scoutsuite

# Create wordlists directory
RUN mkdir -p /usr/share/wordlists/dirb \
    && curl -L -o /usr/share/wordlists/dirb/common.txt \
    https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

# Create screenshots directory for gowitness
RUN mkdir -p /tmp/screenshots

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
ENV MCP_TRANSPORT=http
ENV MCP_PORT=8000

# Set chromium path for gowitness
ENV CHROMIUM_PATH=/usr/bin/chromium

# Health check (increased timeout for slow first response)
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the server
CMD ["python", "server.py"]
