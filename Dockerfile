# Security Tools API Server
# Multi-stage build for smaller final image

FROM python:3.11-slim AS base

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl \
    wget \
    unzip \
    ca-certificates \
    # Network tools
    nmap \
    masscan \
    # DNS tools
    whois \
    dnsutils \
    # SSL tools
    sslscan \
    # Build dependencies for some tools
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Go for ProjectDiscovery tools
ENV GO_VERSION=1.21.6
RUN curl -LO https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"

# Install ProjectDiscovery tools (nuclei, httpx, katana, ffuf)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest

# Install subdomain enumeration tools
RUN go install -v github.com/owasp-amass/amass/v4/...@master \
    && go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/tomnomnom/waybackurls@latest

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
