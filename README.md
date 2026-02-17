# Security Tools API

**AI-Powered Black-Box Security Assessment Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.0+-green.svg)](https://github.com/jlowin/fastmcp)
[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock-orange.svg)](https://aws.amazon.com/bedrock/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

---

## Overview

Security Tools API is a comprehensive penetration testing platform that combines **25 industry-standard security tools** with **Claude AI** (via AWS Bedrock) for intelligent, automated security assessments.

### Key Features

- **25 Security Tools** - Nmap, Nuclei, SQLMap, WPScan, Amass, and more
- **AI-Powered Analysis** - Claude systematically executes tools and correlates findings
- **Professional Methodology** - Follows structured pentesting phases
- **Report Generation** - Generates markdown reports for client delivery
- **No Network Restrictions** - Bypasses Claude Desktop's proxy limitations
- **Pay-as-you-go** - Uses AWS Bedrock (no pre-paid credits needed)

---

## Architecture

```
┌─────────────────────────────┐          ┌─────────────────────────────────┐
│  YOUR MACHINE               │          │  AWS EC2 (Docker)               │
│                             │          │                                 │
│  client_bedrock.py          │   HTTP   │  server.py (FastMCP)            │
│  ├── AWS Bedrock (Claude)   │ ───────▶ │  └── 25 security tools          │
│  ├── Interactive CLI        │          │      (nmap, nuclei, etc.)       │
│  └── Report generation      │          │                                 │
└─────────────────────────────┘          └─────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- AWS Account
- Basic familiarity with AWS Console

---

### Step 1: AWS IAM Setup

You need an IAM user with permissions to access AWS Bedrock (Claude AI).

#### 1.1 Create IAM User

1. Go to [AWS IAM Console](https://console.aws.amazon.com/iam/)
2. Click **Users** → **Create user**
3. User name: `security-tools-user`
4. Click **Next**

#### 1.2 Attach Permissions

Select **Attach policies directly** and add these policies:

| Policy | Purpose |
|--------|---------|
| `AmazonBedrockFullAccess` | Access Claude models |

Or create a custom policy with minimum permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.*"
        }
    ]
}
```

#### 1.3 Create Access Keys

1. Click on your new user → **Security credentials** tab
2. Click **Create access key**
3. Select **Command Line Interface (CLI)**
4. Click **Create access key**
5. **SAVE these credentials** (you won't see the secret key again):
   - Access Key ID: `AKIA...`
   - Secret Access Key: `wJalr...`

---

### Step 2: Launch EC2 Instance

#### 2.1 Create Instance

1. Go to [EC2 Console](https://console.aws.amazon.com/ec2/)
2. Click **Launch Instance**

| Setting | Value |
|---------|-------|
| Name | `security-tools-server` |
| AMI | Amazon Linux 2023 |
| Instance Type | `t3.medium` (4GB RAM for builds) |
| Key Pair | Create new → Download `.pem` file |
| Storage | 20 GB gp3 |

#### 2.2 Configure Security Group

Under **Network Settings**, click **Edit** and add:

| Type | Port | Source | Purpose |
|------|------|--------|---------|
| SSH | 22 | My IP | SSH access |
| Custom TCP | 8000 | My IP (or 0.0.0.0/0) | Tool API |

#### 2.3 Launch and Note Public IP

After launch, note the **Public IPv4 address** (e.g., `54.123.45.67`)

---

### Step 3: Deploy Server on EC2

#### 3.1 Connect to EC2

**Windows (PowerShell):**
```powershell
# Move key file
Move-Item "$env:USERPROFILE\Downloads\your-key.pem" "$env:USERPROFILE\.ssh\"

# Fix permissions
icacls "$env:USERPROFILE\.ssh\your-key.pem" /inheritance:r /grant:r "$env:USERNAME:R"

# Connect
ssh -i "$env:USERPROFILE\.ssh\your-key.pem" ec2-user@YOUR_EC2_IP
```

**macOS/Linux:**
```bash
chmod 400 ~/Downloads/your-key.pem
ssh -i ~/Downloads/your-key.pem ec2-user@YOUR_EC2_IP
```

#### 3.2 Install Docker on EC2

```bash
# Update system
sudo yum update -y

# Install Docker and Git
sudo yum install -y docker git

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker ec2-user

# IMPORTANT: Logout and reconnect for group to take effect
exit
```

Reconnect via SSH, then continue:

#### 3.3 Clone and Build

```bash
# Clone repository
git clone https://github.com/YOUR_ORG/security-tools-api.git
cd security-tools-api

# Build Docker image (takes 5-10 minutes)
docker build -t security-tools .

# Run container
docker run -d -p 8000:8000 --name security-server security-tools

# Verify it's running
curl http://localhost:8000/health
# Should return: {"status": "healthy", "tools_available": 25}
```

---

### Step 4: Configure Client (Local Machine)

#### 4.1 Clone Repository Locally

```bash
git clone https://github.com/YOUR_ORG/security-tools-api.git
cd security-tools-api
```

#### 4.2 Install Python Dependencies

```bash
# Create virtual environment (recommended)
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 4.3 Configure AWS Credentials

**Option A: AWS CLI Configure (Recommended)**

```bash
aws configure
```

Enter when prompted:
```
AWS Access Key ID [None]: AKIAXXXXXXXXXXXXXXXX
AWS Secret Access Key [None]: wJalrXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Default region name [None]: us-east-1
Default output format [None]: json
```

**Option B: Environment Variables**

**Windows (PowerShell):**
```powershell
$env:AWS_ACCESS_KEY_ID = "AKIAXXXXXXXXXXXXXXXX"
$env:AWS_SECRET_ACCESS_KEY = "wJalrXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$env:AWS_REGION = "us-east-1"
```

**macOS/Linux:**
```bash
export AWS_ACCESS_KEY_ID="AKIAXXXXXXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="wJalrXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
export AWS_REGION="us-east-1"
```

#### 4.4 Set Server URL

Point the client to your EC2 instance:

**Windows (PowerShell):**
```powershell
$env:MCP_SERVER_URL = "http://YOUR_EC2_IP:8000"
```

**macOS/Linux:**
```bash
export MCP_SERVER_URL="http://YOUR_EC2_IP:8000"
```

#### 4.5 Verify Connection

```bash
# Test EC2 connection
curl http://YOUR_EC2_IP:8000/health

# Test AWS credentials
aws sts get-caller-identity
```

---

### Step 5: Run Assessment

```bash
python client_bedrock.py
```

```
============================================================
  Security Assessment Tool - AWS Bedrock Edition
  Black-Box Penetration Testing Platform
============================================================

  Server: http://YOUR_EC2_IP:8000
  Model: anthropic.claude-3-opus-20240229-v1:0
  
  Commands: 'help', 'report', 'quit'
============================================================

You: Perform a comprehensive security assessment of example.com

[Claude executes tools systematically across 6 phases...]
[Findings correlated and risk-rated...]

You: report

[Generates security_report_20260217_143022.md]
```

---

### Quick Reference Commands

| Task | Command |
|------|---------|
| Start server (EC2) | `docker run -d -p 8000:8000 --name security-server security-tools` |
| Check server health | `curl http://EC2_IP:8000/health` |
| Start client | `python client_bedrock.py` |
| Generate report | Type `report` in client |
| Stop server | `docker stop security-server` |
| View server logs | `docker logs security-server` |

---

## Available Tools (25)

### Network Scanning
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning, service detection |
| `masscan_scan` | High-speed port scanning |
| `httpx_probe` | HTTP/HTTPS probing |

### DNS & OSINT
| Tool | Description |
|------|-------------|
| `dns_lookup` | DNS record queries |
| `whois_lookup` | Domain registration info |
| `crtsh_lookup` | Certificate transparency |
| `cero_scan` | TLS certificate domains |

### Subdomain Enumeration
| Tool | Description |
|------|-------------|
| `amass_enum` | Deep subdomain enumeration |
| `assetfinder_enum` | Fast passive discovery |
| `alterx_generate` | Wordlist permutations |
| `shuffledns_scan` | DNS brute-forcing |
| `arjun_scan` | Hidden parameter discovery |

### Web Application
| Tool | Description |
|------|-------------|
| `http_headers_check` | Security headers analysis |
| `ffuf_fuzz` | Directory brute-forcing |
| `katana_crawl` | Web crawling |
| `waybackurls_fetch` | Historical URLs |

### Vulnerability Scanning
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Template-based scanning |
| `sqlmap_scan` | SQL injection testing |
| `sslscan_check` | SSL/TLS analysis |
| `commix_scan` | Command injection |
| `smuggler_scan` | HTTP smuggling |

### Specialized
| Tool | Description |
|------|-------------|
| `wpscan_scan` | WordPress vulnerabilities |
| `gowitness_screenshot` | Web screenshots |
| `scoutsuite_scan` | Cloud security (AWS/Azure/GCP) |
| `mobsf_scan` | Mobile app analysis |

---

## Usage Examples

### Simple Scan
```
You: Check security headers for https://example.com
```

### Comprehensive Assessment
```
You: Perform a full security assessment of target.com
```

### Targeted Vulnerability Scan
```
You: Run nuclei vulnerability scan on https://target.com with high severity templates
```

### WordPress Site
```
You: Scan wordpress-site.com for WordPress vulnerabilities and enumerate plugins
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SERVER_URL` | http://localhost:8000 | EC2 server URL |
| `AWS_REGION` | us-east-1 | AWS region for Bedrock |
| `BEDROCK_MODEL` | anthropic.claude-3-opus-20240229-v1:0 | Claude model |

### Model Selection

| Model | Best For | Cost |
|-------|----------|------|
| **Opus** | Comprehensive assessments | $$$ |
| **Sonnet** | Routine scans | $$ |
| **Haiku** | Simple operations | $ |

```powershell
# Use faster/cheaper model
$env:BEDROCK_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"
```

---

## Project Structure

```
security-tools-api/
├── server.py                 # FastMCP server (runs on EC2)
├── client_bedrock.py         # AWS Bedrock client (primary)
├── client.py                 # Anthropic API client (deprecated)
├── Dockerfile                # Container with all tools
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── COMPLETE-SETUP-GUIDE.md   # Full technical documentation
│
└── tools/                    # Tool implementations
    ├── __init__.py           # Central exports
    ├── network.py            # nmap, masscan, httpx
    ├── dns.py                # dns_lookup, whois, crtsh
    ├── web.py                # headers, ffuf, katana, waybackurls
    ├── vuln.py               # nuclei, sqlmap, sslscan
    ├── recon.py              # amass, assetfinder
    ├── injection.py          # commix, smuggler
    ├── wordpress.py          # wpscan
    ├── cloud.py              # scoutsuite
    ├── discovery.py          # alterx, arjun, shuffledns, gowitness, cero
    └── mobile.py             # mobsf
```

---

## API Reference

### Health Check
```bash
curl http://EC2_IP:8000/health
```

### List Tools
```bash
curl http://EC2_IP:8000/mcp/v1/tools
```

### Execute Tool
```bash
curl -X POST http://EC2_IP:8000/mcp/v1/tools/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "scan_type": "quick"}'
```

---

## Assessment Methodology

The platform follows a 6-phase penetration testing methodology:

1. **Reconnaissance & OSINT** - whois, dns, crtsh, cero
2. **Subdomain Enumeration** - assetfinder, amass, alterx, shuffledns
3. **Service Discovery** - httpx, nmap, masscan, gowitness
4. **Web Application Analysis** - headers, katana, waybackurls, ffuf, arjun
5. **Vulnerability Assessment** - nuclei, sqlmap, sslscan, commix, smuggler
6. **Specialized Assessments** - wpscan, scoutsuite, mobsf

---

## Why This Exists

**The Problem:** Claude Desktop's network proxy blocks security scans.

**The Solution:** Deploy tools on EC2, use Claude API (via Bedrock) to orchestrate.

See [COMPLETE-SETUP-GUIDE.md](COMPLETE-SETUP-GUIDE.md) for the full technical journey.

---

## Requirements

### Server (EC2)
- Docker
- 2+ GB RAM (4GB recommended for builds)
- Port 8000 open

### Client (Local)
- Python 3.11+
- AWS credentials with Bedrock access
- Network access to EC2

---

## Security Notice

**Only use this platform on systems you have explicit written authorization to test.**

---

## Documentation

- [Complete Setup Guide](COMPLETE-SETUP-GUIDE.md) - Full technical documentation
- [AWS Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/) - Cost information

---

## License

MIT License - See LICENSE file

---

## Credits

Built on top of:
- [MCP-for-Security](https://github.com/cyproxio/mcp-for-security) by Cyprox
- [FastMCP](https://github.com/jlowin/fastmcp) framework
- [ProjectDiscovery](https://projectdiscovery.io/) tools
