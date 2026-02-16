# Security Tools API

AI-powered security assessment using Claude + MCP tools.

## Quick Start

### 1. Start the Server

**Option A: Local (requires nmap, whois installed)**
```bash
pip install -r requirements.txt
python server.py
```

**Option B: Docker**
```bash
docker build -t security-tools .
docker run -p 8000:8000 security-tools
```

Server runs at `http://localhost:8000/sse`

### 2. Run the Client

Set your API key:
```powershell
$env:ANTHROPIC_API_KEY = "your-key-here"
```

**Interactive mode:**
```bash
python client.py
```

**Single query:**
```bash
python client.py "scan scanme.nmap.org for open ports"
```

## Available Tools

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning and service detection |
| `http_headers_check` | Security header analysis |
| `whois_lookup` | Domain registration info |
| `dns_lookup` | DNS record queries |

## AWS Deployment

1. Push to GitHub
2. Launch EC2 (t3.small, ports 22 + 8000 open)
3. Install Docker, clone repo, build and run
4. Update `MCP_SERVER_URL` in client to `http://EC2_IP:8000/sse`

## Example Session

```
You: Check the security headers for https://google.com

Claude: I'll analyze the security headers for google.com...

Security Headers for https://google.com
==================================================
✓ Strict-Transport-Security: max-age=31536000
✗ Content-Security-Policy: MISSING (CSP - Prevents XSS)
✓ X-Frame-Options: SAMEORIGIN
✓ X-Content-Type-Options: nosniff
...
```
