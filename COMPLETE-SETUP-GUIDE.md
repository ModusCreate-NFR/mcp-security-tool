# Security Tools API - Complete Setup Guide

## AI-Powered Security Assessment Platform

**Date:** February 2026  
**Purpose:** Bypass Claude Desktop's network restrictions by deploying security tools to AWS EC2

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem We Solved](#2-the-problem-we-solved)
3. [Architecture Overview](#3-architecture-overview)
   - [Technical Deep Dive (For Engineers)](#technical-deep-dive-for-engineers)
4. [What Was Built](#4-what-was-built)
5. [EC2 Instance Setup](#5-ec2-instance-setup)
6. [Docker Deployment](#6-docker-deployment)
7. [Testing the Deployment](#7-testing-the-deployment)
8. [Using from Local Machine](#8-using-from-local-machine)
9. [Claude API Integration](#9-claude-api-integration)
10. [Team Usage Guide](#10-team-usage-guide)
11. [Security Considerations](#11-security-considerations)
12. [Troubleshooting](#12-troubleshooting)
13. [Cost Estimates](#13-cost-estimates)

---

## 1. Executive Summary

### What We Achieved

We built a cloud-based security tools platform that allows Claude (AI) to execute real security scans on any target, bypassing the network restrictions imposed by Claude Desktop.

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **server.py** | AWS EC2 | Runs security tools (nmap, whois, DNS, headers) |
| **client.py** | User's laptop | Chat interface connecting Claude + EC2 tools |
| **Docker** | EC2 | Containerized deployment with all tools pre-installed |

### The Result

```
User: "Scan example.com for open ports"
     ↓
Claude API (understands request)
     ↓
client.py (calls EC2 server)
     ↓
EC2 runs nmap on example.com
     ↓
Results returned to Claude
     ↓
Claude: "I found ports 22 and 80 open. Here's my analysis..."
```

---

## 2. The Problem We Solved

### Claude Desktop Limitation

Claude Desktop runs MCP tools through a **network egress proxy** that restricts outbound connections to a whitelist of approved domains.

**What this means:**
- Security tools configured in Claude Desktop CANNOT scan arbitrary targets
- Requests to non-whitelisted domains return: `403 Forbidden - host_not_allowed`
- This blocks ALL practical security scanning use cases

**Example error from Claude Desktop:**
```
The request is being blocked with a 'host_not_allowed' error 
(403 Forbidden). This suggests that the network egress proxy is 
blocking access to [target] because it's not in the allowed domains list.
```

### Allowed vs Blocked Domains

| Allowed (Anthropic whitelist) | Blocked (Everything else) |
|-------------------------------|---------------------------|
| api.anthropic.com | Your client websites |
| github.com | Target domains |
| pypi.org | Internal networks |
| npmjs.com | Custom targets |

### Why Claude Desktop Has This Restriction

- Prevents using Claude as an attack platform
- Protects against scanning random sites through Anthropic's infrastructure
- Compliance and liability protection

### Our Solution

Instead of running tools inside Claude Desktop → Run tools on our own EC2 server → Claude API calls our server → No proxy restrictions!

---

## 3. Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           YOUR LOCAL MACHINE                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  client.py                                                       │   │
│  │  - Chat interface                                                │   │
│  │  - Sends requests to Claude API                                  │   │
│  │  - Calls EC2 when Claude wants to use a tool                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
            ┌───────────────────┴───────────────────┐
            │                                       │
            ▼                                       ▼
┌───────────────────────┐               ┌───────────────────────────────┐
│    CLAUDE API         │               │       AWS EC2 INSTANCE        │
│    (Anthropic)        │               │                               │
│                       │               │  ┌─────────────────────────┐  │
│  - Understands your   │               │  │  Docker Container       │  │
│    natural language   │               │  │                         │  │
│  - Decides which      │               │  │  server.py              │  │
│    tool to use        │               │  │  - nmap_scan            │  │
│  - Analyzes results   │               │  │  - http_headers_check   │  │
│                       │               │  │  - whois_lookup         │  │
│                       │               │  │  - dns_lookup           │  │
│                       │               │  │                         │  │
│                       │               │  │  Port 8000              │  │
└───────────────────────┘               │  └─────────────────────────┘  │
                                        │                               │
                                        │  Can scan ANY target:         │
                                        │  ✓ Client websites            │
                                        │  ✓ External domains           │
                                        │  ✓ Internal networks          │
                                        └───────────────────────────────┘
```

### Request Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         REQUEST FLOW                                      │
└──────────────────────────────────────────────────────────────────────────┘

User types: "Scan scanme.nmap.org for open ports"
    │
    ▼
┌─────────────────────────────────────┐
│  1. client.py sends to Claude API   │
│     with tool definitions           │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  2. Claude decides: "I should use   │
│     nmap_scan tool with target      │
│     scanme.nmap.org"                │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  3. client.py calls EC2:            │
│     POST /mcp/v1/tools/nmap_scan    │
│     {"target": "scanme.nmap.org"}   │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  4. EC2 runs actual nmap command:   │
│     nmap -F -sV scanme.nmap.org     │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  5. Results returned to client.py   │
│     → sent back to Claude API       │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  6. Claude analyzes and responds:   │
│     "I found ports 22 and 80 open.  │
│      Port 22 is SSH, 80 is HTTP..." │
└─────────────────────────────────────┘
```

### Comparison: Claude Desktop vs Our Solution

```
┌─────────────────────────────────────────────────────────────────────────┐
│              CLAUDE DESKTOP (Limited)                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   User ──▶ Claude Desktop ──▶ MCP Tool ──▶ PROXY ──╳ Target             │
│                                              │                           │
│                                        403 Forbidden                     │
│                                        host_not_allowed                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              OUR SOLUTION (No Restrictions)                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   User ──▶ client.py ──▶ Claude API ──▶ client.py ──▶ EC2 ──▶ Target   │
│                              │                          │                │
│                         AI thinking               Direct connection      │
│                                                    (no proxy!)           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Technical Deep Dive (For Engineers)

This section explains the technical architecture in detail - what each component does, why we made certain design choices, and how the pieces fit together.

#### What is MCP (Model Context Protocol)?

MCP is Anthropic's open protocol that allows AI assistants to use external tools. Think of it as a standard way for Claude to call functions that live outside of Claude.

**MCP defines:**
- How tools are described (name, description, parameters, JSON schema)
- How tools are invoked (input/output format)
- Transport mechanisms (how data flows between Claude and tools)

**Two Transport Types:**

| Transport | How It Works | Use Case |
|-----------|--------------|----------|
| **stdio** | Tools run as separate processes, communicate via stdin/stdout | Claude Desktop's native MCP support |
| **HTTP/SSE** | Tools exposed as REST API endpoints over HTTP | Remote servers, web apps, our solution |

#### What is FastMCP?

FastMCP is a **Python framework** that makes it easy to create MCP servers. It handles all the protocol details so you just write Python functions.

**What FastMCP does:**
```
Your Python function    →    FastMCP    →    MCP-compatible server
                              ↓
                         Creates HTTP endpoints
                         Handles JSON schemas
                         Manages request/response format
```

**The key insight:** FastMCP converts decorated Python functions into HTTP API endpoints automatically.

**Example - How FastMCP transforms code:**

```python
# You write this:
@mcp.tool()
def nmap_scan(target: str, scan_type: str = "quick") -> str:
    """Run an nmap scan against a target."""
    result = subprocess.run(["nmap", "-F", target], capture_output=True)
    return result.stdout.decode()

# FastMCP automatically creates:
# - POST /mcp/v1/tools/nmap_scan endpoint
# - JSON schema for parameters (target: string required, scan_type: string optional)
# - Request/response handling
# - Error handling
```

**FastMCP's role in our stack:**

```
┌─────────────────────────────────────────────────────────────────┐
│                        server.py                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   from fastmcp import FastMCP                                   │
│   mcp = FastMCP("security-tools")                               │
│                                                                  │
│   @mcp.tool()          ←── FastMCP decorator                    │
│   def nmap_scan(...):                                           │
│       ...              ←── Your business logic                  │
│                                                                  │
│   app = mcp.http_app() ←── FastMCP creates Starlette ASGI app   │
│   uvicorn.run(app)     ←── Standard Python web server           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Why One File vs. Multiple Folders?

The original [mcp-for-security](https://github.com/cyproxio/mcp-for-security) project has 19 folders - one per tool:

```
mcp-for-security/
├── nmap-mcp/          # Standalone MCP server for nmap
├── nuclei-mcp/        # Standalone MCP server for nuclei
├── sqlmap-mcp/        # Standalone MCP server for sqlmap
├── ffuf-mcp/          # etc...
└── ... (16 more)
```

**Why separate folders?** Because the original uses **stdio transport**:
- Each tool runs as its own process
- Claude Desktop spawns each process separately
- Each needs its own `package.json`, build system, entry point

**Our approach uses HTTP transport:**
- All tools run in ONE server process
- One HTTP endpoint serves all tools
- Much simpler deployment and management

**Comparison:**

| Aspect | Original (stdio) | Our Solution (HTTP) |
|--------|------------------|---------------------|
| Deployment | 19 separate processes | 1 Docker container |
| Configuration | 19 entries in claude_desktop_config.json | 1 server URL |
| Adding a tool | New folder, package.json, build | Add one function to server.py |
| Communication | stdin/stdout pipes | HTTP REST API |
| Where it runs | Same machine as Claude Desktop | Any server (local or remote) |

**Why stdio requires separate processes:**

```
Claude Desktop with stdio:
┌─────────────────────────────────────────────────────────────────┐
│  Claude Desktop                                                  │
│  ├── spawns → nmap-mcp process (stdin/stdout)                   │
│  ├── spawns → nuclei-mcp process (stdin/stdout)                 │
│  ├── spawns → sqlmap-mcp process (stdin/stdout)                 │
│  └── ... 16 more processes                                      │
└─────────────────────────────────────────────────────────────────┘

Our HTTP approach:
┌─────────────────────────────────────────────────────────────────┐
│  client.py ──HTTP──→ EC2:8000 (single server, all tools)        │
└─────────────────────────────────────────────────────────────────┘
```

#### How client.py Works (Claude API, Not Claude Desktop)

**Important distinction:**
- **Claude Desktop** = The Anthropic desktop app with built-in MCP support
- **Claude API** = Anthropic's HTTP API that any program can call

Our `client.py` uses the **Claude API directly**. It's a standalone Python script that:
1. Talks to Anthropic's API (api.anthropic.com)
2. Handles tool calls itself (not relying on Claude Desktop)
3. Calls our EC2 server when Claude wants to use a tool

**The tool-use flow in detail:**

```python
# Step 1: Define tools for Claude (in client.py)
tools = [
    {
        "name": "nmap_scan",
        "description": "Run nmap scan",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string"}
            },
            "required": ["target"]
        }
    }
]

# Step 2: Send user message + tool definitions to Claude API
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    messages=[{"role": "user", "content": "Scan example.com"}],
    tools=tools  # Tell Claude what tools are available
)

# Step 3: Claude responds with tool_use (not text!)
# response.content[0] = {
#     "type": "tool_use",
#     "name": "nmap_scan",
#     "input": {"target": "example.com", "scan_type": "quick"}
# }

# Step 4: WE execute the tool (call EC2)
result = call_mcp_tool("nmap_scan", {"target": "example.com"})

# Step 5: Send result back to Claude for analysis
response = client.messages.create(
    messages=[
        {"role": "user", "content": "Scan example.com"},
        {"role": "assistant", "content": tool_use_block},
        {"role": "user", "content": tool_result}  # The nmap output
    ]
)

# Step 6: NOW Claude responds with analysis text
```

**Why this matters:** Our Python script is the "glue" between Claude's brain and our tools. Claude never directly calls our EC2 server - `client.py` does that when Claude asks.

#### The Full Component Stack

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          COMPLETE STACK                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  USER LAYER                                                              │
│  └── You type: "Scan example.com for vulnerabilities"                   │
│                                                                          │
│  CLIENT LAYER (client.py on your laptop)                                │
│  ├── anthropic Python SDK                                               │
│  ├── Sends prompt + tool definitions to Claude API                      │
│  ├── Receives tool_use requests from Claude                             │
│  ├── httpx HTTP client → calls EC2 server                               │
│  └── Returns tool results to Claude for analysis                        │
│                                                                          │
│  AI LAYER (Anthropic's servers)                                         │
│  ├── Claude model (e.g., claude-sonnet)                                 │
│  ├── Understands natural language                                       │
│  ├── Decides which tools to use                                         │
│  └── Analyzes results and generates response                            │
│                                                                          │
│  TOOL LAYER (EC2 server)                                                │
│  ├── FastMCP framework (creates HTTP API from functions)                │
│  ├── Starlette (ASGI web framework, created by FastMCP)                 │
│  ├── uvicorn (ASGI server, runs the web app)                            │
│  └── Actual tools: nmap, whois, dig (system binaries)                   │
│                                                                          │
│  INFRASTRUCTURE LAYER (AWS)                                             │
│  ├── EC2 instance (Amazon Linux 2023)                                   │
│  ├── Docker container (python:3.11-slim + tools)                        │
│  └── Security Group (controls network access)                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Why We Didn't Use the Original MCP-for-Security

The original project is well-built, but it's designed for **stdio transport with Claude Desktop**:

| Original Design | Our Requirement |
|-----------------|-----------------|
| Runs on same machine as Claude Desktop | Runs on remote server (bypass proxy) |
| Uses stdio (stdin/stdout) | Needs HTTP (for remote access) |
| Each tool = separate Node.js process | All tools = one Python process |
| Configured in Claude Desktop config file | Accessed via API URL |

**The fundamental blocker:** Even if we ran the original tools, Claude Desktop's network proxy would still block outbound scans. We needed tools running OUTSIDE of Claude Desktop's network sandbox.

#### Technologies Summary

| Technology | What | Role in Our Stack |
|------------|------|-------------------|
| **FastMCP** | Python framework | Converts functions to MCP-compatible HTTP endpoints |
| **Starlette** | ASGI web framework | Created by FastMCP, handles HTTP routing |
| **uvicorn** | ASGI server | Runs the Starlette app, listens on port 8000 |
| **anthropic** | Python SDK | Calls Claude API from client.py |
| **httpx** | HTTP client | Calls EC2 server from client.py |
| **Docker** | Containerization | Packages server + tools for deployment |

---

## 4. What Was Built

### Repository Structure

```
mcp-security-tool/
├── server.py           # Main server - runs on EC2
├── client.py           # Chat client - runs on user's machine
├── Dockerfile          # Container definition
├── requirements.txt    # Python dependencies
├── README.md           # Quick start guide
└── COMPLETE-SETUP-GUIDE.md  # This document
```

### server.py - The Tool Server

**Purpose:** Exposes security tools via REST API

**Technologies:**
- FastMCP (MCP server framework)
- Starlette (ASGI web framework)
- uvicorn (ASGI server)

**Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp/v1/tools` | GET | List available tools |
| `/mcp/v1/tools/nmap_scan` | POST | Run nmap scan |
| `/mcp/v1/tools/http_headers_check` | POST | Check security headers |
| `/mcp/v1/tools/whois_lookup` | POST | WHOIS lookup |
| `/mcp/v1/tools/dns_lookup` | POST | DNS record query |

**Available Tools:**

| Tool | Description | Example Input |
|------|-------------|---------------|
| `nmap_scan` | Port scanning and service detection | `{"target": "example.com", "scan_type": "quick"}` |
| `http_headers_check` | Analyze HTTP security headers | `{"url": "https://example.com"}` |
| `whois_lookup` | Domain registration information | `{"domain": "example.com"}` |
| `dns_lookup` | DNS record queries | `{"domain": "example.com", "record_type": "MX"}` |

### client.py - The Chat Interface

**Purpose:** Natural language interface to security tools via Claude

**How it works:**
1. User types a request
2. Client sends to Claude API with tool definitions
3. Claude decides which tool(s) to use
4. Client calls EC2 server to execute tools
5. Results go back to Claude for analysis
6. Claude provides human-readable response

### Dockerfile

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

EXPOSE 8000
CMD ["python", "server.py"]
```

**Includes:**
- Python 3.11
- nmap (network scanner)
- whois (domain lookup)
- dnsutils (nslookup)
- FastMCP + uvicorn

---

## 5. EC2 Instance Setup

### Step 1: Launch EC2 Instance

**AWS Console Navigation:**
1. Go to [console.aws.amazon.com](https://console.aws.amazon.com)
2. Search for "EC2" → Click "Launch Instance"

**Instance Configuration:**

| Setting | Value | Notes |
|---------|-------|-------|
| Name | `mcp-security-tools` | Descriptive name |
| AMI | Amazon Linux 2023 | Free tier eligible |
| Instance Type | `t2.micro` or `t3.small` | t2.micro is free tier |
| Key Pair | Create new: `security-tools-key` | Download .pem file! |

### Step 2: Security Group Configuration

**Inbound Rules:**

| Type | Port | Source | Purpose |
|------|------|--------|---------|
| SSH | 22 | My IP | Connect to server |
| Custom TCP | 8000 | 0.0.0.0/0 (or restrict to team IPs) | Security tools API |

**How to set up:**
1. During instance launch, click "Edit" under Network Settings
2. Add rule: Type = "Custom TCP", Port = 8000, Source = "Anywhere" (or specific IPs)

### Step 3: Connect to EC2

**Move key file (Windows PowerShell):**
```powershell
Move-Item "$env:USERPROFILE\Downloads\security-tools-key.pem" "$env:USERPROFILE\.ssh\"
```

**Fix key permissions (Windows):**
```powershell
icacls "$env:USERPROFILE\.ssh\security-tools-key.pem" /inheritance:r /grant:r "$env:USERNAME:R"
```

**Connect:**
```bash
ssh -i ~/.ssh/security-tools-key.pem ec2-user@OUR_EC2_PUBLIC_IP
```

### Step 4: Install Docker on EC2

**Run these commands on EC2:**

```bash
# Update system
sudo yum update -y

# Install Docker and Git
sudo yum install -y docker git

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (so you don't need sudo)
sudo usermod -aG docker $USER

# IMPORTANT: Log out and back in for group change to take effect
exit
```

**Reconnect:**
```bash
ssh -i ~/.ssh/security-tools-key.pem ec2-user@OUR_EC2_PUBLIC_IP
```

**Verify Docker works:**
```bash
docker --version
docker run hello-world
```

---

## 6. Docker Deployment

### Step 1: Clone the Repository

```bash
git clone https://github.com/ModusCreate-NFR/mcp-security-tool.git
cd mcp-security-tool
```

### Step 2: Build Docker Image

```bash
docker build -t security-tools .
```

**Expected output:**
```
Sending build context to Docker daemon  10.24kB
Step 1/8 : FROM python:3.11-slim
...
Step 8/8 : CMD ["python", "server.py"]
Successfully built abc123def456
Successfully tagged security-tools:latest
```

**Build time:** ~2-5 minutes (depends on network speed)

### Step 3: Run the Container

**Start in detached mode (background):**
```bash
docker run -d -p 8000:8000 --name security-server security-tools
```

**Flags explained:**
- `-d` = detached (runs in background)
- `-p 8000:8000` = map host port 8000 to container port 8000
- `--name security-server` = container name for easy reference

### Step 4: Verify It's Running

**Check container status:**
```bash
docker ps
```

**Expected output:**
```
CONTAINER ID   IMAGE            STATUS          PORTS                    NAMES
338ccdb55d11   security-tools   Up 2 minutes    0.0.0.0:8000->8000/tcp   security-server
```

**Test the API:**
```bash
curl http://localhost:8000/mcp/v1/tools
```

**Expected output:**
```json
{"tools":["nmap_scan","http_headers_check","whois_lookup","dns_lookup"]}
```

### Docker Management Commands

| Command | Purpose |
|---------|---------|
| `docker ps` | List running containers |
| `docker logs security-server` | View container logs |
| `docker stop security-server` | Stop the container |
| `docker start security-server` | Start stopped container |
| `docker restart security-server` | Restart container |
| `docker rm security-server` | Remove container |

---

## 7. Testing the Deployment

### Test 1: List Available Tools

**On EC2:**
```bash
curl http://localhost:8000/mcp/v1/tools
```

**Expected:**
```json
{"tools":["nmap_scan","http_headers_check","whois_lookup","dns_lookup"]}
```

### Test 2: HTTP Headers Check

**On EC2:**
```bash
curl -X POST http://localhost:8000/mcp/v1/tools/http_headers_check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com"}'
```

**Expected output:**
```json
{
  "result": "Security Headers for https://google.com\n==================================================\n[MISSING] Strict-Transport-Security (HSTS - Forces HTTPS)\n[MISSING] Content-Security-Policy (CSP - Prevents XSS)\n[FOUND] X-Frame-Options: SAMEORIGIN\n[MISSING] X-Content-Type-Options (MIME sniffing protection)\n[MISSING] Referrer-Policy (Controls referrer leakage)\n[MISSING] Permissions-Policy (Browser feature control)"
}
```

### Test 3: DNS Lookup

**On EC2:**
```bash
curl -X POST http://localhost:8000/mcp/v1/tools/dns_lookup \
  -H "Content-Type: application/json" \
  -d '{"domain":"microsoft.com","record_type":"MX"}'
```

**Expected output:**
```json
{
  "result": "Server:\t\t172.31.0.2\nAddress:\t172.31.0.2#53\n\nNon-authoritative answer:\nmicrosoft.com\tmail exchanger = 10 microsoft-com.mail.protection.outlook.com.\n"
}
```

### Test 4: Nmap Scan

**On EC2:**
```bash
curl -X POST http://localhost:8000/mcp/v1/tools/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","scan_type":"quick"}'
```

**Expected output:**
```json
{
  "result": "Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 11:52 UTC\nNmap scan report for scanme.nmap.org (45.33.32.156)\nHost is up (0.066s latency).\nNot shown: 98 closed tcp ports (reset)\nPORT   STATE SERVICE    VERSION\n22/tcp open  tcpwrapped\n80/tcp open  http       Apache httpd 2.4.7 ((Ubuntu))\n\nNmap done: 1 IP address (1 host up) scanned in 7.66 seconds\n"
}
```

### Test 5: WHOIS Lookup

**On EC2:**
```bash
curl -X POST http://localhost:8000/mcp/v1/tools/whois_lookup \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com"}'
```

---

## 8. Using from Local Machine

### Get Your EC2 Public IP

**On EC2:**
```bash
curl ifconfig.me
```

This returns your public IP (e.g., `3.92.45.123`)

### Test from Windows PowerShell

**List tools:**
```powershell
Invoke-RestMethod -Uri "http://YOUR_EC2_IP:8000/mcp/v1/tools" -Method GET
```

**Check headers:**
```powershell
Invoke-RestMethod -Uri "http://YOUR_EC2_IP:8000/mcp/v1/tools/http_headers_check" `
  -Method POST `
  -Body '{"url":"https://amazon.com"}' `
  -ContentType "application/json"
```

**Run nmap scan:**
```powershell
Invoke-RestMethod -Uri "http://YOUR_EC2_IP:8000/mcp/v1/tools/nmap_scan" `
  -Method POST `
  -Body '{"target":"scanme.nmap.org","scan_type":"quick"}' `
  -ContentType "application/json"
```

### Test from Mac/Linux

**List tools:**
```bash
curl http://YOUR_EC2_IP:8000/mcp/v1/tools
```

**Check headers:**
```bash
curl -X POST http://YOUR_EC2_IP:8000/mcp/v1/tools/http_headers_check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://amazon.com"}'
```

---

## 9. Claude API Integration

### Overview

The `client.py` script connects Claude's intelligence with your EC2 tools, enabling natural language security assessments.

### Prerequisites

1. **Anthropic API Key**
   - Sign up at [console.anthropic.com](https://console.anthropic.com)
   - Go to API Keys → Create Key
   - Add credits under Plans & Billing

2. **Python environment with dependencies**
   ```bash
   pip install anthropic httpx
   ```

### Setup on Your Local Machine

**Step 1: Clone the repository (if not already done)**
```bash
git clone https://github.com/ModusCreate-NFR/mcp-security-tool.git
cd mcp-security-tool
```

**Step 2: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 3: Set environment variables**

**Windows PowerShell:**
```powershell
$env:MCP_SERVER_URL = "http://YOUR_EC2_IP:8000"
$env:ANTHROPIC_API_KEY = "sk-ant-your-key-here"
```

**Mac/Linux:**
```bash
export MCP_SERVER_URL="http://YOUR_EC2_IP:8000"
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

**Step 4: Run the client**
```bash
python client.py
```

### Example Session

```
============================================================
  Security Tools Chat
  Server: http://3.92.45.123:8000
============================================================

Tools: nmap_scan, http_headers_check, whois_lookup, dns_lookup
Type 'quit' to exit.

You: Scan scanme.nmap.org and tell me what services are running

  [Using nmap_scan...]

Claude: I scanned scanme.nmap.org and found the following:

**Open Ports:**
- **Port 22 (SSH)** - The SSH service is running, likely OpenSSH
- **Port 80 (HTTP)** - Apache httpd 2.4.7 is running on Ubuntu

**Security Observations:**
1. SSH on port 22 could be targeted for brute force attacks. Consider:
   - Using key-based authentication only
   - Implementing fail2ban
   - Moving SSH to a non-standard port

2. The Apache version (2.4.7) is quite old and may have known vulnerabilities.
   Recommend updating to the latest stable version.

Would you like me to check the HTTP headers for security configuration?

You: Yes, check the security headers

  [Using http_headers_check...]

Claude: Here's the security header analysis for http://scanme.nmap.org:

**Missing Headers (Critical):**
- ❌ Strict-Transport-Security - No HSTS, vulnerable to downgrade attacks
- ❌ Content-Security-Policy - No XSS protection
- ❌ X-Content-Type-Options - Vulnerable to MIME sniffing

**Recommendations:**
1. Implement HSTS with: `Strict-Transport-Security: max-age=31536000`
2. Add CSP header to prevent XSS attacks
3. Add `X-Content-Type-Options: nosniff`

You: quit
Goodbye!
```

---

## 10. Team Usage Guide

### For Team Members

Each team member needs:

1. **The client.py script** (from your GitHub repo)
2. **Their own Anthropic API key** (each person gets one)
3. **Your EC2 server URL**

### Quick Start for Team Members

```bash
# 1. Clone the repo
git clone https://github.com/ModusCreate-NFR/mcp-security-tool.git
cd mcp-security-tool

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set environment variables
export MCP_SERVER_URL="http://SHARED_EC2_IP:8000"
export ANTHROPIC_API_KEY="their-own-api-key"

# 4. Run
python client.py
```

### Team Architecture

```
┌─────────────────────┐     ┌─────────────────────┐
│  Team Member A      │     │  Team Member B      │
│  (Windows)          │     │  (Mac)              │
│  API Key: sk-ant-A  │     │  API Key: sk-ant-B  │
└──────────┬──────────┘     └──────────┬──────────┘
           │                           │
           │    ┌─────────────────┐    │
           └───▶│   Claude API    │◀───┘
                │   (Anthropic)   │
                └────────┬────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   YOUR EC2 SERVER   │
              │   (Shared by team)  │
              │                     │
              │   security-tools    │
              │   docker container  │
              └─────────────────────┘
```

### Cost Distribution

| Component | Who Pays | Approximate Cost |
|-----------|----------|------------------|
| EC2 Server | Your team/company | ~$8-15/month (t3.small) or free (t2.micro) |
| Claude API | Each team member | ~$0.003 per 1K input tokens, ~$0.015 per 1K output tokens |

---

## 11. Security Considerations

### Current State: Open Access

Right now, anyone who knows your EC2 IP can call the tools:

```bash
# Anyone can do this!
curl -X POST http://YOUR_EC2_IP:8000/mcp/v1/tools/nmap_scan \
  -d '{"target":"any-site.com"}'
```

### Recommended Security Measures

#### Option 1: IP Whitelist (Simple)

Restrict EC2 Security Group to only allow your team's IPs:
1. AWS Console → EC2 → Security Groups
2. Edit inbound rules for port 8000
3. Change source from "0.0.0.0/0" to specific IPs

#### Option 2: API Key Authentication (Better)

Add API key validation to server.py:

```python
API_KEY = os.environ.get("TOOLS_API_KEY", "your-secret-key")

async def verify_api_key(request):
    auth_header = request.headers.get("Authorization")
    if auth_header != f"Bearer {API_KEY}":
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return None
```

#### Option 3: VPN (Most Secure)

- Set up AWS VPN or WireGuard
- Only allow connections from VPN
- Team members connect to VPN before using tools

### Legal Reminder

**Only scan targets you have explicit permission to test.**

Using these tools against unauthorized targets is illegal and unethical.

---

## 12. Troubleshooting

### Problem: Can't connect to EC2 from local machine

**Symptom:** Connection timeout or refused

**Solutions:**
1. Check EC2 Security Group allows port 8000
2. Verify EC2 public IP is correct: `curl ifconfig.me` on EC2
3. Ensure Docker container is running: `docker ps`
4. Check if server started correctly: `docker logs security-server`

### Problem: Docker container won't start

**Symptom:** Container exits immediately

**Solutions:**
```bash
# Check logs
docker logs security-server

# Try running interactively to see errors
docker run -it -p 8000:8000 security-tools

# Rebuild if needed
docker build -t security-tools .
```

### Problem: nmap scan fails

**Symptom:** Error or empty results

**Solutions:**
1. Target might be blocking scans
2. Try scanme.nmap.org (designed for testing)
3. Check Docker has network access: `docker exec security-server ping google.com`

### Problem: Claude API errors

**Symptom:** 400 or 401 errors from Anthropic

**Solutions:**
1. Check API key is correct
2. Verify you have API credits: [console.anthropic.com](https://console.anthropic.com)
3. Check environment variable is set: `echo $ANTHROPIC_API_KEY`

### Problem: Port 8000 already in use

**Symptom:** "Address already in use" error

**Solutions:**
```bash
# Find what's using the port
sudo lsof -i :8000

# Stop existing container
docker stop security-server
docker rm security-server

# Restart
docker run -d -p 8000:8000 --name security-server security-tools
```

---

## 13. Cost Estimates

### AWS EC2

| Instance Type | Monthly Cost | Notes |
|---------------|--------------|-------|
| t2.micro | ~$0 (free tier) | 750 hrs/month free for 12 months |
| t3.micro | ~$7.59/month | Better performance |
| t3.small | ~$15.18/month | Recommended for teams |

**Additional costs:**
- Data transfer: ~$0.09/GB outbound (first 100GB/month may be free)

### Anthropic Claude API

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|-------|----------------------|------------------------|
| Claude Sonnet | ~$3 | ~$15 |

**Typical usage:**
- Simple query + tool use: ~1,000 tokens
- Cost per query: ~$0.0015 - $0.02

### Total Estimated Monthly Cost

| Scenario | EC2 | Claude API | Total |
|----------|-----|------------|-------|
| Light use (free tier) | $0 | ~$5 | ~$5 |
| Team of 5, moderate use | $15 | ~$25 | ~$40 |
| Heavy production use | $50+ | ~$100+ | $150+ |

---

## Summary

### What We Achieved

1. **Bypassed Claude Desktop's network restrictions** by deploying our own server
2. **Created a portable, containerized solution** with Docker
3. **Enabled natural language security assessments** via Claude API
4. **Built a foundation for team collaboration** where each member can use the tools

### Key Files

| File | Purpose | Location |
|------|---------|----------|
| `server.py` | Security tools API | EC2 |
| `client.py` | Chat interface | User's machine |
| `Dockerfile` | Container definition | Repository |

### Quick Reference Commands

**EC2 (start server):**
```bash
docker run -d -p 8000:8000 --name security-server security-tools
```

**Local (start client):**
```bash
export MCP_SERVER_URL="http://EC2_IP:8000"
export ANTHROPIC_API_KEY="your-key"
python client.py
```

**Test API:**
```bash
curl http://EC2_IP:8000/mcp/v1/tools
```

---

## Document History

| Date | Version | Changes |
|------|---------|---------|
| Feb 11, 2026 | 1.0 | Initial documentation |

---
 
**Last Updated:** February 17, 2026
