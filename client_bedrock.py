"""
MCP Security Assessment Tool - Powered by Modus Create
Professional black-box security assessment tool with AI-powered analysis.

Usage:
    python client_bedrock.py                     # Interactive mode
    python client_bedrock.py "scan example.com"  # Single query

Environment Variables:
    MCP_SERVER_URL: URL of your security tools server (default: http://localhost:8000)
    AWS_REGION: AWS region for Bedrock (default: us-east-1)
    BEDROCK_MODEL: Model ID - options:
        - anthropic.claude-3-5-sonnet-20241022-v2:0 (recommended - fast and intelligent)
        - anthropic.claude-3-5-haiku-20241022-v1:0 (fastest - simple operations)
        - us.anthropic.claude-3-opus-20240229-v1:0 (cross-region inference profile for Opus)
"""
import boto3
import httpx
import sys
import os
import json
from datetime import datetime
from botocore.config import Config

# Configuration
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
# Default to Sonnet (Opus requires inference profile on Bedrock)
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0")

# Session storage for report generation
SESSION_LOG = []
CURRENT_TARGET = None

# Tool definitions for Claude (Bedrock format)
TOOLS = [
    {
        "toolSpec": {
            "name": "nmap_scan",
            "description": "Scan a target for open ports and services using nmap. Use for port scanning, service detection, and network reconnaissance.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP or hostname to scan (e.g., '192.168.1.1', 'scanme.nmap.org')"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["quick", "full", "stealth", "udp", "comprehensive"],
                            "description": "Scan type: quick (top 100), full (all ports), stealth (SYN), udp, comprehensive"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Specific ports to scan (e.g., '22,80,443' or '1-1000')"
                        }
                    },
                    "required": ["target"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "http_headers_check",
            "description": "Analyze HTTP security headers for a website. Checks for HSTS, CSP, X-Frame-Options, etc.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Full URL to check (e.g., 'https://example.com')"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "whois_lookup",
            "description": "Get WHOIS registration information for a domain including registrar, dates, and contact info.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to lookup (e.g., 'example.com')"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "dns_lookup",
            "description": "Query DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA).",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to lookup"
                        },
                        "record_type": {
                            "type": "string",
                            "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"],
                            "description": "DNS record type"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "crtsh_lookup",
            "description": "Discover subdomains from SSL certificate transparency logs (crt.sh).",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Root domain to analyze (e.g., 'example.com')"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "nuclei_scan",
            "description": "Run Nuclei vulnerability scanner with YAML templates. Detects CVEs, XSS, SQLi, misconfigs.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to scan"
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by tags: cve, xss, sqli, lfi, rce, ssrf, exposure, misconfig"
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["info", "low", "medium", "high", "critical"],
                            "description": "Minimum severity to report"
                        }
                    },
                    "required": ["target"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "sqlmap_scan",
            "description": "SQL injection detection using sqlmap. Tests URL parameters for SQLi vulnerabilities.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL with parameters (e.g., 'https://example.com/page?id=1')"
                        },
                        "data": {
                            "type": "string",
                            "description": "POST data for testing POST requests"
                        },
                        "level": {
                            "type": "integer",
                            "description": "Test level 1-5 (higher = more thorough)"
                        },
                        "risk": {
                            "type": "integer",
                            "description": "Risk level 1-3 (higher = more intrusive)"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "sslscan_check",
            "description": "Analyze SSL/TLS configuration. Checks for weak ciphers, protocols, and vulnerabilities.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target host (e.g., 'example.com' or 'example.com:443')"
                        }
                    },
                    "required": ["target"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "masscan_scan",
            "description": "Fast port scanning with masscan. Good for large IP ranges.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP or CIDR range (e.g., '192.168.1.0/24')"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port range (e.g., '80,443' or '1-1000')"
                        },
                        "rate": {
                            "type": "integer",
                            "description": "Packets per second (default 1000)"
                        }
                    },
                    "required": ["target", "ports"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "amass_enum",
            "description": "Advanced subdomain enumeration using OWASP Amass.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["passive", "active"],
                            "description": "passive = safe, active = DNS resolution"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "assetfinder_enum",
            "description": "Fast subdomain discovery using assetfinder.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain"
                        },
                        "subs_only": {
                            "type": "boolean",
                            "description": "Return only subdomains (default true)"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "waybackurls_fetch",
            "description": "Fetch historical URLs from the Wayback Machine.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain"
                        },
                        "no_subs": {
                            "type": "boolean",
                            "description": "Exclude subdomains"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "katana_crawl",
            "description": "Web crawling for endpoint discovery using Katana.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "URLs to crawl"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Crawl depth (1-10)"
                        },
                        "js_crawl": {
                            "type": "boolean",
                            "description": "Parse JavaScript files"
                        }
                    },
                    "required": ["targets"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "ffuf_fuzz",
            "description": "Web fuzzing for directory/file discovery using ffuf.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL with FUZZ keyword (e.g., 'https://example.com/FUZZ')"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist path"
                        },
                        "extensions": {
                            "type": "string",
                            "description": "File extensions (e.g., 'php,html,js')"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "httpx_probe",
            "description": "HTTP probing for service detection using httpx.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Domains to probe"
                        },
                        "ports": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Ports to check"
                        }
                    },
                    "required": ["targets"]
                }
            }
        }
    },
    # === INJECTION TESTING ===
    {
        "toolSpec": {
            "name": "commix_scan",
            "description": "Test for OS command injection vulnerabilities using Commix.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL with parameters to test"
                        },
                        "data": {
                            "type": "string",
                            "description": "POST data for POST requests"
                        },
                        "cookie": {
                            "type": "string",
                            "description": "Cookie header value"
                        },
                        "level": {
                            "type": "integer",
                            "description": "Test level 1-3 (higher = more thorough)"
                        },
                        "technique": {
                            "type": "string",
                            "enum": ["classic", "eval-based", "time-based", "file-based"],
                            "description": "Specific injection technique"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "smuggler_scan",
            "description": "Test for HTTP Request Smuggling vulnerabilities.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL to test"
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST"],
                            "description": "HTTP method"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Request timeout in seconds"
                        },
                        "verbose": {
                            "type": "boolean",
                            "description": "Enable verbose output"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    # === WORDPRESS ===
    {
        "toolSpec": {
            "name": "wpscan_scan",
            "description": "Scan WordPress sites for vulnerabilities, plugins, themes, and users using WPScan.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target WordPress URL"
                        },
                        "enumerate": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "What to enumerate: vp (vulnerable plugins), ap (all plugins), vt (vulnerable themes), at (all themes), u (users), cb (config backups), dbe (db exports)"
                        },
                        "detection_mode": {
                            "type": "string",
                            "enum": ["mixed", "passive", "aggressive"],
                            "description": "Detection mode"
                        },
                        "api_token": {
                            "type": "string",
                            "description": "WPScan API token for vulnerability data"
                        },
                        "random_user_agent": {
                            "type": "boolean",
                            "description": "Use random user agents"
                        },
                        "force": {
                            "type": "boolean",
                            "description": "Force scan even if WordPress not detected"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    # === CLOUD SECURITY ===
    {
        "toolSpec": {
            "name": "scoutsuite_scan",
            "description": "Run Scout Suite for AWS/Azure/GCP cloud security auditing. Requires cloud credentials.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "provider": {
                            "type": "string",
                            "enum": ["aws", "azure", "gcp"],
                            "description": "Cloud provider to audit"
                        },
                        "profile": {
                            "type": "string",
                            "description": "AWS/Azure profile name"
                        },
                        "regions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific regions to audit"
                        },
                        "services": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific services to audit (e.g., ec2, s3, iam)"
                        },
                        "access_key": {
                            "type": "string",
                            "description": "AWS access key (if not using profile)"
                        },
                        "secret_key": {
                            "type": "string",
                            "description": "AWS secret key (if not using profile)"
                        }
                    },
                    "required": ["provider"]
                }
            }
        }
    },
    # === DISCOVERY TOOLS ===
    {
        "toolSpec": {
            "name": "alterx_generate",
            "description": "Generate subdomain wordlists using AlterX permutation patterns.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Base domain to permute"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Custom permutation pattern"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Input wordlist to permute"
                        },
                        "enrich": {
                            "type": "boolean",
                            "description": "Enrich with common patterns"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "arjun_scan",
            "description": "Discover hidden HTTP parameters using Arjun.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL to test"
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "JSON", "XML"],
                            "description": "HTTP method"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Custom parameter wordlist"
                        },
                        "threads": {
                            "type": "integer",
                            "description": "Number of concurrent threads"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Request timeout in seconds"
                        },
                        "stable": {
                            "type": "boolean",
                            "description": "Use stable mode (slower but reliable)"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "shuffledns_scan",
            "description": "Bruteforce subdomains using ShuffleDNS with massdns for speed.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Subdomain wordlist path"
                        },
                        "resolvers": {
                            "type": "string",
                            "description": "Custom DNS resolvers file"
                        },
                        "threads": {
                            "type": "integer",
                            "description": "Number of concurrent threads"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "gowitness_screenshot",
            "description": "Capture screenshots of web pages using Gowitness.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL to screenshot"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Page load timeout in seconds"
                        },
                        "fullpage": {
                            "type": "boolean",
                            "description": "Capture full page screenshot"
                        },
                        "screenshot_path": {
                            "type": "string",
                            "description": "Directory to save screenshots"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "cero_scan",
            "description": "Probe TLS certificates to discover domains from SSL certs.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of hosts/IPs to probe"
                        },
                        "concurrency": {
                            "type": "integer",
                            "description": "Number of concurrent connections"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Connection timeout in seconds"
                        },
                        "verbose": {
                            "type": "boolean",
                            "description": "Enable verbose output"
                        }
                    },
                    "required": ["targets"]
                }
            }
        }
    },
    # === MOBILE SECURITY ===
    {
        "toolSpec": {
            "name": "mobsf_scan",
            "description": "Scan mobile applications (APK/IPA) using MobSF. Requires MobSF server running.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to APK/IPA file to analyze"
                        },
                        "api_url": {
                            "type": "string",
                            "description": "MobSF API URL (default: http://localhost:8000)"
                        },
                        "api_key": {
                            "type": "string",
                            "description": "MobSF API key"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["apk", "ipa", "zip", "appx"],
                            "description": "Force scan type"
                        }
                    },
                    "required": ["file_path", "api_key"]
                }
            }
        }
    }
]


def call_mcp_tool(tool_name: str, arguments: dict, show_output: bool = True) -> str:
    """Call a tool on the MCP server with progress display."""
    global SESSION_LOG
    
    # Show what we're doing
    print(f"\n{'─' * 60}")
    print(f"  EXECUTING: {tool_name}")
    print(f"  TARGET: {json.dumps(arguments, indent=2)}")
    print(f"{'─' * 60}")
    print("  Status: Running...", end="", flush=True)
    
    start_time = datetime.now()
    
    try:
        with httpx.Client(timeout=300.0) as client:
            response = client.post(
                f"{MCP_SERVER_URL}/mcp/v1/tools/{tool_name}",
                json=arguments
            )
            elapsed = (datetime.now() - start_time).total_seconds()
            
            if response.status_code == 200:
                result = response.json().get("result", response.text)
                print(f"\r  Status: Completed in {elapsed:.1f}s")
                
                # Show raw output
                if show_output:
                    print(f"\n{'─' * 60}")
                    print("  RAW OUTPUT:")
                    print(f"{'─' * 60}")
                    print(result)
                    print(f"{'─' * 60}\n")
                
                # Log for report
                SESSION_LOG.append({
                    "timestamp": datetime.now().isoformat(),
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": result,
                    "elapsed": elapsed
                })
                
                return result
            else:
                print(f"\r  Status: Failed ({response.status_code})")
                return f"Error: {response.status_code} - {response.text}"
    except httpx.TimeoutException:
        print(f"\r  Status: Timeout after 300s")
        return "Error: Tool execution timed out. The scan may still be running on the server."
    except Exception as e:
        print(f"\r  Status: Error - {e}")
        return f"Error calling tool: {e}"


def get_bedrock_client():
    """Create a Bedrock Runtime client."""
    config = Config(
        region_name=AWS_REGION,
        retries={'max_attempts': 3, 'mode': 'adaptive'}
    )
    return boto3.client('bedrock-runtime', config=config)


def chat(user_message: str, conversation: list = None) -> tuple[str, list]:
    """Send a message to Claude via Bedrock with tools available."""
    client = get_bedrock_client()
    
    if conversation is None:
        conversation = []
    
    conversation.append({
        "role": "user",
        "content": [{"text": user_message}]
    })
    
    # System prompt for professional pentesting
    system = [{
        "text": """You are Claude, an elite Security Specialist and penetration tester conducting a black-box security assessment. You have access to industry-standard security tools and must use them systematically.

## YOUR ROLE
You are Claude, a Security Specialist performing authorized security assessments for clients. When given a target, you must conduct a THOROUGH assessment using multiple tools in the correct methodology order.

## ASSESSMENT METHODOLOGY
For comprehensive assessments, ALWAYS follow this order and use ALL relevant tools:

### Phase 1: Reconnaissance & OSINT
1. **whois_lookup** - Domain registration, ownership, dates
2. **dns_lookup** - A, MX, NS, TXT records (run multiple times for different record types)
3. **crtsh_lookup** - SSL certificate transparency for subdomain discovery
4. **cero_scan** - Extract domains from TLS certificates of target IPs

### Phase 2: Subdomain Enumeration  
5. **assetfinder_enum** - Fast subdomain discovery
6. **amass_enum** - Deep subdomain enumeration (passive mode first)
7. **alterx_generate** - Generate permutations for subdomain bruteforce
8. **shuffledns_scan** - Fast subdomain bruteforce with massdns

### Phase 3: Service Discovery
9. **httpx_probe** - Probe discovered subdomains for live hosts
10. **nmap_scan** - Port scan (start with quick, then targeted scans on interesting hosts)
11. **masscan_scan** - Fast port scan for large IP ranges
12. **gowitness_screenshot** - Visual recon by screenshotting discovered web services

### Phase 4: Web Application Analysis
13. **http_headers_check** - Security headers analysis
14. **katana_crawl** - Crawl for endpoints and URLs
15. **waybackurls_fetch** - Historical URLs from Wayback Machine
16. **ffuf_fuzz** - Directory and file brute-forcing
17. **arjun_scan** - Discover hidden HTTP parameters

### Phase 5: Vulnerability Assessment
18. **nuclei_scan** - Template-based vulnerability scanning (use different severity levels)
19. **sqlmap_scan** - SQL injection testing on discovered parameters
20. **sslscan_check** - SSL/TLS configuration analysis
21. **commix_scan** - OS command injection testing
22. **smuggler_scan** - HTTP request smuggling detection

### Phase 6: Specialized Assessments
23. **wpscan_scan** - WordPress vulnerability scanning (if WordPress detected)
24. **scoutsuite_scan** - Cloud security auditing (AWS/Azure/GCP when credentials available)
25. **mobsf_scan** - Mobile application analysis (APK/IPA files when provided)

## CRITICAL RULES
1. **ALWAYS SHOW RAW OUTPUT** - Include complete, unmodified tool output. Never truncate or summarize away data.
2. **CHAIN TOOLS INTELLIGENTLY** - Use output from one tool to inform the next (e.g., discovered subdomains → httpx probe → nmap specific IPs)
3. **BE THOROUGH** - For comprehensive requests, run ALL relevant tools. Don't stop after 2-3 scans.
4. **SHOW PROGRESS** - Explain what you're doing and why before each tool execution
5. **CORRELATE FINDINGS** - Connect findings across tools (e.g., "The open port 8080 found by nmap correlates with the admin panel discovered by ffuf")

## OUTPUT FORMAT
Structure ALL responses as:

```
================================================================================
PHASE: [Phase Name]
================================================================================

## [Tool Name] Results
**Target:** [exact target]
**Command/Parameters:** [what was run]

### Raw Output
[COMPLETE unmodified tool output - NEVER truncate]

### Findings
- [Bullet points of key findings]

### Risk Assessment  
| Finding | Severity | CVSS | Impact |
|---------|----------|------|--------|

### Next Steps
[What tools/scans should run next based on these findings]
```

## WHEN USER REQUESTS COMPREHENSIVE ASSESSMENT
If user asks for "full assessment", "comprehensive scan", "complete security assessment", or similar:
- Run ALL phases above systematically
- Use findings from each phase to inform the next
- Don't stop until all phases are complete
- Provide executive summary at the end

## SEVERITY RATINGS
- **CRITICAL**: Immediate exploitation possible, full system compromise
- **HIGH**: Significant security impact, exploitation likely  
- **MEDIUM**: Security weakness, exploitation requires conditions
- **LOW**: Minor issue, limited security impact
- **INFO**: Informational finding, no direct security impact

Remember: You are a professional pentester. Your output will be used in client reports. Be thorough, technical, and precise."""
    }]
    
    # Tool configuration for Bedrock
    tool_config = {"tools": TOOLS}
    
    try:
        response = client.converse(
            modelId=BEDROCK_MODEL,
            system=system,
            messages=conversation,
            toolConfig=tool_config,
            inferenceConfig={
                "maxTokens": 8192,
                "temperature": 0.1
            }
        )
    except Exception as e:
        error_msg = str(e)
        if "AccessDeniedException" in error_msg:
            return "Error: Access denied. Please enable model access in AWS Bedrock console.", conversation
        elif "ValidationException" in error_msg:
            return f"Error: Validation error - {error_msg}", conversation
        else:
            return f"Error calling Bedrock: {e}", conversation
    
    # Handle tool use loop
    while response.get("stopReason") == "tool_use":
        # Get assistant's response
        assistant_message = response["output"]["message"]
        conversation.append(assistant_message)
        
        # Process tool uses
        tool_results = []
        for block in assistant_message["content"]:
            if "toolUse" in block:
                tool_use = block["toolUse"]
                tool_name = tool_use["name"]
                tool_input = tool_use["input"]
                tool_id = tool_use["toolUseId"]
                
                print(f"\n  [Executing {tool_name}...]", flush=True)
                
                # Call the tool (output already displayed by call_mcp_tool)
                result = call_mcp_tool(tool_name, tool_input)
                
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tool_id,
                        "content": [{"text": result}]
                    }
                })
        
        # Add tool results to conversation
        conversation.append({
            "role": "user",
            "content": tool_results
        })
        
        # Continue conversation
        response = client.converse(
            modelId=BEDROCK_MODEL,
            system=system,
            messages=conversation,
            toolConfig=tool_config,
            inferenceConfig={
                "maxTokens": 8192,
                "temperature": 0.1
            }
        )
    
    # Extract final response text
    final_message = response["output"]["message"]
    conversation.append(final_message)
    
    response_text = ""
    for block in final_message["content"]:
        if "text" in block:
            response_text += block["text"]
    
    return response_text, conversation


def print_banner():
    """Print the welcome banner."""
    model_name = BEDROCK_MODEL.split("anthropic.")[-1].split("-v")[0] if "anthropic" in BEDROCK_MODEL else BEDROCK_MODEL
    
    print("\n" + "=" * 70)
    print("   __  __  ___  ____  _   _ ____    __  __  ____ ____  ")
    print("  |  \\/  |/ _ \\|  _ \\| | | / ___|  |  \\/  |/ ___|  _ \\ ")
    print("  | |\\/| | | | | | | | | | \\___ \\  | |\\/| | |   | |_) |")
    print("  | |  | | |_| | |_| | |_| |___) | | |  | | |___|  __/ ")
    print("  |_|  |_|\\___/|____/ \\___/|____/  |_|  |_|\\____|_|    ")
    print("")
    print("  MODUS MCP Security Assessment Tool")
    print("  Powered by Modus Create | Black-Box Penetration Testing")
    print("=" * 70)
    print(f"\n  Server:  {MCP_SERVER_URL}")
    print(f"  Model:   {model_name}")
    print(f"  Region:  {AWS_REGION}")
    print("\n  Assessment Phases:")
    print("    1. Recon:      whois, dns, crtsh")
    print("    2. Enum:       amass, assetfinder")
    print("    3. Discovery:  nmap, masscan, httpx")
    print("    4. Web:        headers, katana, waybackurls, ffuf")
    print("    5. Vuln:       nuclei, sqlmap, sslscan")
    print("\n  Commands:")
    print("    report   - Generate markdown assessment report")
    print("    clear    - Reset session")
    print("    quit     - Exit")
    print("\n  Example:")
    print("    ► Perform comprehensive security assessment of https://example.com")
    print("=" * 70 + "\n")


def generate_report():
    """Generate a professional markdown report from the session log."""
    global SESSION_LOG
    
    if not SESSION_LOG:
        print("\n  No scan data to report. Run some scans first.\n")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_assessment_{timestamp}.md"
    
    # Group scans by phase
    phases = {
        "Reconnaissance": ["whois_lookup", "dns_lookup", "crtsh_lookup"],
        "Subdomain Enumeration": ["assetfinder_enum", "amass_enum"],
        "Service Discovery": ["httpx_probe", "nmap_scan", "masscan_scan"],
        "Web Application Analysis": ["http_headers_check", "katana_crawl", "waybackurls_fetch", "ffuf_fuzz"],
        "Vulnerability Assessment": ["nuclei_scan", "sqlmap_scan", "sslscan_check"]
    }
    
    report = f"""# Black-Box Security Assessment Report

---

**Report ID:** SEC-{timestamp}
**Assessment Date:** {datetime.now().strftime("%Y-%m-%d")}
**Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Assessment Tool:** MCP Security Assessment Tool
**Scans Performed:** {len(SESSION_LOG)}

---

## 1. Executive Summary

This report documents the findings of an automated black-box security assessment. The assessment utilized {len(SESSION_LOG)} security scanning tools across multiple phases of testing.

### Assessment Scope
- Total scans executed: {len(SESSION_LOG)}
- Assessment duration: {sum(e['elapsed'] for e in SESSION_LOG):.1f} seconds

---

## 2. Methodology

The assessment followed industry-standard penetration testing methodology:
1. **Reconnaissance** - Gathering publicly available information
2. **Enumeration** - Discovering subdomains and assets
3. **Service Discovery** - Identifying running services and open ports
4. **Web Application Analysis** - Testing web application security
5. **Vulnerability Assessment** - Identifying security vulnerabilities

---

## 3. Technical Findings

"""
    
    # Organize findings by phase
    for phase_name, phase_tools in phases.items():
        phase_scans = [e for e in SESSION_LOG if e['tool'] in phase_tools]
        if phase_scans:
            report += f"""### 3.{list(phases.keys()).index(phase_name) + 1} {phase_name}

"""
            for entry in phase_scans:
                report += f"""#### {entry['tool']}

**Timestamp:** {entry['timestamp']}  
**Target:** `{json.dumps(entry['arguments'])}`  
**Execution Time:** {entry['elapsed']:.1f} seconds

<details>
<summary>Click to expand raw output</summary>

```
{entry['result']}
```

</details>

---

"""
    
    # Add any scans that don't fit into standard phases
    other_scans = [e for e in SESSION_LOG if e['tool'] not in sum(phases.values(), [])]
    if other_scans:
        report += """### 3.6 Additional Scans

"""
        for entry in other_scans:
            report += f"""#### {entry['tool']}

**Timestamp:** {entry['timestamp']}  
**Target:** `{json.dumps(entry['arguments'])}`  
**Execution Time:** {entry['elapsed']:.1f} seconds

```
{entry['result']}
```

---

"""

    report += """## 4. Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | - | Requires immediate attention |
| High | - | Should be addressed urgently |
| Medium | - | Should be addressed in near term |
| Low | - | Should be addressed when possible |
| Info | - | Informational findings |

*Note: Populate this table based on analysis of the findings above.*

---

## 5. Recommendations

Based on the findings in this assessment, the following recommendations are provided:

1. **Immediate Actions**
   - Review and address any critical or high severity findings
   
2. **Short-term Actions**  
   - Implement missing security headers
   - Review exposed services and close unnecessary ports
   
3. **Long-term Actions**
   - Establish regular security assessment schedule
   - Implement security monitoring and alerting

---

## 6. Disclaimer

This assessment was performed using automated security scanning tools. The findings represent point-in-time observations and should be validated manually before implementing remediation measures. False positives may be present and should be verified.

This report is intended for authorized recipients only and contains sensitive security information. Handle according to your organization's information classification policies.

---

*Report generated by MCP Security Assessment Tool*
*Assessment Server: {MCP_SERVER_URL}*
"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    
    print(f"\n  ✓ Report saved: {filename}")
    print(f"  ✓ Scans included: {len(SESSION_LOG)}")
    print(f"  ✓ Total scan time: {sum(e['elapsed'] for e in SESSION_LOG):.1f}s\n")
    return filename


def main():
    """Main chat loop."""
    print_banner()
    
    # Check for single query mode
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print(f"┌─ Query ─────────────────────────────────────────────────────┐")
        print(f"│ {query[:60]:<60} │")
        print(f"└─────────────────────────────────────────────────────────────┘")
        response, _ = chat(query)
        print(f"\n{'═' * 70}")
        print("ANALYSIS")
        print(f"{'═' * 70}")
        print(response)
        print(f"{'═' * 70}\n")
        return
    
    # Interactive mode
    conversation = None
    
    while True:
        try:
            user_input = input("\n► ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nAssessment session ended.")
            break
        
        if not user_input:
            continue
        
        if user_input.lower() == "quit":
            print("\nAssessment session ended.")
            break
        
        if user_input.lower() == "clear":
            conversation = None
            SESSION_LOG.clear()
            print("\n  Session cleared.\n")
            continue
        
        if user_input.lower() == "report":
            generate_report()
            continue
        
        response, conversation = chat(user_input, conversation)
        print(f"\n{'═' * 70}")
        print("ANALYSIS")
        print(f"{'═' * 70}")
        print(response)
        print(f"{'═' * 70}")


if __name__ == "__main__":
    main()
