"""
MCP Security Assessment Tool v2 - Powered by Modus Create
Professional black-box security assessment tool with session management.

Usage:
    python client_bedrock_v2.py                     # Interactive mode
    python client_bedrock_v2.py "scan example.com"  # Single query

Commands:
    start <name>  - Start named session (e.g., "start ACME Corp Pentest")
    status        - Show current session status
    save          - Save session to disk
    load <name>   - Load previous session
    report        - Generate markdown report
    clear         - Reset session
    help          - Show commands
    quit          - Exit

Environment Variables:
    MCP_SERVER_URL: URL of your security tools server (default: http://localhost:8000)
    AWS_REGION: AWS region for Bedrock (default: us-east-1)
"""
import boto3
import httpx
import sys
import os
import json
from datetime import datetime
from pathlib import Path
from botocore.config import Config

# Configuration
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-3-5-sonnet-20241022-v2:0")

# Directories
SESSIONS_DIR = Path("sessions")
REPORTS_DIR = Path("reports")
SESSIONS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


class Session:
    """Manages assessment session state."""
    
    def __init__(self, name: str = None):
        self.name = name
        self.created_at = datetime.now().isoformat()
        self.targets = set()
        self.scans = []
        self.conversation = []
        self.findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
    
    @property
    def display_name(self):
        if self.name:
            return self.name
        return f"unnamed_{self.created_at[:10]}"
    
    @property
    def filename(self):
        safe_name = self.display_name.replace(" ", "-").replace("/", "-")
        return f"{safe_name}_{self.created_at[:10]}.json"
    
    def add_scan(self, tool: str, arguments: dict, result: str, elapsed: float):
        """Record a scan result."""
        # Track targets
        for key in ["target", "domain", "url", "targets"]:
            if key in arguments:
                val = arguments[key]
                if isinstance(val, list):
                    self.targets.update(val)
                else:
                    self.targets.add(str(val))
        
        self.scans.append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool,
            "arguments": arguments,
            "result": result,
            "elapsed": elapsed
        })
    
    def status(self) -> str:
        """Return session status summary."""
        duration = sum(s["elapsed"] for s in self.scans)
        return f"""
  Session:  {self.display_name}
  Created:  {self.created_at[:19]}
  Targets:  {len(self.targets)} ({', '.join(list(self.targets)[:3])}{'...' if len(self.targets) > 3 else ''})
  Scans:    {len(self.scans)}
  Duration: {duration:.1f}s
"""
    
    def save(self) -> str:
        """Save session to disk."""
        filepath = SESSIONS_DIR / self.filename
        data = {
            "name": self.name,
            "created_at": self.created_at,
            "targets": list(self.targets),
            "scans": self.scans,
            "findings": self.findings
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return str(filepath)
    
    @classmethod
    def load(cls, name: str) -> "Session":
        """Load session from disk."""
        # Try exact filename or search
        filepath = SESSIONS_DIR / name
        if not filepath.exists():
            # Search by partial name
            matches = list(SESSIONS_DIR.glob(f"*{name}*.json"))
            if matches:
                filepath = matches[0]
            else:
                raise FileNotFoundError(f"Session not found: {name}")
        
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        session = cls(data.get("name"))
        session.created_at = data.get("created_at", datetime.now().isoformat())
        session.targets = set(data.get("targets", []))
        session.scans = data.get("scans", [])
        session.findings = data.get("findings", session.findings)
        return session
    
    @staticmethod
    def list_sessions() -> list:
        """List saved sessions."""
        return [f.stem for f in SESSIONS_DIR.glob("*.json")]


# Global session
current_session = Session()


# Tool definitions for Claude (Bedrock format) - keeping essential ones
TOOLS = [
    {
        "toolSpec": {
            "name": "nmap_scan",
            "description": "Port scan with nmap. Use for: open ports, service versions, OS detection.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP or hostname"},
                        "scan_type": {"type": "string", "enum": ["quick", "full", "stealth", "udp", "comprehensive"]},
                        "ports": {"type": "string", "description": "Ports to scan (e.g., '22,80,443' or '1-100')"}
                    },
                    "required": ["target"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "masscan_scan",
            "description": "Fast port scan for large IP ranges. NOTE: Requires IP address, not hostname.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP or CIDR (NOT hostname - resolve first with dns_lookup)"},
                        "ports": {"type": "string", "description": "Ports (e.g., '80,443' or '1-1000')"},
                        "rate": {"type": "integer", "description": "Packets/sec (default 1000)"}
                    },
                    "required": ["target", "ports"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "httpx_probe",
            "description": "Probe HTTP services. Returns status codes, titles, tech stack.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string"}, "description": "List of domains/URLs"}
                    },
                    "required": ["targets"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "dns_lookup",
            "description": "DNS records lookup. Use to resolve hostnames to IPs before masscan.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"},
                        "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"]}
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "whois_lookup",
            "description": "WHOIS registration info - registrar, dates, contacts.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"}
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "crtsh_lookup",
            "description": "Find subdomains from SSL certificate transparency logs.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"}
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "http_headers_check",
            "description": "Analyze security headers (HSTS, CSP, X-Frame-Options, etc).",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Full URL with https://"}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "nuclei_scan",
            "description": "Vulnerability scanner - CVEs, XSS, SQLi, misconfigs.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}, "description": "cve, xss, sqli, lfi, rce"},
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]}
                    },
                    "required": ["target"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "sqlmap_scan",
            "description": "SQL injection testing on URL parameters.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL with parameters (e.g., page?id=1)"},
                        "level": {"type": "integer", "description": "1-5 (higher=thorough)"},
                        "risk": {"type": "integer", "description": "1-3 (higher=intrusive)"}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "sslscan_check",
            "description": "SSL/TLS configuration analysis - ciphers, protocols, vulns.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"}
                    },
                    "required": ["target"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "amass_enum",
            "description": "Subdomain enumeration with OWASP Amass.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"},
                        "mode": {"type": "string", "enum": ["passive", "active"]}
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "assetfinder_enum",
            "description": "Fast subdomain discovery.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"}
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "ffuf_fuzz",
            "description": "Directory/file brute-forcing.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL with FUZZ keyword"},
                        "wordlist": {"type": "string"},
                        "extensions": {"type": "string", "description": "e.g., php,html,js"}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "katana_crawl",
            "description": "Web crawler - discover endpoints and URLs.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string"}},
                        "depth": {"type": "integer", "description": "Crawl depth 1-10"}
                    },
                    "required": ["targets"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "waybackurls_fetch",
            "description": "Historical URLs from Wayback Machine.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"}
                    },
                    "required": ["domain"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "wpscan_scan",
            "description": "WordPress vulnerability scanner.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "enumerate": {"type": "array", "items": {"type": "string"}, "description": "vp, ap, u"}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "commix_scan",
            "description": "OS command injection testing.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "level": {"type": "integer", "description": "1-3"}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "arjun_scan",
            "description": "Discover hidden HTTP parameters.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET", "POST", "JSON"]}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "gowitness_screenshot",
            "description": "Screenshot web pages.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"}
                    },
                    "required": ["url"]
                }
            }
        }
    },
    {
        "toolSpec": {
            "name": "smuggler_scan",
            "description": "HTTP request smuggling detection.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"}
                    },
                    "required": ["url"]
                }
            }
        }
    }
]


def call_mcp_tool(tool_name: str, arguments: dict) -> str:
    """Call a tool on the MCP server."""
    global current_session
    
    print(f"\n{'─' * 60}")
    print(f"  TOOL: {tool_name}")
    print(f"  ARGS: {json.dumps(arguments, indent=2)}")
    print(f"{'─' * 60}")
    print("  Running...", end="", flush=True)
    
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
                print(f"\r  Done ({elapsed:.1f}s)")
                
                # Show output (truncated for display)
                output_lines = result.split('\n')
                if len(output_lines) > 30:
                    print(f"\n  OUTPUT ({len(output_lines)} lines, showing first 30):")
                    print("  " + "\n  ".join(output_lines[:30]))
                    print(f"  ... ({len(output_lines) - 30} more lines)")
                else:
                    print(f"\n  OUTPUT:")
                    print("  " + "\n  ".join(output_lines))
                print(f"{'─' * 60}")
                
                # Log to session
                current_session.add_scan(tool_name, arguments, result, elapsed)
                
                return result
            else:
                print(f"\r  Failed ({response.status_code})")
                return f"Error: {response.status_code} - {response.text}"
    except httpx.TimeoutException:
        print(f"\r  Timeout (300s)")
        return "Error: Tool execution timed out."
    except Exception as e:
        print(f"\r  Error: {e}")
        return f"Error: {e}"


def get_bedrock_client():
    """Create a Bedrock Runtime client."""
    config = Config(
        region_name=AWS_REGION,
        retries={'max_attempts': 3, 'mode': 'adaptive'}
    )
    return boto3.client('bedrock-runtime', config=config)


# System prompt - context-aware
SYSTEM_PROMPT = """You are Claude, a Security Specialist conducting authorized penetration testing.

## EXECUTION RULES

**PRECISE MODE** (default):
When user gives a specific request like "scan ports 1-100" or "check headers":
- Execute EXACTLY what they ask
- Use ONE tool
- Do NOT chain additional tools
- Report results, then SUGGEST (don't execute) next steps

**COMPREHENSIVE MODE**:
When user says "full assessment", "comprehensive", "complete scan", or similar:
- Execute full methodology across all phases
- Chain tools intelligently
- Be thorough

## TOOL USAGE TIPS
- `masscan_scan` requires IP address. If given hostname, use `dns_lookup` first to resolve.
- For port scans: `nmap_scan` for single hosts, `masscan_scan` for IP ranges
- For web targets: always include protocol (https://)

## OUTPUT FORMAT
Keep it clean:

**[Tool Name] Results**
Target: [target]
```
[raw output - complete, never truncate]
```

**Findings:**
- [key findings as bullets]

**Risk:** [severity if applicable]

**Suggested Next Steps:** [what to run next - but ASK before running in precise mode]

## SEVERITY LEVELS
- CRITICAL: Immediate exploitation possible
- HIGH: Significant security impact
- MEDIUM: Requires conditions to exploit
- LOW: Minor security impact
- INFO: Informational only
"""


def chat(user_message: str, conversation: list = None) -> tuple[str, list]:
    """Send a message to Claude via Bedrock."""
    global current_session
    
    client = get_bedrock_client()
    
    if conversation is None:
        conversation = []
    
    conversation.append({
        "role": "user",
        "content": [{"text": user_message}]
    })
    
    system = [{"text": SYSTEM_PROMPT}]
    tool_config = {"tools": TOOLS}
    
    try:
        response = client.converse(
            modelId=BEDROCK_MODEL,
            system=system,
            messages=conversation,
            toolConfig=tool_config,
            inferenceConfig={"maxTokens": 8192, "temperature": 0.1}
        )
    except Exception as e:
        return f"Error: {e}", conversation
    
    # Handle tool use loop
    while response.get("stopReason") == "tool_use":
        assistant_message = response["output"]["message"]
        conversation.append(assistant_message)
        
        tool_results = []
        for block in assistant_message["content"]:
            if "toolUse" in block:
                tool_use = block["toolUse"]
                result = call_mcp_tool(tool_use["name"], tool_use["input"])
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tool_use["toolUseId"],
                        "content": [{"text": result}]
                    }
                })
        
        conversation.append({"role": "user", "content": tool_results})
        
        response = client.converse(
            modelId=BEDROCK_MODEL,
            system=system,
            messages=conversation,
            toolConfig=tool_config,
            inferenceConfig={"maxTokens": 8192, "temperature": 0.1}
        )
    
    # Extract final response
    final_message = response["output"]["message"]
    conversation.append(final_message)
    
    response_text = ""
    for block in final_message["content"]:
        if "text" in block:
            response_text += block["text"]
    
    current_session.conversation = conversation
    return response_text, conversation


def generate_report() -> str:
    """Generate assessment report."""
    global current_session
    
    if not current_session.scans:
        print("\n  No scans to report.\n")
        return None
    
    # Prompt for name if unnamed
    if not current_session.name:
        print("\n  Session has no name.")
        name = input("  Enter session name (or press Enter for default): ").strip()
        if name:
            current_session.name = name
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = current_session.display_name.replace(" ", "-")
    filename = REPORTS_DIR / f"{safe_name}_{timestamp}.md"
    
    # Group by target
    targets_data = {}
    for scan in current_session.scans:
        target = None
        for key in ["target", "domain", "url"]:
            if key in scan["arguments"]:
                target = scan["arguments"][key]
                break
        if not target:
            target = "General"
        
        if target not in targets_data:
            targets_data[target] = []
        targets_data[target].append(scan)
    
    report = f"""# Security Assessment Report: {current_session.display_name}

**Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Assessment Started:** {current_session.created_at[:19]}  
**Total Scans:** {len(current_session.scans)}  
**Targets:** {len(current_session.targets)}  
**Total Duration:** {sum(s['elapsed'] for s in current_session.scans):.1f}s

---

## Executive Summary

This report documents {len(current_session.scans)} security scans across {len(current_session.targets)} target(s).

### Targets Assessed
{chr(10).join(f'- {t}' for t in sorted(current_session.targets))}

---

## Findings by Target

"""

    for target, scans in targets_data.items():
        report += f"""### {target}

"""
        for scan in scans:
            report += f"""#### {scan['tool']}

**Time:** {scan['timestamp'][:19]}  
**Duration:** {scan['elapsed']:.1f}s  
**Parameters:** `{json.dumps(scan['arguments'])}`

<details>
<summary>Raw Output</summary>

```
{scan['result']}
```

</details>

---

"""

    report += """## Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | - | Immediate exploitation possible |
| High     | - | Significant security impact |
| Medium   | - | Requires conditions to exploit |
| Low      | - | Minor security impact |
| Info     | - | Informational findings |

*Review findings above and populate this table.*

---

## Recommendations

1. **Immediate:** Address critical and high severity findings
2. **Short-term:** Fix security header issues, close unnecessary ports
3. **Long-term:** Establish regular assessment schedule

---

*Generated by MODUS MCP Security Assessment Tool*
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    
    print(f"\n  ✓ Report saved: {filename}")
    print(f"  ✓ Scans: {len(current_session.scans)}")
    print(f"  ✓ Targets: {len(current_session.targets)}\n")
    
    return str(filename)


def print_banner():
    """Print welcome banner."""
    print("\n" + "=" * 60)
    print("  MODUS MCP Security Assessment Tool v2")
    print("  Powered by Modus Create")
    print("=" * 60)
    print(f"\n  Server: {MCP_SERVER_URL}")
    print(f"  Model:  {BEDROCK_MODEL.split('.')[-1][:30]}")
    print("\n  Commands:")
    print("    start <name>  - Name this session")
    print("    status        - Session summary")
    print("    save          - Save session")
    print("    load <name>   - Load session")
    print("    report        - Generate report")
    print("    clear         - Reset session")
    print("    help          - Show this help")
    print("    quit          - Exit")
    print("=" * 60 + "\n")


def print_help():
    """Print help."""
    print("""
  COMMANDS:
    start <name>   Start/name session (e.g., "start ACME Pentest")
    status         Show session status
    save           Save session to disk
    load <name>    Load saved session
    report         Generate markdown report
    clear          Clear session and start fresh
    help           Show this help
    quit           Exit

  SCAN EXAMPLES:
    "scan ports 22,80,443 on example.com"     - Precise, one tool
    "full assessment of example.com"          - Comprehensive, chains tools
    "check security headers for example.com"  - Precise, headers only
    "enumerate subdomains of example.com"     - Subdomain tools
""")


def main():
    """Main loop."""
    global current_session
    
    print_banner()
    
    # Single query mode
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print(f"Security Specialist: {query}\n")
        response, _ = chat(query)
        print(f"\n{'─' * 60}")
        print(f"Claude: {response}")
        print(f"{'─' * 60}\n")
        return
    
    conversation = None
    
    while True:
        try:
            user_input = input("Security Specialist: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nSession ended.")
            break
        
        if not user_input:
            continue
        
        cmd = user_input.lower().split()
        
        if cmd[0] == "quit":
            if current_session.scans:
                save = input("  Save session before exit? (y/N): ").strip().lower()
                if save == "y":
                    current_session.save()
                    print(f"  Saved: {current_session.filename}")
            print("Session ended.")
            break
        
        elif cmd[0] == "help":
            print_help()
            continue
        
        elif cmd[0] == "clear":
            current_session = Session()
            conversation = None
            print("\n  Session cleared.\n")
            continue
        
        elif cmd[0] == "status":
            print(current_session.status())
            continue
        
        elif cmd[0] == "start":
            name = " ".join(cmd[1:]) if len(cmd) > 1 else None
            if name:
                current_session.name = name
                print(f"\n  Session: {name}\n")
            else:
                name = input("  Session name: ").strip()
                if name:
                    current_session.name = name
                    print(f"\n  Session: {name}\n")
            continue
        
        elif cmd[0] == "save":
            filepath = current_session.save()
            print(f"\n  Saved: {filepath}\n")
            continue
        
        elif cmd[0] == "load":
            name = " ".join(cmd[1:]) if len(cmd) > 1 else None
            if not name:
                sessions = Session.list_sessions()
                if sessions:
                    print("\n  Available sessions:")
                    for s in sessions:
                        print(f"    - {s}")
                    name = input("  Load which session? ").strip()
                else:
                    print("\n  No saved sessions.\n")
                    continue
            try:
                current_session = Session.load(name)
                print(f"\n  Loaded: {current_session.display_name}")
                print(f"  Scans: {len(current_session.scans)}\n")
            except FileNotFoundError as e:
                print(f"\n  {e}\n")
            continue
        
        elif cmd[0] == "report":
            generate_report()
            continue
        
        # Regular chat
        response, conversation = chat(user_input, conversation)
        print(f"\n{'─' * 60}")
        print(f"Claude: {response}")
        print(f"{'─' * 60}\n")


if __name__ == "__main__":
    main()
