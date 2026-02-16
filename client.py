"""
Security Tools Client - Anthropic API Edition
Chat with Claude using your security tools via MCP.

Usage:
    python client.py                     # Interactive mode
    python client.py "scan example.com"  # Single query

Environment Variables:
    ANTHROPIC_API_KEY: Your Anthropic API key
    MCP_SERVER_URL: URL of your security tools server (default: http://localhost:8000)
"""
import anthropic
import httpx
import sys
import os
import json

# Configuration
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
MODEL = "claude-sonnet-4-20250514"

# Tool definitions for Claude
TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Scan a target for open ports and services using nmap. Use for port scanning, service detection, and network reconnaissance.",
        "input_schema": {
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
    },
    {
        "name": "http_headers_check",
        "description": "Analyze HTTP security headers for a website. Checks for HSTS, CSP, X-Frame-Options, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL to check (e.g., 'https://example.com')"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "whois_lookup",
        "description": "Get WHOIS registration information for a domain including registrar, dates, and contact info.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to lookup (e.g., 'example.com')"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "dns_lookup",
        "description": "Query DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA).",
        "input_schema": {
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
    },
    {
        "name": "crtsh_lookup",
        "description": "Discover subdomains from SSL certificate transparency logs (crt.sh).",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Root domain to analyze (e.g., 'example.com')"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "nuclei_scan",
        "description": "Run Nuclei vulnerability scanner with YAML templates. Detects CVEs, XSS, SQLi, misconfigs.",
        "input_schema": {
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
    },
    {
        "name": "sqlmap_scan",
        "description": "SQL injection detection using sqlmap. Tests URL parameters for SQLi vulnerabilities.",
        "input_schema": {
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
    },
    {
        "name": "sslscan_check",
        "description": "Analyze SSL/TLS configuration. Checks for weak ciphers, protocols, and vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host (e.g., 'example.com' or 'example.com:443')"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "masscan_scan",
        "description": "Fast port scanning with masscan. Good for large IP ranges.",
        "input_schema": {
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
    },
    {
        "name": "amass_enum",
        "description": "Advanced subdomain enumeration using OWASP Amass.",
        "input_schema": {
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
    },
    {
        "name": "assetfinder_enum",
        "description": "Fast subdomain discovery using assetfinder.",
        "input_schema": {
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
    },
    {
        "name": "waybackurls_fetch",
        "description": "Fetch historical URLs from the Wayback Machine.",
        "input_schema": {
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
    },
    {
        "name": "katana_crawl",
        "description": "Web crawling for endpoint discovery using Katana.",
        "input_schema": {
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
    },
    {
        "name": "ffuf_fuzz",
        "description": "Web fuzzing for directory/file discovery using ffuf.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL with FUZZ keyword (e.g., 'https://example.com/FUZZ')"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist path (default: /usr/share/wordlists/dirb/common.txt)"
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions (e.g., 'php,html,js')"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "httpx_probe",
        "description": "HTTP probing for service detection using httpx.",
        "input_schema": {
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
                    "description": "Ports to check (default: 80, 443, 8080, 8443)"
                }
            },
            "required": ["targets"]
        }
    }
]


def call_mcp_tool(tool_name: str, arguments: dict) -> str:
    """Call a tool on the MCP server."""
    try:
        with httpx.Client(timeout=300.0) as client:
            response = client.post(
                f"{MCP_SERVER_URL}/mcp/v1/tools/{tool_name}",
                json=arguments
            )
            if response.status_code == 200:
                return response.json().get("result", response.text)
            else:
                return f"Error: {response.status_code} - {response.text}"
    except httpx.TimeoutException:
        return "Error: Tool execution timed out. The scan may still be running on the server."
    except Exception as e:
        return f"Error calling tool: {e}"


def chat(user_message: str, conversation: list = None) -> tuple[str, list]:
    """Send a message to Claude with tools available."""
    client = anthropic.Anthropic()
    
    if conversation is None:
        conversation = []
    
    conversation.append({"role": "user", "content": user_message})
    
    # Initial request with tools
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        tools=TOOLS,
        messages=conversation
    )
    
    # Handle tool use loop
    while response.stop_reason == "tool_use":
        # Find tool use blocks
        tool_results = []
        assistant_content = response.content
        
        for block in response.content:
            if block.type == "tool_use":
                tool_name = block.name
                tool_input = block.input
                tool_id = block.id
                
                print(f"\n  [Using {tool_name}...]", flush=True)
                
                # Call the tool
                result = call_mcp_tool(tool_name, tool_input)
                
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": result
                })
        
        # Add assistant message and tool results
        conversation.append({"role": "assistant", "content": assistant_content})
        conversation.append({"role": "user", "content": tool_results})
        
        # Continue conversation
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            tools=TOOLS,
            messages=conversation
        )
    
    # Extract final text response
    assistant_content = response.content
    conversation.append({"role": "assistant", "content": assistant_content})
    
    text_parts = []
    for block in response.content:
        if hasattr(block, 'text'):
            text_parts.append(block.text)
    
    return "\n".join(text_parts), conversation


def interactive_mode():
    """Run an interactive chat session."""
    print("\n" + "=" * 60)
    print("  Security Tools Assessment Platform")
    print("  Powered by Anthropic Claude API")
    print("=" * 60)
    print(f"\n  Server: {MCP_SERVER_URL}")
    print(f"  Model:  {MODEL}")
    print("\n  Available Tools:")
    print("    - Network: nmap, masscan, httpx")
    print("    - DNS: dns_lookup, whois, crtsh")
    print("    - Web: headers, ffuf, katana, waybackurls")
    print("    - Vuln: nuclei, sqlmap, sslscan")
    print("    - Recon: amass, assetfinder")
    print("\n  Type 'quit' to exit, 'clear' to reset conversation")
    print("=" * 60 + "\n")
    
    conversation = []
    
    while True:
        try:
            user_input = input("Security Specialist: ").strip()
            if not user_input:
                continue
            if user_input.lower() in ('quit', 'exit', 'q'):
                print("Goodbye!")
                break
            if user_input.lower() == 'clear':
                conversation = []
                print("Conversation cleared.\n")
                continue
            
            response, conversation = chat(user_input, conversation)
            print(f"\nClaude: {response}\n")
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except anthropic.APIError as e:
            print(f"\nAPI Error: {e}")
        except Exception as e:
            print(f"\nError: {e}")


def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not set")
        print('Set with: $env:ANTHROPIC_API_KEY = "your-key"')
        sys.exit(1)
    
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print(f"Security Specialist: {query}\n")
        response, _ = chat(query)
        print(f"Claude: {response}")
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
