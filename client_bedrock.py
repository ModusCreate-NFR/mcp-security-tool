"""
Security Tools Client - AWS Bedrock Edition
Chat with Claude on AWS Bedrock using your security tools.

Prerequisites:
    - AWS CLI configured with credentials
    - Bedrock model access enabled in your AWS region
    - pip install boto3 httpx

Usage:
    python client_bedrock.py                     # Interactive mode
    python client_bedrock.py "scan example.com"  # Single query

Environment Variables:
    MCP_SERVER_URL: URL of your security tools server (default: http://localhost:8000)
    AWS_REGION: AWS region for Bedrock (default: us-east-1)
    BEDROCK_MODEL: Model ID (default: anthropic.claude-3-sonnet-20240229-v1:0)
"""
import boto3
import httpx
import sys
import os
import json
from botocore.config import Config

# Configuration
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "anthropic.claude-3-sonnet-20240229-v1:0")

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
    
    # System prompt for security context
    system = [{
        "text": """You are an expert security analyst assistant. You have access to various security tools to help assess targets.

IMPORTANT GUIDELINES:
1. Only scan targets the user has explicit authorization to test
2. Start with non-intrusive scans before aggressive ones
3. Explain findings in clear, actionable terms
4. Recommend remediation for any issues found
5. Be thorough but efficient - combine related checks when possible

When presenting results:
- Summarize key findings first
- Highlight critical/high severity issues
- Provide specific remediation steps
- Note any limitations or areas needing further investigation"""
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
                "maxTokens": 4096,
                "temperature": 0.7
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
                
                print(f"\n  [Using {tool_name}...]", flush=True)
                
                # Call the tool
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
                "maxTokens": 4096,
                "temperature": 0.7
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
    print("\n" + "=" * 60)
    print("  Security Tools Assessment Platform")
    print("  Powered by AWS Bedrock + Claude")
    print("=" * 60)
    print(f"\n  Server: {MCP_SERVER_URL}")
    print(f"  Region: {AWS_REGION}")
    print(f"  Model:  {BEDROCK_MODEL}")
    print("\n  Available Tools:")
    print("    - Network: nmap, masscan, httpx")
    print("    - DNS: dns_lookup, whois, crtsh")
    print("    - Web: headers, ffuf, katana, waybackurls")
    print("    - Vuln: nuclei, sqlmap, sslscan")
    print("    - Recon: amass, assetfinder")
    print("\n  Type 'quit' to exit, 'clear' to reset conversation")
    print("=" * 60 + "\n")


def main():
    """Main chat loop."""
    print_banner()
    
    # Check for single query mode
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print(f"Security Specialist: {query}\n")
        response, _ = chat(query)
        print(f"\nClaude: {response}\n")
        return
    
    # Interactive mode
    conversation = None
    
    while True:
        try:
            user_input = input("Security Specialist: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
            break
        
        if not user_input:
            continue
        
        if user_input.lower() == "quit":
            print("Goodbye!")
            break
        
        if user_input.lower() == "clear":
            conversation = None
            print("Conversation cleared.\n")
            continue
        
        response, conversation = chat(user_input, conversation)
        print(f"\nClaude: {response}\n")


if __name__ == "__main__":
    main()
