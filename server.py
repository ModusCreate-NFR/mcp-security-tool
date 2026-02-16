"""
Security Tools MCP Server
Exposes security tools via HTTP/SSE for Claude API integration.

This server provides 15 security tools organized by category:
- Network: nmap, masscan, httpx
- DNS: dns_lookup, whois, crtsh
- Web: http_headers, ffuf, katana, waybackurls
- Vulnerability: nuclei, sqlmap, sslscan
- Recon: amass, assetfinder

Usage:
    python server.py

Endpoints:
    GET  /mcp/v1/tools              - List all available tools
    POST /mcp/v1/tools/{tool_name}  - Execute a tool
    GET  /sse                       - MCP SSE endpoint
"""
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
from typing import Optional, List

# Import all tools from the tools module
from tools import (
    # Network tools
    nmap_scan, masscan_scan, httpx_probe,
    # DNS tools
    dns_lookup, whois_lookup, crtsh_lookup,
    # Web tools
    http_headers_check, ffuf_fuzz, katana_crawl, waybackurls_fetch,
    # Vulnerability tools
    nuclei_scan, sqlmap_scan, sslscan_check,
    # Recon tools
    amass_enum, assetfinder_enum,
)

# Initialize FastMCP server
mcp = FastMCP(
    name="security-tools",
    instructions="""Security assessment tools for authorized penetration testing.

IMPORTANT: Only use these tools on targets you have explicit permission to test.

Available tool categories:
- Network scanning (nmap, masscan, httpx)
- DNS reconnaissance (dns_lookup, whois, crtsh)
- Web application testing (headers, ffuf, katana, waybackurls)
- Vulnerability scanning (nuclei, sqlmap, sslscan)
- Subdomain enumeration (amass, assetfinder)
"""
)


# =============================================================================
# NETWORK TOOLS
# =============================================================================

@mcp.tool()
def tool_nmap_scan(target: str, scan_type: str = "quick", ports: Optional[str] = None) -> str:
    """
    Scan a target for open ports and services using nmap.
    
    Args:
        target: IP or hostname to scan (e.g., "192.168.1.1", "scanme.nmap.org")
        scan_type: "quick" (top 100), "full" (all ports), "stealth" (SYN), "udp", "comprehensive"
        ports: Specific ports to scan (e.g., "22,80,443" or "1-1000")
    """
    return nmap_scan(target, scan_type, ports)


@mcp.tool()
def tool_masscan_scan(target: str, ports: str = "1-1000", rate: int = 1000) -> str:
    """
    Fast port scanning using masscan. Good for large IP ranges.
    
    Args:
        target: IP or CIDR range (e.g., "192.168.1.0/24")
        ports: Port range (e.g., "80,443" or "1-65535")
        rate: Packets per second (default 1000, max 10000)
    """
    return masscan_scan(target, ports, rate)


@mcp.tool()
def tool_httpx_probe(targets: List[str], ports: Optional[List[int]] = None, probes: Optional[List[str]] = None) -> str:
    """
    Probe HTTP/HTTPS services using httpx.
    
    Args:
        targets: List of domains to probe
        ports: Ports to check (default: 80, 443, 8080, 8443)
        probes: Probes to run (status-code, title, tech-detect, etc.)
    """
    return httpx_probe(targets, ports, probes)


# =============================================================================
# DNS TOOLS
# =============================================================================

@mcp.tool()
def tool_dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Query DNS records for a domain.
    
    Args:
        domain: Domain to lookup (e.g., "example.com")
        record_type: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, ANY
    """
    return dns_lookup(domain, record_type)


@mcp.tool()
def tool_whois_lookup(domain: str) -> str:
    """
    Get WHOIS registration information for a domain.
    
    Args:
        domain: Domain to lookup (e.g., "example.com")
    """
    return whois_lookup(domain)


@mcp.tool()
def tool_crtsh_lookup(domain: str, include_expired: bool = False) -> str:
    """
    Discover subdomains from SSL certificate transparency logs.
    
    Args:
        domain: Root domain to analyze (e.g., "example.com")
        include_expired: Include expired certificates
    """
    return crtsh_lookup(domain, include_expired)


# =============================================================================
# WEB TOOLS
# =============================================================================

@mcp.tool()
def tool_http_headers_check(url: str) -> str:
    """
    Analyze HTTP security headers for a website.
    
    Args:
        url: Full URL to check (e.g., "https://example.com")
    """
    return http_headers_check(url)


@mcp.tool()
def tool_ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    mode: str = "dir",
    extensions: Optional[str] = None
) -> str:
    """
    Web fuzzing for directory/file/parameter discovery.
    
    Args:
        url: URL with FUZZ keyword (e.g., "https://example.com/FUZZ")
        wordlist: Path to wordlist file
        mode: "dir" (directories), "file" (with extensions)
        extensions: File extensions (e.g., "php,html,js")
    """
    return ffuf_fuzz(url, wordlist, mode, extensions)


@mcp.tool()
def tool_katana_crawl(
    targets: List[str],
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False
) -> str:
    """
    Web crawling for endpoint and URL discovery.
    
    Args:
        targets: URLs to crawl
        depth: Maximum crawl depth (1-10)
        js_crawl: Parse JavaScript files for endpoints
        headless: Use headless browser
    """
    return katana_crawl(targets, depth, js_crawl, headless)


@mcp.tool()
def tool_waybackurls_fetch(domain: str, no_subs: bool = False) -> str:
    """
    Fetch historical URLs from the Wayback Machine.
    
    Args:
        domain: Target domain
        no_subs: Exclude subdomains
    """
    return waybackurls_fetch(domain, no_subs)


# =============================================================================
# VULNERABILITY TOOLS
# =============================================================================

@mcp.tool()
def tool_nuclei_scan(
    target: str,
    tags: Optional[List[str]] = None,
    severity: Optional[str] = None
) -> str:
    """
    Run Nuclei vulnerability scanner with YAML templates.
    
    Args:
        target: Target URL to scan
        tags: Filter by tags (cve, xss, sqli, lfi, rce, ssrf, exposure, misconfig)
        severity: Filter by severity (info, low, medium, high, critical)
    """
    return nuclei_scan(target, tags, severity)


@mcp.tool()
def tool_sqlmap_scan(
    url: str,
    data: Optional[str] = None,
    level: int = 1,
    risk: int = 1
) -> str:
    """
    SQL injection detection using sqlmap.
    
    Args:
        url: URL with parameters (e.g., "https://example.com/page?id=1")
        data: POST data for testing
        level: Test level 1-5 (higher = more thorough)
        risk: Risk level 1-3 (higher = more intrusive)
    """
    return sqlmap_scan(url, data, level, risk)


@mcp.tool()
def tool_sslscan_check(target: str, show_certificate: bool = True) -> str:
    """
    Analyze SSL/TLS configuration and identify weaknesses.
    
    Args:
        target: Host to scan (e.g., "example.com" or "example.com:443")
        show_certificate: Include certificate details
    """
    return sslscan_check(target, show_certificate)


# =============================================================================
# RECON TOOLS
# =============================================================================

@mcp.tool()
def tool_amass_enum(domain: str, mode: str = "passive", brute: bool = False) -> str:
    """
    Advanced subdomain enumeration using OWASP Amass.
    
    Args:
        domain: Target domain
        mode: "passive" (safe) or "active" (DNS resolution)
        brute: Enable brute force discovery
    """
    return amass_enum(domain, mode, brute)


@mcp.tool()
def tool_assetfinder_enum(domain: str, subs_only: bool = True) -> str:
    """
    Fast subdomain discovery using assetfinder.
    
    Args:
        domain: Target domain
        subs_only: Return only subdomains (default true)
    """
    return assetfinder_enum(domain, subs_only)


# =============================================================================
# REST API CONFIGURATION
# =============================================================================

# Map tool names to their implementations for REST API
TOOL_FUNCTIONS = {
    # Network
    "nmap_scan": nmap_scan,
    "masscan_scan": masscan_scan,
    "httpx_probe": httpx_probe,
    
    # DNS
    "dns_lookup": dns_lookup,
    "whois_lookup": whois_lookup,
    "crtsh_lookup": crtsh_lookup,
    
    # Web
    "http_headers_check": http_headers_check,
    "ffuf_fuzz": ffuf_fuzz,
    "katana_crawl": katana_crawl,
    "waybackurls_fetch": waybackurls_fetch,
    
    # Vulnerability
    "nuclei_scan": nuclei_scan,
    "sqlmap_scan": sqlmap_scan,
    "sslscan_check": sslscan_check,
    
    # Recon
    "amass_enum": amass_enum,
    "assetfinder_enum": assetfinder_enum,
}


async def call_tool(request):
    """REST endpoint to call a tool."""
    tool_name = request.path_params["tool_name"]
    
    if tool_name not in TOOL_FUNCTIONS:
        return JSONResponse(
            {"error": f"Unknown tool: {tool_name}", "available_tools": list(TOOL_FUNCTIONS.keys())},
            status_code=404
        )
    
    try:
        body = await request.json()
    except:
        body = {}
    
    try:
        result = TOOL_FUNCTIONS[tool_name](**body)
        return JSONResponse({"result": result})
    except TypeError as e:
        return JSONResponse({"error": f"Invalid parameters: {e}"}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def list_tools(request):
    """List available tools with descriptions."""
    tools_info = {
        "network": ["nmap_scan", "masscan_scan", "httpx_probe"],
        "dns": ["dns_lookup", "whois_lookup", "crtsh_lookup"],
        "web": ["http_headers_check", "ffuf_fuzz", "katana_crawl", "waybackurls_fetch"],
        "vulnerability": ["nuclei_scan", "sqlmap_scan", "sslscan_check"],
        "recon": ["amass_enum", "assetfinder_enum"],
    }
    return JSONResponse({
        "tools": list(TOOL_FUNCTIONS.keys()),
        "categories": tools_info,
        "total": len(TOOL_FUNCTIONS)
    })


async def health_check(request):
    """Health check endpoint."""
    return JSONResponse({"status": "healthy", "tools_available": len(TOOL_FUNCTIONS)})


# Create combined app with REST API and MCP SSE
mcp_app = mcp.http_app(path="/sse")

app = Starlette(
    routes=[
        Route("/health", health_check),
        Route("/mcp/v1/tools", list_tools),
        Route("/mcp/v1/tools/{tool_name}", call_tool, methods=["POST"]),
        Mount("/", app=mcp_app),
    ]
)


if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "=" * 60)
    print("  Security Tools MCP Server")
    print("=" * 60)
    print("\n  Endpoints:")
    print("    GET  /health              - Health check")
    print("    GET  /mcp/v1/tools        - List tools")
    print("    POST /mcp/v1/tools/{name} - Execute tool")
    print("    GET  /sse                 - MCP SSE endpoint")
    print("\n  Tools Available: 15")
    print("    Network:  nmap, masscan, httpx")
    print("    DNS:      dns_lookup, whois, crtsh")
    print("    Web:      headers, ffuf, katana, waybackurls")
    print("    Vuln:     nuclei, sqlmap, sslscan")
    print("    Recon:    amass, assetfinder")
    print("\n" + "=" * 60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
