"""
Security Tools MCP Server
Exposes security tools via HTTP/SSE for Claude API integration.

This server provides 25 security tools organized by category:
- Network: nmap, masscan, httpx
- DNS: dns_lookup, whois, crtsh, cero
- Web: http_headers, ffuf, katana, waybackurls, arjun
- Vulnerability: nuclei, sqlmap, sslscan, commix, smuggler
- Recon: amass, assetfinder, alterx, shuffledns, gowitness
- Specialized: wpscan, scoutsuite, mobsf

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
    # Injection tools
    commix_scan, smuggler_scan,
    # WordPress
    wpscan_scan,
    # Cloud
    scoutsuite_scan,
    # Discovery tools
    alterx_generate, arjun_scan, shuffledns_scan, gowitness_screenshot, cero_scan,
    # Mobile
    mobsf_scan,
)

# Initialize FastMCP server
mcp = FastMCP(
    name="security-tools",
    instructions="""Security assessment tools for authorized penetration testing.

IMPORTANT: Only use these tools on targets you have explicit permission to test.

Available tool categories:
- Network scanning (nmap, masscan, httpx)
- DNS reconnaissance (dns_lookup, whois, crtsh, cero)
- Web application testing (headers, ffuf, katana, waybackurls, arjun)
- Vulnerability scanning (nuclei, sqlmap, sslscan, commix, smuggler)
- Subdomain enumeration (amass, assetfinder, alterx, shuffledns)
- Visual recon (gowitness)
- Specialized (wpscan, scoutsuite, mobsf)
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
# INJECTION TOOLS
# =============================================================================

@mcp.tool()
def tool_commix_scan(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    level: int = 1,
    technique: Optional[str] = None
) -> str:
    """
    Test for OS command injection vulnerabilities using Commix.
    
    Args:
        url: Target URL with parameters to test
        data: POST data for POST requests
        cookie: Cookie header value
        level: Test level 1-3 (higher = more thorough)
        technique: Specific technique (classic, eval-based, time-based, file-based)
    """
    return commix_scan(url, data, cookie, level, technique)


@mcp.tool()
def tool_smuggler_scan(
    url: str,
    method: str = "POST",
    timeout: int = 10,
    verbose: bool = False
) -> str:
    """
    Test for HTTP Request Smuggling vulnerabilities.
    
    Args:
        url: Target URL to test
        method: HTTP method (GET or POST)
        timeout: Request timeout in seconds
        verbose: Enable verbose output
    """
    return smuggler_scan(url, method, timeout, verbose)


# =============================================================================
# WORDPRESS TOOLS
# =============================================================================

@mcp.tool()
def tool_wpscan_scan(
    url: str,
    enumerate: Optional[List[str]] = None,
    detection_mode: str = "mixed",
    api_token: Optional[str] = None,
    random_user_agent: bool = True,
    force: bool = False
) -> str:
    """
    Scan WordPress sites for vulnerabilities using WPScan.
    
    Args:
        url: Target WordPress URL
        enumerate: What to enumerate (vp, ap, vt, at, u, cb, dbe)
        detection_mode: Detection mode (mixed, passive, aggressive)
        api_token: WPScan API token
        random_user_agent: Use random user agents
        force: Force scan even if WordPress not detected
    """
    return wpscan_scan(url, enumerate, detection_mode, api_token, random_user_agent, force)


# =============================================================================
# CLOUD SECURITY TOOLS
# =============================================================================

@mcp.tool()
def tool_scoutsuite_scan(
    provider: str,
    profile: Optional[str] = None,
    regions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None
) -> str:
    """
    Run Scout Suite for cloud security auditing.
    
    Args:
        provider: Cloud provider (aws, azure, gcp)
        profile: AWS/Azure profile name
        regions: Specific regions to audit
        services: Specific services to audit
        access_key: AWS access key
        secret_key: AWS secret key
    """
    return scoutsuite_scan(provider, profile, regions, services, access_key, secret_key)


# =============================================================================
# DISCOVERY TOOLS
# =============================================================================

@mcp.tool()
def tool_alterx_generate(
    domain: str,
    pattern: Optional[str] = None,
    wordlist: Optional[str] = None,
    enrich: bool = True,
    limit: int = 1000
) -> str:
    """
    Generate subdomain wordlists using AlterX permutation patterns.
    
    Args:
        domain: Base domain to permute
        pattern: Custom permutation pattern
        wordlist: Input wordlist to permute
        enrich: Enrich with common patterns
        limit: Maximum number of results
    """
    return alterx_generate(domain, pattern, wordlist, enrich, limit)


@mcp.tool()
def tool_arjun_scan(
    url: str,
    method: str = "GET",
    wordlist: Optional[str] = None,
    threads: int = 10,
    timeout: int = 15,
    stable: bool = False
) -> str:
    """
    Discover hidden HTTP parameters using Arjun.
    
    Args:
        url: Target URL to test
        method: HTTP method (GET, POST, JSON, XML)
        wordlist: Custom parameter wordlist
        threads: Number of concurrent threads
        timeout: Request timeout
        stable: Use stable mode (slower but reliable)
    """
    return arjun_scan(url, method, wordlist, threads, timeout, stable)


@mcp.tool()
def tool_shuffledns_scan(
    domain: str,
    wordlist: Optional[str] = None,
    resolvers: Optional[str] = None,
    threads: int = 100
) -> str:
    """
    Bruteforce subdomains using ShuffleDNS with massdns.
    
    Args:
        domain: Target domain
        wordlist: Subdomain wordlist path
        resolvers: Custom DNS resolvers file
        threads: Number of concurrent threads
    """
    return shuffledns_scan(domain, wordlist, resolvers, threads)


@mcp.tool()
def tool_gowitness_screenshot(
    url: str,
    timeout: int = 10,
    fullpage: bool = False,
    screenshot_path: str = "/tmp/screenshots"
) -> str:
    """
    Capture screenshots of web pages using Gowitness.
    
    Args:
        url: URL to screenshot
        timeout: Page load timeout
        fullpage: Capture full page
        screenshot_path: Directory to save screenshots
    """
    return gowitness_screenshot(url, timeout, fullpage, screenshot_path)


@mcp.tool()
def tool_cero_scan(
    targets: List[str],
    concurrency: int = 100,
    timeout: int = 5,
    verbose: bool = False
) -> str:
    """
    Probe TLS certificates to discover domains.
    
    Args:
        targets: List of hosts/IPs to probe
        concurrency: Number of concurrent connections
        timeout: Connection timeout
        verbose: Enable verbose output
    """
    return cero_scan(targets, concurrency, timeout, verbose)


# =============================================================================
# MOBILE SECURITY TOOLS
# =============================================================================

@mcp.tool()
def tool_mobsf_scan(
    file_path: str,
    api_key: str,
    api_url: str = "http://localhost:8000",
    scan_type: Optional[str] = None
) -> str:
    """
    Scan mobile applications using MobSF.
    
    Args:
        file_path: Path to APK/IPA file
        api_key: MobSF API key
        api_url: MobSF API URL
        scan_type: Force scan type (apk, ipa, zip, appx)
    """
    return mobsf_scan(file_path, api_key, api_url, scan_type)


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
    
    # Injection
    "commix_scan": commix_scan,
    "smuggler_scan": smuggler_scan,
    
    # WordPress
    "wpscan_scan": wpscan_scan,
    
    # Cloud
    "scoutsuite_scan": scoutsuite_scan,
    
    # Discovery
    "alterx_generate": alterx_generate,
    "arjun_scan": arjun_scan,
    "shuffledns_scan": shuffledns_scan,
    "gowitness_screenshot": gowitness_screenshot,
    "cero_scan": cero_scan,
    
    # Mobile
    "mobsf_scan": mobsf_scan,
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
        "dns": ["dns_lookup", "whois_lookup", "crtsh_lookup", "cero_scan"],
        "web": ["http_headers_check", "ffuf_fuzz", "katana_crawl", "waybackurls_fetch", "arjun_scan"],
        "vulnerability": ["nuclei_scan", "sqlmap_scan", "sslscan_check", "commix_scan", "smuggler_scan"],
        "recon": ["amass_enum", "assetfinder_enum", "alterx_generate", "shuffledns_scan", "gowitness_screenshot"],
        "specialized": ["wpscan_scan", "scoutsuite_scan", "mobsf_scan"],
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
    print("\n  Tools Available: 25")
    print("    Network:     nmap, masscan, httpx")
    print("    DNS:         dns_lookup, whois, crtsh, cero")
    print("    Web:         headers, ffuf, katana, waybackurls, arjun")
    print("    Vuln:        nuclei, sqlmap, sslscan, commix, smuggler")
    print("    Recon:       amass, assetfinder, alterx, shuffledns, gowitness")
    print("    Specialized: wpscan, scoutsuite, mobsf")
    print("\n" + "=" * 60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
