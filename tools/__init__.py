"""
Security Tools Module
Organized by category for maintainability.
"""
from .network import nmap_scan, masscan_scan, httpx_probe
from .dns import dns_lookup, whois_lookup, crtsh_lookup
from .web import http_headers_check, ffuf_fuzz, katana_crawl, waybackurls_fetch
from .vuln import nuclei_scan, sqlmap_scan, sslscan_check
from .recon import amass_enum, assetfinder_enum

# All available tools
ALL_TOOLS = {
    # Network Tools
    "nmap_scan": nmap_scan,
    "masscan_scan": masscan_scan,
    "httpx_probe": httpx_probe,
    
    # DNS Tools
    "dns_lookup": dns_lookup,
    "whois_lookup": whois_lookup,
    "crtsh_lookup": crtsh_lookup,
    
    # Web Tools
    "http_headers_check": http_headers_check,
    "ffuf_fuzz": ffuf_fuzz,
    "katana_crawl": katana_crawl,
    "waybackurls_fetch": waybackurls_fetch,
    
    # Vulnerability Tools
    "nuclei_scan": nuclei_scan,
    "sqlmap_scan": sqlmap_scan,
    "sslscan_check": sslscan_check,
    
    # Recon Tools
    "amass_enum": amass_enum,
    "assetfinder_enum": assetfinder_enum,
}

__all__ = list(ALL_TOOLS.keys()) + ["ALL_TOOLS"]
