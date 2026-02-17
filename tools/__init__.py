"""
Security Tools Module
Organized by category for maintainability.
"""
from .network import nmap_scan, masscan_scan, httpx_probe
from .dns import dns_lookup, whois_lookup, crtsh_lookup
from .web import http_headers_check, ffuf_fuzz, katana_crawl, waybackurls_fetch
from .vuln import nuclei_scan, sqlmap_scan, sslscan_check
from .recon import amass_enum, assetfinder_enum
from .injection import commix_scan, smuggler_scan
from .wordpress import wpscan_scan
from .cloud import scoutsuite_scan
from .discovery import alterx_generate, arjun_scan, shuffledns_scan, gowitness_screenshot, cero_scan
from .mobile import mobsf_scan

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
    
    # Injection Tools
    "commix_scan": commix_scan,
    "smuggler_scan": smuggler_scan,
    
    # WordPress Tools
    "wpscan_scan": wpscan_scan,
    
    # Cloud Security Tools
    "scoutsuite_scan": scoutsuite_scan,
    
    # Discovery Tools
    "alterx_generate": alterx_generate,
    "arjun_scan": arjun_scan,
    "shuffledns_scan": shuffledns_scan,
    "gowitness_screenshot": gowitness_screenshot,
    "cero_scan": cero_scan,
    
    # Mobile Security Tools
    "mobsf_scan": mobsf_scan,
}

__all__ = list(ALL_TOOLS.keys()) + ["ALL_TOOLS"]
