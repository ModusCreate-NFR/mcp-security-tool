"""
DNS and Domain Intelligence Tools
- dns_lookup: DNS record queries
- whois_lookup: Domain registration info
- crtsh_lookup: Certificate transparency subdomain discovery
"""
import subprocess
import json
from typing import Optional
import urllib.request
import urllib.error


def dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Query DNS records for a domain.
    
    Args:
        domain: Domain to lookup (e.g., "example.com")
        record_type: DNS record type - A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, ANY
    
    Returns:
        DNS query results
    """
    valid_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "ANY"]
    record_type = record_type.upper()
    
    if record_type not in valid_types:
        return f"Error: Invalid record type. Use one of: {', '.join(valid_types)}"
    
    try:
        result = subprocess.run(
            ["nslookup", f"-type={record_type}", domain],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout if result.stdout else ""
        if result.stderr:
            output += f"\n{result.stderr}"
        return output.strip() if output.strip() else "No DNS records found"
    except subprocess.TimeoutExpired:
        return "Error: DNS lookup timed out"
    except FileNotFoundError:
        # Try dig as fallback
        try:
            result = subprocess.run(
                ["dig", record_type, domain, "+short"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip() if result.stdout else "No DNS records found"
        except:
            return "Error: Neither nslookup nor dig found. Please install dnsutils."
    except Exception as e:
        return f"Error: {e}"


def whois_lookup(domain: str) -> str:
    """
    Get WHOIS registration information for a domain.
    
    Args:
        domain: Domain to lookup (e.g., "example.com")
    
    Returns:
        WHOIS registration data
    """
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout if result.stdout else ""
        
        # Extract key fields for cleaner output
        if output:
            key_fields = [
                "Domain Name", "Registry Domain ID", "Registrar",
                "Creation Date", "Updated Date", "Expiry Date", "Expiration Date",
                "Registrant", "Admin", "Tech",
                "Name Server", "DNSSEC", "Status"
            ]
            
            lines = output.split('\n')
            filtered = []
            for line in lines:
                if any(field.lower() in line.lower() for field in key_fields):
                    filtered.append(line.strip())
            
            if filtered:
                return "WHOIS Summary:\n" + "\n".join(filtered) + "\n\n--- Full WHOIS ---\n" + output
        
        return output if output.strip() else "No WHOIS data found"
    except subprocess.TimeoutExpired:
        return "Error: WHOIS lookup timed out"
    except FileNotFoundError:
        return "Error: whois not found. Please install whois."
    except Exception as e:
        return f"Error: {e}"


def crtsh_lookup(domain: str, include_expired: bool = False) -> str:
    """
    Discover subdomains from SSL certificate transparency logs (crt.sh).
    
    Args:
        domain: Root domain to analyze (e.g., "example.com")
        include_expired: Include expired certificates in results
    
    Returns:
        List of discovered subdomains from certificate logs
    """
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SecurityScanner/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
        
        if not data:
            return f"No certificates found for {domain}"
        
        # Extract unique domain names
        domains = set()
        for cert in data:
            name = cert.get('name_value', '')
            # Handle wildcard and multi-domain certs
            for d in name.split('\n'):
                d = d.strip().lower()
                if d and not d.startswith('*'):
                    domains.add(d)
        
        sorted_domains = sorted(domains)
        
        result = [
            f"Certificate Transparency Results for {domain}",
            f"Found {len(sorted_domains)} unique domains/subdomains:",
            "=" * 50
        ]
        result.extend(sorted_domains)
        
        return "\n".join(result)
    
    except urllib.error.URLError as e:
        return f"Error connecting to crt.sh: {e}"
    except json.JSONDecodeError:
        return "Error: Invalid response from crt.sh"
    except Exception as e:
        return f"Error: {e}"
