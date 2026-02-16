"""
Reconnaissance Tools
- amass_enum: Advanced subdomain enumeration
- assetfinder_enum: Fast subdomain discovery
"""
import subprocess
import re
from typing import Optional, List


def _remove_ansi(text: str) -> str:
    """Remove ANSI color codes from text."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


def amass_enum(
    domain: str,
    mode: str = "passive",
    brute: bool = False,
    wordlist: Optional[str] = None
) -> str:
    """
    Advanced subdomain enumeration using OWASP Amass.
    
    Args:
        domain: Target domain (e.g., "example.com")
        mode: Enumeration mode - "passive" (safe, no direct contact) or "active" (DNS resolution)
        brute: Enable brute force subdomain discovery
        wordlist: Custom wordlist for brute force
    
    Returns:
        Discovered subdomains
    """
    try:
        cmd = ["amass", "enum", "-d", domain]
        
        if mode == "passive":
            cmd.append("-passive")
        
        if brute:
            cmd.append("-brute")
            if wordlist:
                cmd.extend(["-w", wordlist])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        output = _remove_ansi(result.stdout) if result.stdout else ""
        stderr = _remove_ansi(result.stderr) if result.stderr else ""
        
        if output.strip():
            lines = [l.strip() for l in output.split('\n') if l.strip()]
            unique_domains = sorted(set(lines))
            return f"Amass Enumeration Results ({len(unique_domains)} subdomains):\n\n" + "\n".join(unique_domains)
        
        # Check stderr for results (amass sometimes outputs there)
        if stderr.strip():
            return stderr
        
        return "No subdomains discovered"
        
    except subprocess.TimeoutExpired:
        return "Error: Enumeration timed out (10 minute limit). Passive mode is faster."
    except FileNotFoundError:
        return "Error: amass not found. Please install amass."
    except Exception as e:
        return f"Error: {e}"


def assetfinder_enum(domain: str, subs_only: bool = True) -> str:
    """
    Fast subdomain discovery using assetfinder.
    
    Args:
        domain: Target domain (e.g., "example.com")
        subs_only: Return only subdomains (exclude related domains)
    
    Returns:
        Discovered subdomains and related domains
    """
    try:
        cmd = ["assetfinder"]
        
        if subs_only:
            cmd.append("--subs-only")
        
        cmd.append(domain)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = _remove_ansi(result.stdout) if result.stdout else ""
        
        if output.strip():
            lines = [l.strip() for l in output.split('\n') if l.strip()]
            unique_domains = sorted(set(lines))
            return f"Assetfinder Results ({len(unique_domains)} domains):\n\n" + "\n".join(unique_domains)
        
        return "No domains discovered"
        
    except subprocess.TimeoutExpired:
        return "Error: Discovery timed out (2 minute limit)"
    except FileNotFoundError:
        return "Error: assetfinder not found. Please install assetfinder."
    except Exception as e:
        return f"Error: {e}"
