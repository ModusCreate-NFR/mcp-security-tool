"""
Network Scanning Tools
- nmap: Port scanning and service detection
- masscan: Fast port scanning
- httpx: HTTP probing and service detection
"""
import subprocess
import shlex
import socket
from urllib.parse import urlparse
from typing import Optional, List


def _extract_hostname(target: str) -> str:
    """Extract hostname from URL or return as-is if already a hostname/IP."""
    target = target.strip()
    # If it looks like a URL (has ://), parse it
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0] if parsed.netloc else target
    # Remove any trailing path/port
    return target.split("/")[0].split(":")[0]


def nmap_scan(target: str, scan_type: str = "quick", ports: Optional[str] = None) -> str:
    """
    Scan a target for open ports and services using nmap.
    
    Args:
        target: IP address or hostname to scan (e.g., "192.168.1.1", "scanme.nmap.org")
        scan_type: Type of scan - "quick" (top 100), "full" (all 65535), "stealth" (SYN), "udp"
        ports: Optional specific ports to scan (e.g., "22,80,443" or "1-1000")
    
    Returns:
        Nmap scan results
    """
    scan_args = {
        "quick": "-F -sV",           # Fast scan, top 100 ports with version detection
        "full": "-p- -sV",           # All ports with version detection
        "stealth": "-sS -F",         # SYN stealth scan, top 100 ports
        "udp": "-sU --top-ports 50", # UDP scan, top 50 ports
        "comprehensive": "-sV -sC -O --top-ports 1000",  # Version, scripts, OS detection
    }
    
    # Extract hostname from URL if needed
    target = _extract_hostname(target)
    
    args = scan_args.get(scan_type, scan_args["quick"])
    
    # Override with specific ports if provided
    if ports:
        args = f"-p{ports} -sV"
    
    try:
        cmd = ["nmap"] + shlex.split(args) + [target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        output = result.stdout if result.stdout else ""
        if result.stderr:
            output += f"\nWarnings: {result.stderr}"
        return output if output.strip() else "No results returned"
    except subprocess.TimeoutExpired:
        return "Error: Scan timed out (10 minute limit). Try a quicker scan type."
    except FileNotFoundError:
        return "Error: nmap not found. Please install nmap."
    except Exception as e:
        return f"Error: {e}"


def masscan_scan(target: str, ports: str = "1-1000", rate: int = 1000) -> str:
    """
    Fast port scanning using masscan.
    
    Args:
        target: IP address, hostname, or CIDR range to scan
        ports: Port range to scan (e.g., "80,443" or "1-65535")
        rate: Packets per second (default 1000, max 10000)
    
    Returns:
        Masscan results
    """
    import socket
    import re
    
    # Limit rate to prevent abuse
    rate = min(rate, 10000)
    
    # Check if target is a hostname (not IP or CIDR) and resolve it
    resolved_target = target
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    
    if not re.match(ip_pattern, target):
        # It's a hostname, try to resolve
        try:
            resolved_ip = socket.gethostbyname(target)
            resolved_target = resolved_ip
            print(f"[masscan] Resolved {target} to {resolved_ip}")
        except socket.gaierror:
            return f"Error: Could not resolve hostname '{target}' to IP address. Masscan requires an IP address."
    
    try:
        cmd = ["masscan", f"-p{ports}", resolved_target, f"--rate={rate}"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        output = result.stdout + result.stderr
        return output.strip() if output.strip() else "No open ports found"
    except subprocess.TimeoutExpired:
        return "Error: Scan timed out (5 minute limit)"
    except FileNotFoundError:
        return "Error: masscan not found. Please install masscan."
    except Exception as e:
        return f"Error: {e}"


def httpx_probe(
    targets: List[str],
    ports: Optional[List[int]] = None,
    probes: Optional[List[str]] = None
) -> str:
    """
    Probe HTTP/HTTPS services using httpx.
    
    Args:
        targets: List of domains to probe (e.g., ["example.com", "test.com"])
        ports: List of ports to check (default: 80, 443, 8080, 8443)
        probes: List of probes to run - status-code, title, tech-detect, content-length, etc.
    
    Returns:
        HTTP probe results
    """
    if not targets:
        return "Error: No targets provided"
    
    # Default ports if not specified
    if not ports:
        ports = [80, 443, 8080, 8443]
    
    # Default probes
    if not probes:
        probes = ["status-code", "title", "tech-detect", "content-length"]
    
    try:
        cmd = ["httpx", "-silent"]
        
        # Add targets
        for target in targets:
            cmd.extend(["-u", target])
        
        # Add ports
        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        
        # Add probes
        for probe in probes:
            cmd.append(f"-{probe}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout if result.stdout else ""
        return output.strip() if output.strip() else "No HTTP services found"
    except subprocess.TimeoutExpired:
        return "Error: Probe timed out (2 minute limit)"
    except FileNotFoundError:
        return "Error: httpx not found. Please install httpx."
    except Exception as e:
        return f"Error: {e}"
