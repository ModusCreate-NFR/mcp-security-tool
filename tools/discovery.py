"""
Discovery Tools
Additional reconnaissance and discovery tools.
"""
import subprocess
import re
import os
import base64


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from output."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


async def alterx_generate(pattern: str = None, domain: str = None, 
                          wordlist: str = None, enrich: bool = True,
                          limit: int = 100) -> str:
    """
    Generate subdomain wordlists using AlterX permutations.
    
    Args:
        pattern: Custom pattern for permutations
        domain: Base domain to permute
        wordlist: Input wordlist of subdomains to permute
        enrich: Enrich input with common patterns
        limit: Maximum number of results
    
    Returns:
        Generated subdomain wordlist
    """
    cmd = ["alterx"]
    
    if pattern:
        cmd.extend(["-p", pattern])
    
    if domain:
        cmd.extend(["-d", domain])
    
    if wordlist:
        cmd.extend(["-l", wordlist])
    
    if enrich:
        cmd.append("-enrich")
    
    if limit:
        cmd.extend(["-limit", str(limit)])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "Error: AlterX timed out"
    except FileNotFoundError:
        return "Error: alterx not found. Install with: go install github.com/projectdiscovery/alterx/cmd/alterx@latest"
    except Exception as e:
        return f"Error running alterx: {e}"


async def arjun_scan(url: str, method: str = "GET", headers: dict = None,
                     wordlist: str = None, threads: int = 10,
                     timeout: int = 15, stable: bool = False) -> str:
    """
    Discover hidden HTTP parameters using Arjun.
    
    Args:
        url: Target URL to test
        method: HTTP method (GET, POST, JSON, XML)
        headers: Custom headers as dict
        wordlist: Custom parameter wordlist
        threads: Number of concurrent threads
        timeout: Request timeout in seconds
        stable: Use stable mode (slower but more reliable)
    
    Returns:
        Discovered parameters
    """
    cmd = ["arjun", "-u", url]
    
    if method:
        cmd.extend(["-m", method])
    
    if headers:
        for key, value in headers.items():
            cmd.extend(["--headers", f"{key}: {value}"])
    
    if wordlist:
        cmd.extend(["-w", wordlist])
    
    if threads:
        cmd.extend(["-t", str(threads)])
    
    if timeout:
        cmd.extend(["--timeout", str(timeout)])
    
    if stable:
        cmd.append("--stable")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout + result.stderr
        return strip_ansi(output) if output.strip() else "No hidden parameters discovered"
    except subprocess.TimeoutExpired:
        return "Error: Arjun timed out after 300 seconds"
    except FileNotFoundError:
        return "Error: arjun not found. Install with: pip install arjun"
    except Exception as e:
        return f"Error running arjun: {e}"


async def shuffledns_scan(domain: str, wordlist: str = None, 
                          resolvers: str = None, threads: int = 100,
                          massdns_path: str = None) -> str:
    """
    Bruteforce subdomains using ShuffleDNS with massdns.
    
    Args:
        domain: Target domain
        wordlist: Subdomain wordlist path
        resolvers: Custom resolvers file
        threads: Number of concurrent threads
        massdns_path: Path to massdns binary
    
    Returns:
        Discovered subdomains
    """
    cmd = ["shuffledns", "-d", domain]
    
    if wordlist:
        cmd.extend(["-w", wordlist])
    else:
        # Use a default wordlist if available
        default_lists = [
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/opt/wordlists/subdomains.txt"
        ]
        for wl in default_lists:
            if os.path.exists(wl):
                cmd.extend(["-w", wl])
                break
    
    if resolvers:
        cmd.extend(["-r", resolvers])
    
    if threads:
        cmd.extend(["-t", str(threads)])
    
    if massdns_path:
        cmd.extend(["-massdns", massdns_path])
    
    cmd.append("-silent")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        return result.stdout if result.stdout.strip() else "No subdomains discovered"
    except subprocess.TimeoutExpired:
        return "Error: ShuffleDNS timed out"
    except FileNotFoundError:
        return "Error: shuffledns not found. Install with: go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    except Exception as e:
        return f"Error running shuffledns: {e}"


async def gowitness_screenshot(url: str, timeout: int = 30,
                               fullpage: bool = False, 
                               screenshot_path: str = "./screenshots") -> str:
    """
    Capture screenshots of web pages using Gowitness.
    
    Args:
        url: URL to screenshot
        timeout: Page load timeout in seconds
        fullpage: Capture full page screenshot
        screenshot_path: Directory to save screenshots
    
    Returns:
        Path to saved screenshot or error message
    """
    cmd = ["gowitness", "scan", "single", "--url", url,
           "--screenshot-path", screenshot_path,
           "--write-none"]  # Don't write to database
    
    if timeout:
        cmd.extend(["--timeout", str(timeout)])
    
    if fullpage:
        cmd.append("--screenshot-fullpage")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout + result.stderr
        
        # Find the screenshot file
        if os.path.exists(screenshot_path):
            files = os.listdir(screenshot_path)
            if files:
                latest = max(files, key=lambda f: os.path.getctime(os.path.join(screenshot_path, f)))
                return f"Screenshot saved: {os.path.join(screenshot_path, latest)}\n\n{strip_ansi(output)}"
        
        return strip_ansi(output) if output.strip() else "Screenshot captured"
    except subprocess.TimeoutExpired:
        return "Error: Gowitness timed out"
    except FileNotFoundError:
        return "Error: gowitness not found. Install with: go install github.com/sensepost/gowitness@latest"
    except Exception as e:
        return f"Error running gowitness: {e}"


async def cero_scan(targets: list, concurrency: int = 100,
                    timeout: int = 4, verbose: bool = False) -> str:
    """
    Probe TLS certificates to discover domains using Cero.
    
    Args:
        targets: List of hosts/IPs to probe
        concurrency: Number of concurrent connections
        timeout: Connection timeout in seconds
        verbose: Enable verbose output
    
    Returns:
        Discovered domains from TLS certificates
    """
    cmd = ["cero"]
    
    if concurrency:
        cmd.extend(["-c", str(concurrency)])
    
    if timeout:
        cmd.extend(["-t", str(timeout)])
    
    if verbose:
        cmd.append("-v")
    
    # Add targets
    cmd.extend(targets)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.stdout if result.stdout.strip() else "No domains discovered from TLS certificates"
    except subprocess.TimeoutExpired:
        return "Error: Cero timed out"
    except FileNotFoundError:
        return "Error: cero not found. Install with: go install github.com/glebarez/cero@latest"
    except Exception as e:
        return f"Error running cero: {e}"
