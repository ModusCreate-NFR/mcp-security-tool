"""
Injection Testing Tools
Command injection and HTTP smuggling detection.
"""
import subprocess
import re


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from output."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


async def commix_scan(url: str, data: str = None, cookie: str = None, 
                      level: int = 1, technique: str = None) -> str:
    """
    Test for OS command injection vulnerabilities using Commix.
    
    Args:
        url: Target URL with parameters to test
        data: POST data (for POST requests)
        cookie: Cookie header value
        level: Test level 1-3 (higher = more thorough)
        technique: Specific technique: classic, eval-based, time-based, file-based
    
    Returns:
        Commix scan results
    """
    cmd = ["commix", "-u", url, "--batch"]
    
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if level:
        cmd.extend(["--level", str(level)])
    if technique:
        cmd.extend(["--technique", technique])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout + result.stderr
        return strip_ansi(output)
    except subprocess.TimeoutExpired:
        return "Error: Commix scan timed out after 300 seconds"
    except FileNotFoundError:
        return "Error: commix not found. Install with: pip install commix"
    except Exception as e:
        return f"Error running commix: {e}"


async def smuggler_scan(url: str, method: str = "POST", 
                        timeout: int = 10, verbose: bool = False) -> str:
    """
    Test for HTTP Request Smuggling vulnerabilities.
    
    Args:
        url: Target URL to test
        method: HTTP method (GET, POST)
        timeout: Request timeout in seconds
        verbose: Enable verbose output
    
    Returns:
        Smuggler scan results
    """
    cmd = ["python3", "-m", "smuggler", "-u", url]
    
    if method:
        cmd.extend(["-m", method])
    if timeout:
        cmd.extend(["-t", str(timeout)])
    if verbose:
        cmd.append("-v")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout + result.stderr
        return strip_ansi(output) if output.strip() else "No HTTP smuggling vulnerabilities detected"
    except subprocess.TimeoutExpired:
        return "Error: Smuggler scan timed out"
    except FileNotFoundError:
        return "Error: smuggler not found. Install with: pip install smuggler"
    except Exception as e:
        return f"Error running smuggler: {e}"
