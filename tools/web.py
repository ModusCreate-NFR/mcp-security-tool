"""
Web Application Testing Tools
- http_headers_check: Security headers analysis
- ffuf_fuzz: Web fuzzing (directories, parameters)
- katana_crawl: Web crawling and endpoint discovery
- waybackurls_fetch: Historical URL discovery from Wayback Machine
"""
import subprocess
import urllib.request
import urllib.error
import ssl
from typing import Optional, List


def http_headers_check(url: str) -> str:
    """
    Analyze HTTP security headers for a website.
    
    Args:
        url: Full URL to check (e.g., "https://example.com")
    
    Returns:
        Security headers analysis with recommendations
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SecurityScanner/1.0'}
        )
        response = urllib.request.urlopen(req, timeout=15, context=ctx)
        headers = dict(response.headers)
        
        # Security headers to check with descriptions
        security_headers = {
            'Strict-Transport-Security': {
                'desc': 'HSTS - Forces HTTPS connections',
                'severity': 'HIGH',
                'fix': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'desc': 'CSP - Prevents XSS and injection attacks',
                'severity': 'HIGH',
                'fix': 'Define a Content-Security-Policy appropriate for your application'
            },
            'X-Frame-Options': {
                'desc': 'Clickjacking protection',
                'severity': 'MEDIUM',
                'fix': 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'desc': 'MIME sniffing protection',
                'severity': 'MEDIUM',
                'fix': 'Add header: X-Content-Type-Options: nosniff'
            },
            'Referrer-Policy': {
                'desc': 'Controls referrer information leakage',
                'severity': 'LOW',
                'fix': 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'desc': 'Controls browser features (camera, mic, etc)',
                'severity': 'LOW',
                'fix': 'Add header: Permissions-Policy: geolocation=(), microphone=()'
            },
            'X-XSS-Protection': {
                'desc': 'Legacy XSS filter (deprecated but still useful)',
                'severity': 'LOW',
                'fix': 'Add header: X-XSS-Protection: 1; mode=block'
            },
        }
        
        results = [
            f"Security Headers Analysis for {url}",
            "=" * 60,
            ""
        ]
        
        found = []
        missing = []
        
        for header, info in security_headers.items():
            value = headers.get(header)
            if value:
                found.append(f"[PASS] {header}")
                found.append(f"       Value: {value}")
            else:
                missing.append(f"[FAIL] {header} - {info['desc']}")
                missing.append(f"       Severity: {info['severity']}")
                missing.append(f"       Fix: {info['fix']}")
                missing.append("")
        
        if found:
            results.append("FOUND HEADERS:")
            results.extend(found)
            results.append("")
        
        if missing:
            results.append("MISSING HEADERS:")
            results.extend(missing)
        
        # Score
        score = len(found) // 2  # Each header adds 2 lines
        total = len(security_headers)
        results.append(f"\nSecurity Score: {score}/{total}")
        
        return "\n".join(results)
        
    except urllib.error.URLError as e:
        return f"Error connecting to {url}: {e}"
    except Exception as e:
        return f"Error: {e}"


def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    mode: str = "dir",
    extensions: Optional[str] = None,
    method: str = "GET",
    filter_codes: Optional[str] = None,
    threads: int = 40
) -> str:
    """
    Web fuzzing using ffuf for directory/file/parameter discovery.
    
    Args:
        url: Target URL with FUZZ keyword (e.g., "https://example.com/FUZZ")
        wordlist: Path to wordlist file
        mode: Fuzzing mode - "dir" (directories), "file" (with extensions), "param" (parameters)
        extensions: File extensions to try (e.g., "php,html,js")
        method: HTTP method (GET, POST, etc.)
        filter_codes: Status codes to filter out (e.g., "404,403")
        threads: Number of concurrent threads (max 50)
    
    Returns:
        Fuzzing results
    """
    if "FUZZ" not in url:
        return "Error: URL must contain FUZZ keyword (e.g., https://example.com/FUZZ)"
    
    threads = min(threads, 50)  # Limit threads
    
    try:
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-X", method,
            "-mc", "all",  # Match all codes
            "-ac",  # Auto-calibrate
            "-s",   # Silent mode
        ]
        
        if extensions and mode == "file":
            cmd.extend(["-e", extensions])
        
        if filter_codes:
            cmd.extend(["-fc", filter_codes])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        output = result.stdout if result.stdout else ""
        if result.stderr and "error" in result.stderr.lower():
            output += f"\nErrors: {result.stderr}"
        
        return output.strip() if output.strip() else "No results found"
        
    except subprocess.TimeoutExpired:
        return "Error: Fuzzing timed out (5 minute limit)"
    except FileNotFoundError:
        return "Error: ffuf not found. Please install ffuf."
    except Exception as e:
        return f"Error: {e}"


def katana_crawl(
    targets: List[str],
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
    exclude: Optional[List[str]] = None
) -> str:
    """
    Web crawling using Katana for endpoint and URL discovery.
    
    Args:
        targets: List of URLs to crawl (e.g., ["https://example.com"])
        depth: Maximum crawl depth (1-10)
        js_crawl: Enable JavaScript file parsing for endpoints
        headless: Use headless browser for JavaScript-heavy sites
        exclude: Patterns to exclude from crawling
    
    Returns:
        Discovered endpoints and URLs
    """
    if not targets:
        return "Error: No targets provided"
    
    depth = min(max(depth, 1), 10)  # Clamp between 1-10
    
    try:
        cmd = [
            "katana",
            "-u", ",".join(targets),
            "-d", str(depth),
            "-silent",
        ]
        
        if js_crawl:
            cmd.append("-jc")
        
        if headless:
            cmd.append("-headless")
        
        if exclude:
            cmd.extend(["-exclude", ",".join(exclude)])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        output = result.stdout if result.stdout else ""
        
        # Count results
        lines = [l for l in output.split('\n') if l.strip()]
        if lines:
            return f"Found {len(lines)} endpoints:\n\n" + output
        
        return "No endpoints discovered"
        
    except subprocess.TimeoutExpired:
        return "Error: Crawling timed out (5 minute limit)"
    except FileNotFoundError:
        return "Error: katana not found. Please install katana."
    except Exception as e:
        return f"Error: {e}"


def waybackurls_fetch(domain: str, no_subs: bool = False) -> str:
    """
    Fetch historical URLs from the Wayback Machine.
    
    Args:
        domain: Target domain (e.g., "example.com")
        no_subs: If True, exclude subdomains from results
    
    Returns:
        Historical URLs from Wayback Machine
    """
    try:
        cmd = ["waybackurls", domain]
        if no_subs:
            cmd.append("--no-subs")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = result.stdout if result.stdout else ""
        
        if output.strip():
            lines = output.strip().split('\n')
            unique_urls = sorted(set(lines))
            return f"Found {len(unique_urls)} unique historical URLs:\n\n" + "\n".join(unique_urls)
        
        return "No historical URLs found"
        
    except subprocess.TimeoutExpired:
        return "Error: Fetch timed out (2 minute limit)"
    except FileNotFoundError:
        return "Error: waybackurls not found. Please install waybackurls."
    except Exception as e:
        return f"Error: {e}"
