"""
Vulnerability Scanning Tools
- nuclei_scan: Template-based vulnerability scanning
- sqlmap_scan: SQL injection detection
- sslscan_check: SSL/TLS configuration analysis
"""
import subprocess
import re
from typing import Optional, List


def _remove_ansi(text: str) -> str:
    """Remove ANSI color codes from text."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


def nuclei_scan(
    target: str,
    tags: Optional[List[str]] = None,
    severity: Optional[str] = None,
    templates: Optional[List[str]] = None
) -> str:
    """
    Run Nuclei vulnerability scanner with YAML-based templates.
    
    Args:
        target: Target URL to scan (e.g., "https://example.com")
        tags: Filter templates by tags (e.g., ["cve", "xss", "sqli", "lfi"])
        severity: Filter by severity - "info", "low", "medium", "high", "critical"
        templates: Specific template IDs to run
    
    Returns:
        Vulnerability scan results
    
    Common tags: cve, xss, sqli, lfi, rce, ssrf, redirect, exposure, misconfig
    """
    try:
        cmd = ["nuclei", "-u", target, "-silent", "-nc"]  # -nc = no color
        
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        if severity:
            valid_severities = ["info", "low", "medium", "high", "critical"]
            if severity.lower() in valid_severities:
                cmd.extend(["-severity", severity.lower()])
        
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        output = _remove_ansi(result.stdout) if result.stdout else ""
        stderr = _remove_ansi(result.stderr) if result.stderr else ""
        
        # Parse results
        if output.strip():
            lines = output.strip().split('\n')
            findings = [l for l in lines if l.strip()]
            return f"Nuclei Scan Results ({len(findings)} findings):\n\n" + "\n".join(findings)
        
        if "no results" in stderr.lower() or not stderr:
            return "No vulnerabilities found (this is good!)"
        
        return f"Scan completed.\n{stderr}"
        
    except subprocess.TimeoutExpired:
        return "Error: Scan timed out (10 minute limit). Try using specific tags to narrow the scan."
    except FileNotFoundError:
        return "Error: nuclei not found. Please install nuclei."
    except Exception as e:
        return f"Error: {e}"


def sqlmap_scan(
    url: str,
    data: Optional[str] = None,
    level: int = 1,
    risk: int = 1,
    technique: Optional[str] = None,
    dbs: bool = False,
    tables: bool = False,
    dump: bool = False
) -> str:
    """
    SQL injection detection and exploitation using sqlmap.
    
    Args:
        url: Target URL with parameters (e.g., "https://example.com/page?id=1")
        data: POST data if testing POST request (e.g., "username=test&password=test")
        level: Test level 1-5 (higher = more tests, slower)
        risk: Risk level 1-3 (higher = more intrusive tests)
        technique: SQL injection techniques - B(oolean), E(rror), U(nion), S(tacked), T(ime)
        dbs: Enumerate databases
        tables: Enumerate tables
        dump: Dump table data (use carefully!)
    
    Returns:
        SQL injection test results
    """
    level = min(max(level, 1), 5)
    risk = min(max(risk, 1), 3)
    
    try:
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",  # Non-interactive
            "--level", str(level),
            "--risk", str(risk),
        ]
        
        if data:
            cmd.extend(["--data", data])
        
        if technique:
            cmd.extend(["--technique", technique.upper()])
        
        if dbs:
            cmd.append("--dbs")
        
        if tables:
            cmd.append("--tables")
        
        if dump:
            cmd.append("--dump")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        output = _remove_ansi(result.stdout + result.stderr)
        
        # Extract key findings
        if "is vulnerable" in output.lower() or "parameter" in output.lower():
            return output
        elif "not injectable" in output.lower():
            return "No SQL injection vulnerabilities found"
        
        return output if output.strip() else "Scan completed with no findings"
        
    except subprocess.TimeoutExpired:
        return "Error: Scan timed out (10 minute limit)"
    except FileNotFoundError:
        return "Error: sqlmap not found. Please install sqlmap."
    except Exception as e:
        return f"Error: {e}"


def sslscan_check(
    target: str,
    show_certificate: bool = True,
    check_vulnerabilities: bool = True
) -> str:
    """
    Analyze SSL/TLS configuration and identify weaknesses.
    
    Args:
        target: Target host:port (e.g., "example.com:443" or "example.com")
        show_certificate: Include certificate details in output
        check_vulnerabilities: Check for SSL vulnerabilities (POODLE, Heartbleed, etc.)
    
    Returns:
        SSL/TLS configuration analysis
    """
    # Add default port if not specified
    if ":" not in target:
        target = f"{target}:443"
    
    try:
        cmd = ["sslscan", "--no-colour"]
        
        if show_certificate:
            cmd.append("--show-certificate")
        
        if not check_vulnerabilities:
            cmd.extend([
                "--no-heartbleed",
                "--no-compression",
                "--no-fallback"
            ])
        
        cmd.append(target)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = _remove_ansi(result.stdout) if result.stdout else ""
        
        if output.strip():
            # Summarize key findings
            issues = []
            if "SSLv2" in output and "Enabled" in output:
                issues.append("[CRITICAL] SSLv2 enabled")
            if "SSLv3" in output and "Enabled" in output:
                issues.append("[HIGH] SSLv3 enabled (POODLE vulnerable)")
            if "TLSv1.0" in output and "Enabled" in output:
                issues.append("[MEDIUM] TLSv1.0 enabled (deprecated)")
            if "heartbleed" in output.lower() and "vulnerable" in output.lower():
                issues.append("[CRITICAL] Heartbleed vulnerable")
            if "RC4" in output:
                issues.append("[MEDIUM] RC4 cipher supported")
            
            summary = ""
            if issues:
                summary = "ISSUES FOUND:\n" + "\n".join(issues) + "\n\n" + "=" * 50 + "\n\n"
            
            return summary + output
        
        return "No SSL/TLS information found. Is the port correct?"
        
    except subprocess.TimeoutExpired:
        return "Error: SSL scan timed out (2 minute limit)"
    except FileNotFoundError:
        return "Error: sslscan not found. Please install sslscan."
    except Exception as e:
        return f"Error: {e}"
