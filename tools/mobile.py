"""
Mobile Security Tools
MobSF for mobile application security testing.
"""
import subprocess
import re
import requests
import os


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from output."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


async def mobsf_scan(file_path: str = None, api_url: str = "http://localhost:8000",
                     api_key: str = None, scan_type: str = None) -> str:
    """
    Scan mobile applications using MobSF (Mobile Security Framework).
    
    Note: Requires MobSF server running. Start with:
        docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
    
    Args:
        file_path: Path to APK/IPA/ZIP file to analyze
        api_url: MobSF API URL (default: http://localhost:8000)
        api_key: MobSF API key (get from MobSF web interface)
        scan_type: Force scan type: apk, ipa, zip, appx
    
    Returns:
        MobSF scan results summary
    """
    if not api_key:
        return """Error: MobSF API key required.

To get your API key:
1. Start MobSF: docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
2. Open http://localhost:8000 in browser
3. Go to API Docs → Copy your REST API Key
4. Pass it as api_key parameter"""

    if not file_path or not os.path.exists(file_path):
        return f"Error: File not found: {file_path}"
    
    headers = {"Authorization": api_key}
    
    try:
        # Upload the file
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
            upload_response = requests.post(
                f"{api_url}/api/v1/upload",
                files=files,
                headers=headers,
                timeout=300
            )
        
        if upload_response.status_code != 200:
            return f"Error uploading file: {upload_response.text}"
        
        upload_data = upload_response.json()
        file_hash = upload_data.get("hash")
        
        if not file_hash:
            return f"Error: No hash returned from upload: {upload_data}"
        
        # Start the scan
        scan_data = {"hash": file_hash}
        if scan_type:
            scan_data["scan_type"] = scan_type
        
        scan_response = requests.post(
            f"{api_url}/api/v1/scan",
            data=scan_data,
            headers=headers,
            timeout=600  # Scans can take time
        )
        
        if scan_response.status_code != 200:
            return f"Error starting scan: {scan_response.text}"
        
        # Get the report
        report_response = requests.post(
            f"{api_url}/api/v1/report_json",
            data={"hash": file_hash},
            headers=headers,
            timeout=60
        )
        
        if report_response.status_code != 200:
            return f"Error getting report: {report_response.text}"
        
        report = report_response.json()
        
        # Format the output
        output = f"""MobSF Analysis Report
=====================
File: {report.get('file_name', 'Unknown')}
Package: {report.get('package_name', 'Unknown')}
Version: {report.get('version_name', 'Unknown')}
Size: {report.get('size', 'Unknown')}

Security Score: {report.get('security_score', 'Unknown')}/100

High Severity Issues: {len(report.get('high', []))}
Medium Severity Issues: {len(report.get('medium', []))}
Warning Issues: {len(report.get('warning', []))}
Info Issues: {len(report.get('info', []))}

Permissions: {len(report.get('permissions', {}))}
Activities: {len(report.get('activities', []))}
Services: {len(report.get('services', []))}
Receivers: {len(report.get('receivers', []))}
Providers: {len(report.get('providers', []))}

Full report available at: {api_url}/static_analyzer/{file_hash}
"""
        
        # Add high severity findings
        if report.get('high'):
            output += "\n\nHigh Severity Findings:\n"
            for finding in report['high'][:10]:  # Limit to first 10
                output += f"  - {finding}\n"
        
        return output
        
    except requests.exceptions.ConnectionError:
        return f"""Error: Cannot connect to MobSF at {api_url}

Start MobSF with:
  docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"""
    except Exception as e:
        return f"Error running MobSF scan: {e}"
