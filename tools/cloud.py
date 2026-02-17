"""
Cloud Security Tools
Scout Suite for AWS/Azure/GCP security auditing.
"""
import subprocess
import re
import os


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from output."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


async def scoutsuite_scan(provider: str, profile: str = None, 
                          regions: list = None, services: list = None,
                          access_key: str = None, secret_key: str = None,
                          session_token: str = None, report_dir: str = None) -> str:
    """
    Run Scout Suite for cloud security assessment.
    
    Args:
        provider: Cloud provider - aws, azure, gcp
        profile: AWS/Azure profile name to use
        regions: Specific regions to audit (e.g., ['us-east-1', 'eu-west-1'])
        services: Specific services to audit (e.g., ['ec2', 's3', 'iam'])
        access_key: AWS access key (if not using profile)
        secret_key: AWS secret key (if not using profile)
        session_token: AWS session token for temporary credentials
        report_dir: Directory to store the report
    
    Returns:
        Scout Suite audit results
    """
    cmd = ["scout", provider]
    
    # AWS-specific credentials
    if provider == "aws":
        if profile:
            cmd.extend(["--profile", profile])
        elif access_key and secret_key:
            # Set as environment variables for the subprocess
            env = os.environ.copy()
            env["AWS_ACCESS_KEY_ID"] = access_key
            env["AWS_SECRET_ACCESS_KEY"] = secret_key
            if session_token:
                env["AWS_SESSION_TOKEN"] = session_token
        else:
            env = None
    else:
        env = None
    
    if regions:
        cmd.extend(["--regions", ",".join(regions)])
    
    if services:
        cmd.extend(["--services", ",".join(services)])
    
    if report_dir:
        cmd.extend(["--report-dir", report_dir])
    
    cmd.append("--no-browser")  # Don't open browser automatically
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,  # Cloud audits can take 30+ minutes
            env=env if provider == "aws" and access_key else None
        )
        output = result.stdout + result.stderr
        return strip_ansi(output)
    except subprocess.TimeoutExpired:
        return "Error: Scout Suite timed out after 30 minutes"
    except FileNotFoundError:
        return "Error: scout not found. Install with: pip install scoutsuite"
    except Exception as e:
        return f"Error running Scout Suite: {e}"
