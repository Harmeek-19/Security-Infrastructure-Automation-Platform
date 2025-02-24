#!/usr/bin/env python3
# diagnostic_scan.py - A script to diagnose and test Nuclei scanning

import os
import sys
import json
import time
import subprocess
from pathlib import Path
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def run_nuclei_scan(target, templates="cves,vulnerabilities,exposures", severity="low,medium,high,critical"):
    """Run a Nuclei scan with detailed output for diagnostics"""
    
    # Define the command
    nuclei_path = os.path.expanduser("~/go/bin/nuclei")
    output_file = f"diagnostic-{int(time.time())}.json"
    
    # Build a command with extensive debugging
    cmd = [
        nuclei_path,
        "-target", target,
        "-j",  # JSON output
        "-output", output_file,
        "-t", templates,
        "-severity", severity,
        "-no-interactsh",  # Prevent hanging
        "-v",  # Verbose output
        "-stats",  # Show statistics
        "-timeout", "30",
        "-max-host-error", "10",
        "-retries", "2"
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    print("-" * 80)
    
    # Run the scan with live output
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )
        
        # Process output in real-time
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(line.strip())
                
        # Get the exit code
        exit_code = process.wait()
        
        # Print stderr
        stderr = process.stderr.read()
        if stderr:
            print("\nSTDERR OUTPUT:")
            print(stderr)
            
        print(f"\nNuclei completed with exit code: {exit_code}")
        
        # Check output file
        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"Output file created: {output_file} (size: {file_size} bytes)")
            
            if file_size > 0:
                print("\nFINDINGS:")
                with open(output_file, 'r') as f:
                    content = f.read().strip()
                    findings = [json.loads(line) for line in content.split('\n') if line.strip()]
                    
                    if findings:
                        print(f"Found {len(findings)} vulnerabilities:")
                        for i, finding in enumerate(findings):
                            name = finding.get("info", {}).get("name", "Unknown")
                            severity = finding.get("info", {}).get("severity", "unknown")
                            host = finding.get("host", "")
                            print(f"  {i+1}. [{severity.upper()}] {name} on {host}")
                    else:
                        print("No vulnerabilities found (empty JSON array)")
            else:
                print("Output file is empty (no findings)")
        else:
            print(f"Output file was not created: {output_file}")
            
    except Exception as e:
        print(f"Error running Nuclei: {str(e)}")
        
def check_nuclei_installation():
    """Check Nuclei installation and configuration"""
    nuclei_path = os.path.expanduser("~/go/bin/nuclei")
    
    print("CHECKING NUCLEI INSTALLATION")
    print("-" * 80)
    
    if not os.path.exists(nuclei_path):
        print(f"ERROR: Nuclei not found at {nuclei_path}")
        print("Please install using: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        return False
        
    print(f"Nuclei found at: {nuclei_path}")
    
    # Check version
    try:
        version_output = subprocess.check_output([nuclei_path, "-version"], text=True, stderr=subprocess.STDOUT)
        print(f"Version info: {version_output.strip()}")
        
        if "outdated" in version_output:
            print("\nWARNING: Nuclei is outdated. Consider updating for better results.")
            print("Run: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
    except Exception as e:
        print(f"Error checking version: {str(e)}")
        
    # Check template status
    try:
        template_output = subprocess.check_output([nuclei_path, "-tl"], text=True, stderr=subprocess.STDOUT)
        template_count = len(template_output.strip().split("\n"))
        print(f"Templates available: {template_count}")
        
        # Validate templates
        validate_output = subprocess.run([nuclei_path, "-validate"], 
                                        capture_output=True, text=True)
        
        if validate_output.stderr and "error" in validate_output.stderr:
            print("\nWARNING: Template validation issues found:")
            print(validate_output.stderr.strip())
            print("\nConsider updating templates: nuclei -update-templates")
        else:
            print("Templates validated successfully")
            
    except Exception as e:
        print(f"Error checking templates: {str(e)}")
        
    return True

def check_target_connectivity(target):
    """Check if the target is accessible via HTTP/HTTPS"""
    print("\nCHECKING TARGET CONNECTIVITY")
    print("-" * 80)
    
    # Format target URL
    urls = []
    if target.startswith(('http://', 'https://')):
        urls = [target]
    else:
        urls = [f"https://{target}", f"http://{target}"]
    
    for url in urls:
        try:
            print(f"Testing connection to {url}...")
            response = requests.get(url, timeout=10, verify=False)
            print(f"✓ Connection successful: {url} (Status: {response.status_code})")
            print(f"Response size: {len(response.content)} bytes")
            print(f"Server: {response.headers.get('Server', 'Unknown')}")
            return True
        except Exception as e:
            print(f"✗ Connection failed to {url}: {str(e)}")
    
    print("WARNING: Target may not be accessible. This could cause scanning issues.")
    return False

def update_nuclei():
    """Update Nuclei and templates"""
    print("\nUPDATING NUCLEI AND TEMPLATES")
    print("-" * 80)
    
    # Update Nuclei
    try:
        print("1. Updating Nuclei to latest version...")
        upgrade_cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"]
        upgrade_process = subprocess.run(upgrade_cmd, capture_output=True, text=True)
        
        if upgrade_process.returncode == 0:
            print("✓ Nuclei updated successfully")
        else:
            print(f"✗ Failed to update Nuclei: {upgrade_process.stderr}")
    except Exception as e:
        print(f"Error updating Nuclei: {str(e)}")
    
    # Update templates
    try:
        print("\n2. Updating Nuclei templates...")
        nuclei_path = os.path.expanduser("~/go/bin/nuclei")
        update_cmd = [nuclei_path, "-update-templates"]
        update_process = subprocess.run(update_cmd, capture_output=True, text=True)
        
        if update_process.returncode == 0:
            print("✓ Templates updated successfully")
            if "No new updates found" in update_process.stderr:
                print("Note: Templates were already up to date")
        else:
            print(f"✗ Failed to update templates: {update_process.stderr}")
    except Exception as e:
        print(f"Error updating templates: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Nuclei scanner diagnostic tool")
    parser.add_argument("--target", "-t", help="Target to scan (e.g., example.com)", required=False)
    parser.add_argument("--update", "-u", action="store_true", help="Update Nuclei and templates")
    parser.add_argument("--check", "-c", action="store_true", help="Check Nuclei installation only")
    parser.add_argument("--templates", help="Templates to use (default: cves,vulnerabilities,exposures)", 
                        default="cves,vulnerabilities,exposures")
    parser.add_argument("--severity", help="Severity levels to include (default: low,medium,high,critical)", 
                        default="low,medium,high,critical")
    
    args = parser.parse_args()
    
    if args.update:
        update_nuclei()
        return
        
    if check_nuclei_installation():
        print("\nNuclei installation check completed.")
        
        if args.check:
            return
            
        if not args.target:
            print("\nERROR: No target specified. Use --target or -t option.")
            parser.print_help()
            return
            
        check_target_connectivity(args.target)
        print("\nStarting Nuclei scan...")
        run_nuclei_scan(args.target, args.templates, args.severity)

if __name__ == "__main__":
    main()