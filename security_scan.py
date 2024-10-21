import os
import re
import json
import yaml
from collections import defaultdict

# Define sensitive patterns (e.g., API keys, passwords, etc.)
SENSITIVE_PATTERNS = [
    r'(api|secret|key|token|password)\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}["\']?',  # API keys, tokens
    r'^[A-Za-z0-9+\/=]{20,}$',  # Base64 strings (could be a secret key)
    r'(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["\']?.{8,}["\']?',  # Password field
]

# Define insecure configurations (e.g., hardcoded credentials, debug mode enabled)
INSECURE_CONFIGS = [
    r'(?i)\b(debug|dev|test)\b\s*[:=]\s*["\']?true["\']?',  # Debug mode enabled
    r'(?i)\b(password|passwd)\b\s*[:=]\s*["\']?.{8,}["\']?',  # Hardcoded password
]

def scan_file_for_sensitive_data(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append((pattern, matches))
    return findings

def scan_file_for_insecure_configs(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
        for pattern in INSECURE_CONFIGS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append((pattern, matches))
    return findings

def scan_directory(directory):
    results = defaultdict(list)
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(('.py', '.txt', '.md', '.yml', '.json')):
                # Scan for sensitive data
                sensitive_data = scan_file_for_sensitive_data(file_path)
                if sensitive_data:
                    results['Sensitive Data'].append({
                        'file': file_path,
                        'findings': sensitive_data
                    })

                # Scan for insecure configurations
                insecure_configs = scan_file_for_insecure_configs(file_path)
                if insecure_configs:
                    results['Insecure Configurations'].append({
                        'file': file_path,
                        'findings': insecure_configs
                    })
    return results

def generate_report(results, output_file="security_scan_report.json"):
    report = {}
    for category, items in results.items():
        report[category] = []
        for item in items:
            report[category].append({
                'file': item['file'],
                'findings': item['findings']
            })
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)
    print(f"Security scan completed. Report generated: {output_file}")

if __name__ == '__main__':
    directory_to_scan = input("Enter the directory to scan for sensitive data and insecure configurations: ")
    results = scan_directory(directory_to_scan)
    generate_report(results)
