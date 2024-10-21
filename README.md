# Security Scan Tool 🛡️

This Python script scans a directory for sensitive data (e.g., API keys, passwords) and insecure configurations (e.g., debug mode enabled, hardcoded passwords) in common project files. The results are compiled into a JSON report, which can be used for further analysis or remediation.

## Features 🌟

- **Detects Sensitive Data**: Scans for API keys, tokens, passwords, and base64-encoded secrets.
- **Checks Insecure Configurations**: Detects configurations like debug mode enabled or hardcoded passwords.
- **Supports Multiple File Types**: Includes `.py`, `.txt`, `.md`, `.yml`, and `.json`.
- **Generates a Detailed JSON Report**: Provides a clear, structured report of findings.

## Usage 🚀

### Prerequisites

- Python 3.x installed on your machine.

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/security-scan-tool.git
   cd security-scan-tool
