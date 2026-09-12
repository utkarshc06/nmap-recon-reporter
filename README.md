# Nmap Recon Reporter

An automated Python script that executes an Nmap service-version scan, parses the resulting XML data, and generates a clean, structured Markdown reconnaissance report.

## Features
- **CLI Interface:** Accepts target IP addresses or CIDR ranges.
- **Automated Scanning:** Runs a targeted Nmap scan (`-sV -T4`).
- **XML Parsing:** Extracts open ports, protocols, services, and product versions.
- **Instant Reporting:** Automatically formats findings into a timestamped `.md` report.

## Prerequisites
- Kali Linux
- Python 3 with `python-nmap` installed inside a virtual environment.
- Nmap installed on your system.

## Installation & Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/utkarshc06/nmap-recon-reporter.git](https://github.com/utkarshc06/nmap-recon-reporter.git)
   cd nmap-recon-reporter
