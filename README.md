# CYS-ILM Reconnaissance Tool v3.0

> **Professional open-source intelligence & active-scanning framework for authorized security assessments.**

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Privilege & Sudo](#privilege--sudo)
7. [Output Formats](#output-formats)
8. [Disclaimer](#disclaimer)

---

## Overview

CYS-ILM Recon Tool is a modular Python reconnaissance framework developed by the
CYS-ILM Security Team.  It combines passive OSINT gathering with active network
enumeration to produce professional, risk-rated security reports — suitable for
penetration-testing engagements, university capstone projects, and corporate
security assessments.

---

## Features

| Category | Capabilities |
|---|---|
| **Passive** | WHOIS · DNS (A/AAAA/MX/TXT/NS/SOA/CNAME/CAA/DMARC) · Subdomain discovery (crt.sh + brute-common) · Reverse-IP PTR · Email intelligence (SPF/DMARC/DKIM) |
| **Active** | Port scanning via nmap (quick / standard / comprehensive / stealth) · Service banner grabbing · Web technology fingerprinting · HTTP security-header grading · SSL/TLS analysis · Sensitive path discovery · HTTP method enumeration |
| **Reporting** | Colour terminal output · Text report · Self-contained dark-theme HTML report · JSON raw data |
| **Security** | Input sanitisation · Rate limiting on external APIs · Automatic sudo escalation for privileged scans · Graceful TCP-connect fallback when root is unavailable |

---

## Architecture

```
cysilm_recon_tool/
├── cysilm_recon_tool.py   # Entry point, CLI, orchestration
├── config.ini             # Tunable defaults
├── requirements.txt
├── README.md
│
├── modules/
│   ├── passive_recon.py   # WHOIS, DNS, subdomains, email intel
│   ├── active_recon.py    # Nmap, banners, tech, headers, vulns
│   └── reporting.py       # Text / HTML / JSON report generation
│
├── utils/
│   ├── logger.py          # Coloured, levelled logging
│   ├── validator.py       # Target sanitisation & validation
│   └── exceptions.py      # Custom exception hierarchy
│
└── outputs/               # Auto-created; all reports saved here
```

---

## Installation

```bash
# 1. Clone
git clone https://github.com/CYS-ilm/CYS-ilm_Recon_Tool.git
cd CYS-ilm_Recon_Tool

# 2. Virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify
python3 cysilm_recon_tool.py --help
```

> **Nmap must be installed** on the system:
> ```bash
> sudo apt install nmap      # Debian/Ubuntu
> sudo dnf install nmap      # Fedora/RHEL
> brew install nmap          # macOS
> ```

---

## Usage

### Scan modes

```bash
# Full comprehensive scan (SYN-scan, auto-escalates to sudo)
python3 cysilm_recon_tool.py example.com --all --output html

# Passive only (no root needed)
python3 cysilm_recon_tool.py example.com --passive --output txt

# Active only – quick TCP-connect (no root needed)
python3 cysilm_recon_tool.py example.com --active --scan-type quick

# Quick preset (common ports, passive + active)
python3 cysilm_recon_tool.py example.com --quick --output html

# Custom port range with comprehensive SYN-scan
sudo python3 cysilm_recon_tool.py example.com \
    --active --ports 1-65535 --scan-type comprehensive --output all

# Individual modules
python3 cysilm_recon_tool.py example.com --whois --dns --tech -v
```

### All flags

| Flag | Description |
|---|---|
| `--all` | Full passive + active scan |
| `--passive` | Passive recon only |
| `--active` | Active recon only |
| `--quick` | Quick preset (common ports) |
| `--whois` | WHOIS lookup |
| `--dns` | DNS enumeration |
| `--subdomains` | Subdomain discovery |
| `--scan` | Port scan |
| `--banners` | Banner grabbing |
| `--tech` | Technology detection |
| `--ports RANGE` | e.g. `1-1000` or `80,443,8080` |
| `--scan-type` | `quick` `standard` `comprehensive` `stealth` |
| `--timing 0-5` | Nmap timing template (default 3) |
| `--output` | `txt` `html` `json` `all` |
| `--output-dir DIR` | Output directory (default `outputs/`) |
| `--no-report` | Skip file report generation |
| `--timeout SEC` | Connection timeout (default 10 s) |
| `-v / -vv` | Verbose / debug output |
| `-q` | Quiet mode |

---

## Privilege & Sudo

| Scan type | Root required? |
|---|---|
| `quick` (TCP-connect) | **No** |
| `standard` (SYN) | **Yes** |
| `comprehensive` (SYN + scripts) | **Yes** |
| `stealth` (fragmented SYN) | **Yes** |

When a privileged scan type is selected without root, the tool **automatically
re-launches itself with `sudo`**.  If sudo is unavailable it gracefully falls back
to a TCP-connect scan and warns the user.

---

## Output Formats

All reports are saved to `outputs/` (or your `--output-dir`):

| Format | File | Contents |
|---|---|---|
| `txt` | `recon_<target>_<ts>.txt` | Full human-readable report |
| `html` | `recon_<target>_<ts>.html` | Self-contained dark-theme report |
| `json` | `recon_<target>_<ts>.json` | Raw machine-readable data |

---

## Disclaimer

> This tool is for **educational purposes and authorized security testing only**.
> Always obtain **explicit written permission** before scanning any system or network
> you do not own.  The CYS-ILM team accepts no responsibility for misuse.
