# 🕵️ SPY BUG
### Authorized Web Security Assessment & Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Development-orange)

**SPY BUG** is a Python-based web security assessment tool designed to help cybersecurity learners, ethical hackers, and authorized security testers identify potential web application security weaknesses.

## Features

- DNS Reconnaissance
- Same-host Web Crawling
- Security Header Analysis
- Cookie Security Configuration Checks
- Common Path Discovery
- Reflected Input Analysis
- Optional Browser-Based XSS Confirmation
- Passive SQL Error Detection
- Optional Read-Only SQL Differential Checks
- Two-Account IDOR Comparison
- Business Logic Review
- Authenticated GET Checks
- TLS Inspection
- HTML and JSON Report Generation

## Installation

Clone the repository:

```bash
git clone https://github.com/hackwithspy/SPY_BUG.git
cd SPY_BUG
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic scan:

```bash
python3 spy_bugs.py --target https://example.com --authorized
```

Customize the scan:

```bash
python3 spy_bugs.py \
--target https://example.com \
--authorized \
--delay 1 \
--max-pages 40
```

Optional SQL differential checks:

```bash
python3 spy_bugs.py \
--target https://example.com \
--authorized \
--active-confirm
```

Optional browser-based XSS confirmation requires Playwright and Chromium.

## Reports

The scanner generates:

- `spy_bugs_report.html`
- `spy_bugs_report.json`

These reports contain scan statistics, findings, evidence indicators, and errors.

## Project Structure

```text
SPY_BUG/
spy_bugs.py
README.md
requirements.txt
LICENSE
SECURITY.md
.gitignore
docs/
screenshots/
reports/
tests/
```

## Disclaimer

SPY BUG is intended strictly for authorized security testing, educational purposes, and defensive security assessments.

Only scan websites and systems that you own or have explicit permission to test.

Unauthorized scanning or testing may violate applicable laws and regulations.

The developer is not responsible for misuse of this software.

## Author

**Hack With Spy**

GitHub: https://github.com/hackwithspy

---

⭐ If you find this project useful, consider starring the repository.
