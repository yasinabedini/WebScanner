# 🛡️ Web Scanner Toolkit

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**A Professional Offensive Security Reconnaissance Suite**

*Automated vulnerability scanning, data leakage detection, and port enumeration*

</div>

---

## 📖 Overview

**Web Scanner Toolkit** is a comprehensive offensive security suite designed for penetration testers, bug bounty hunters, and security researchers.:

1. **🎯 Nuclei Vulnerability Scanner** - Advanced template-based vulnerability detection
2. **🕵️ Data Leakage Scanner** - Intelligent web crawling with sensitive data detection
3. **🌐 Subdomain Port Scanner** - Automated subdomain enumeration and port scanning

---

## ✨ Features

### 🎯 Nuclei Scanner (v4.5)
- ✅ **Real-time progress tracking** with live statistics
- ✅ **Professional PDF reports** with severity analysis
- ✅ **Multi-threading support** for faster scans
- ✅ **Executive summaries** for stakeholders

### 🕵️ Data Leakage Scanner (v2.0)
- ✅ **Smart web crawling** powered by Katana
- ✅ **Regex-based detection** for 15+ sensitive data types
- ✅ **Pattern matching** for API keys, credentials, tokens
- ✅ **Iranian phone/email** specific patterns
- ✅ **Comprehensive PDF reports** with risk assessment

### 🌐 Subdomain Port Scanner (v2.0)
- ✅ **Automated subdomain discovery** via Subfinder
- ✅ **Multi-threaded port scanning** (up to 65535 ports)
- ✅ **DNS resolution** with health checks
- ✅ **Detailed PDF reports** with findings breakdown

---

## 🚀 Installation

### Prerequisites
```bash
# Python 3.8 or higher
python --version


# Git
git --version
```

### Clone Repository

```bash
git clone https://github.com/yasinabedini/WebScanner.git
cd WebScanner
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```txt
reportlab>=4.0.0
tqdm>=4.65.0
```


### Directory Structure

```txt
WebScnanner/
├── tools/
│   ├── nuclei.exe
│   ├── katana.exe
│   └── subfinder.exe
├── data/              # Raw scan outputs
├── reports/           # PDF reports
├── Scanner.py
├── Leakage.py
├── Domain.py
├── requirements.txt
└── README.md
```
---

## 🎯 Tools

### 1️⃣ Scanner.py 

Automated template-based vulnerability detection with real-time progress tracking.

**Basic Usage:**
```bash
python Scanner.py https://example.com
```

**Advanced Options:**
```bash

usage: Scanner.py [-h] -d DOMAIN [-o OUTPUT] [-v] [--skip-subdomain] [--skip-ports] [--tools-dir TOOLS_DIR]

Enterprise Web Security Scanner - Automated reconnaissance and vulnerability scanning

options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Target domain to scan
  -o, --output OUTPUT   Output directory for results (default: results)
  -v, --verbose         Enable verbose output
  --skip-subdomain      Skip subdomain enumeration phase
  --skip-ports          Skip port scanning phase
  --tools-dir TOOLS_DIR
                        Custom tools directory (default: ./tools)

Examples:
  Scanner.py -d example.com
  Scanner.py -d example.com -v
  Scanner.py -d example.com --skip-ports
  Scanner.py -d example.com -o /path/to/results
  Scanner.py -d example.com --tools-dir ./custom_tools

```

---

### 2️⃣ Leakage.py

Intelligent web crawler with pattern-based sensitive data detection.

**Basic Usage:**
```bash
usage: Leakage.py [-h] [-o OUTPUT] domain

positional arguments:
  domain               Target domain to scan

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output directory (default: crawl_results)

Examples:
  Leakage.py example.com
  Leakage.py https://example.com -o my_results
```
---

### 3️⃣ Domain.py
Automated subdomain discovery with intelligent port scanning.

**Basic Usage:**
```bash
usage: Domain.py [-h] [-m {common,extended,full}] [-t TIMEOUT] [-w WORKERS] [--no-pdf] domain

positional arguments:
  domain                Target domain to scan

options:
  -h, --help            show this help message and exit
  -m, --mode {common,extended,full}
                        Scan mode (default: common)
  -t, --timeout TIMEOUT
                        Port timeout in seconds (default: 1.0)
  -w, --workers WORKERS
                        Max concurrent threads (default: 100)
  --no-pdf              Skip PDF generation

Examples:
  Domain.py example.com
  Domain.py example.com -m extended
  Domain.py example.com -m full -t 2.0 -w 200

Scan Modes:
  common   - Top 20 common ports (fast)
  extended - Top 1000 ports + services (balanced)
  full     - All 65535 ports (slow)
```
---

## 📚 Examples

### Example 1: Full Vulnerability Assessment

```bash
# Step 1: Nuclei scan for vulnerabilities
python Scanner.py https://target.com --severity high,critical

# Step 2: Check for data leakage
python Leakage.py https://target.com --depth 5

# Step 3: Enumerate subdomains and ports
python Domain.py target.com -m extended
```
---

## 📊 Report Samples


---

## ⚠️ Disclaimer

**IMPORTANT:** This toolkit is designed for **authorized security testing only**.


⚖️ Legal Notice:

• Only use on systems you own or have explicit written permission to test
• Unauthorized access to computer systems is illegal in most jurisdictions
• The authors assume NO liability for misuse or damage caused by this tool
• Users are solely responsible for compliance with applicable laws
• This tool is provided "AS IS" without warranty of any kind

By using this toolkit, you agree to use it responsibly and ethically.

---

Copyright (c) 2025 Yasin Abedini

---

## 👨‍💻 Author

**Yasin Abedini**

- 🌐 GitHub: [@yasinabedini](https://github.com/yasinabedini)
- 📧 Email: yasinabedini.net@gmail.com
---

## 🌟 Star History

If you find this toolkit useful, please ⭐ star the repository!

[![Star History Chart](https://api.star-history.com/svg?repos=yasinabedini/WebScanner&type=Date)](https://star-history.com/#yasinabedini/WebScanner&Date)

---

## 🙏 Acknowledgments

This toolkit integrates the following excellent open-source projects:

- [Nuclei](https://github.com/projectdiscovery/nuclei) - ProjectDiscovery
- [Katana](https://github.com/projectdiscovery/katana) - ProjectDiscovery
- [Subfinder](https://github.com/projectdiscovery/subfinder) - ProjectDiscovery
- [ReportLab](https://www.reportlab.com/) - PDF generation

<div align="center">

**Made with ❤️ by security researchers, for security researchers**

[⬆ Back to Top](#️-WebScanner)

</div>
