# 🛡️ Web Scanner Toolkit

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**A Professional Offensive Security Reconnaissance Suite**

*Automated vulnerability scanning, data leakage detection, and port enumeration*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-tools) • [Examples](#-examples)

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

bash
git clone https://github.com/yasinabedini/cyberrecon-toolkit.git
cd cyberrecon-toolkit

### Install Dependencies

bash
pip install -r requirements.txt

**requirements.txt:**
txt
reportlab>=4.0.0
tqdm>=4.65.0

### External Tools Setup

#### 1. Nuclei
bash
# Download from https://github.com/projectdiscovery/nuclei/releases
# Place nuclei.exe in ./tools/ directory

# Update templates
./tools/nuclei.exe -update-templates

#### 2. Katana
bash
# Download from https://github.com/projectdiscovery/katana/releases
# Place katana.exe in ./tools/ directory

#### 3. Subfinder
bash
# Download from https://github.com/projectdiscovery/subfinder/releases
# Place subfinder.exe in ./tools/ directory

### Directory Structure


cyberrecon-toolkit/
├── tools/
│   ├── nuclei.exe
│   ├── katana.exe
│   └── subfinder.exe
├── data/              # Raw scan outputs
├── reports/           # PDF reports
├── NucleiScanner.py
├── DataLeakageScanner.py
├── SubdomainPortScanner.py
├── requirements.txt
└── README.md

---

## 🎯 Tools

### 1️⃣ Nuclei Vulnerability Scanner

Automated template-based vulnerability detection with real-time progress tracking.

**Basic Usage:**
bash
python NucleiScanner.py https://example.com

**Advanced Options:**
bash
python NucleiScanner.py https://example.com \
--severity critical,high \
--rate-limit 150 \
--timeout 10 \
--retries 2

**Command Line Options:**

-h, --help              Show help message
-s, --severity          Filter by severity (info,low,medium,high,critical)
-rl, --rate-limit       Max requests per second (default: 150)
-t, --timeout           Request timeout in seconds (default: 10)
-r, --retries           Number of retries (default: 1)
--update-templates      Update Nuclei templates before scan

**Output:**
- Raw JSON: `data/nuclei_<target>_<timestamp>.json`
- PDF Report: `reports/<target>_nuclei_<timestamp>.pdf`

---

### 2️⃣ Data Leakage Scanner

Intelligent web crawler with pattern-based sensitive data detection.

**Basic Usage:**
bash
python DataLeakageScanner.py https://example.com

**Advanced Options:**
bash
python DataLeakageScanner.py https://example.com \
--depth 5 \
--crawl-scope same-domain \
--rate-limit 100 \
--timeout 15

**Command Line Options:**

-h, --help              Show help message
-d, --depth             Maximum crawl depth (default: 3)
-cs, --crawl-scope      Crawl scope: same-domain, same-host (default: same-domain)
-rl, --rate-limit       Max requests per second (default: 150)
-t, --timeout           Request timeout in seconds (default: 10)

**Detection Patterns:**

✓ Email addresses (general + Iranian domains)
✓ Iranian phone numbers (09xx-xxx-xxxx)
✓ API keys (generic patterns)
✓ AWS credentials (Access Key, Secret Key)
✓ JWT tokens
✓ Private SSH/SSL keys
✓ Database connection strings
✓ Google API keys
✓ Stripe/PayPal keys
✓ OAuth tokens
✓ IP addresses (internal networks)
✓ Credit card numbers (basic pattern)
✓ Iranian national IDs
✓ JSON Web Tokens
✓ Bearer tokens

**Output:**
- Raw JSON: `data/katana_<target>_<timestamp>.json`
- Findings JSON: `data/findings_<target>_<timestamp>.json`
- PDF Report: `reports/<target>_leakage_<timestamp>.pdf`

---

### 3️⃣ Subdomain Port Scanner

Automated subdomain discovery with intelligent port scanning.

**Basic Usage:**
bash
python SubdomainPortScanner.py example.com

**Scan Modes:**
bash
# Common ports (fast - 20 ports)
python SubdomainPortScanner.py example.com -m common

# Extended scan (balanced - 1000+ ports)
python SubdomainPortScanner.py example.com -m extended

# Full scan (comprehensive - all 65535 ports)
python SubdomainPortScanner.py example.com -m full

**Advanced Options:**
bash
python SubdomainPortScanner.py example.com \
-m extended \
-t 1.5 \
-w 200 \
--no-pdf

**Command Line Options:**

-h, --help              Show help message
-m, --mode              Scan mode: common, extended, full (default: common)
-t, --timeout           Port timeout in seconds (default: 1.0)
-w, --workers           Max concurrent threads (default: 100)
--no-pdf                Skip PDF generation

**Port Risk Levels:**

CRITICAL: FTP(21), Telnet(23), RDP(3389), VNC(5900), SMB(445)
HIGH:     SSH(22), MySQL(3306), PostgreSQL(5432), Redis(6379), MongoDB(27017)
MEDIUM:   SMTP(25), POP3(110), IMAP(143), HTTP-Proxy(8080)
LOW:      HTTP(80), HTTPS(443), DNS(53)

**Output:**
- Subdomains: `data/subdomains_<domain>_<timestamp>.txt`
- PDF Report: `reports/<domain>_portscan_<timestamp>.pdf`

---

## 📚 Examples

### Example 1: Full Vulnerability Assessment

bash
# Step 1: Nuclei scan for vulnerabilities
python NucleiScanner.py https://target.com --severity high,critical

# Step 2: Check for data leakage
python DataLeakageScanner.py https://target.com --depth 5

# Step 3: Enumerate subdomains and ports
python SubdomainPortScanner.py target.com -m extended

### Example 2: Bug Bounty Recon

bash
# Fast reconnaissance
python SubdomainPortScanner.py target.com -m common
python NucleiScanner.py https://target.com --rate-limit 100

# Deep inspection on interesting endpoints
python DataLeakageScanner.py https://api.target.com --depth 4

### Example 3: Red Team Assessment

bash
# Comprehensive scanning
python SubdomainPortScanner.py target.com -m full -w 500
python NucleiScanner.py https://target.com --update-templates
python DataLeakageScanner.py https://target.com --depth 10

---

## 📊 Report Samples

All tools generate **professional PDF reports** including:

### Nuclei Reports
- 📌 Executive Summary
- 📊 Severity Distribution
- 🎯 Risk Score Calculation
- 📝 Detailed Findings (CVE, CVSS, CWE)
- 💡 Remediation Recommendations

### Data Leakage Reports
- 📌 Executive Summary
- 📊 Category Breakdown (Credentials, API Keys, etc.)
- 🎯 Risk Assessment
- 📝 Detailed Findings with Context
- 🛡️ Security Recommendations

### Port Scan Reports
- 📌 Scan Statistics
- 📊 Risk-based Port Classification
- 🌐 Subdomain-to-IP Mapping
- 📝 Detailed Port Findings
- 🔒 Security Implications

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

## 🛠️ Troubleshooting

### Common Issues

**Issue:** `nuclei.exe not found`
bash
# Solution: Download and place in ./tools/ directory
# https://github.com/projectdiscovery/nuclei/releases

**Issue:** `Permission denied`
bash
# Solution: Make tools executable (Linux/Mac)
chmod +x tools/nuclei.exe
chmod +x tools/katana.exe
chmod +x tools/subfinder.exe

**Issue:** `reportlab not found`
bash
# Solution: Install dependencies
pip install reportlab tqdm

**Issue:** Slow port scanning
bash
# Solution: Increase workers and adjust timeout
python SubdomainPortScanner.py target.com -w 500 -t 0.5

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 Changelog

### v2.0 (Current)
- ✨ Added real-time progress tracking
- ✨ Professional PDF report generation
- ✨ Risk-based severity classification
- ✨ Optimized regex patterns
- ✨ CLI argument parsing with `-h` support
- 🐛 Fixed indentation errors
- 🚀 Performance improvements

### v1.0
- 🎉 Initial release
- ✅ Nuclei integration
- ✅ Katana crawler
- ✅ Subfinder enumeration

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.


MIT License

Copyright (c) 2025 Yasin Abedini

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...

---

## 👨‍💻 Author

**Yasin Abedini**

- 🌐 GitHub: [@yasinabedini](https://github.com/yasinabedini)
- 📧 Email: your.email@example.com
- 🐦 Twitter: [@yourtwitterhandle]

---

## 🌟 Star History

If you find this toolkit useful, please ⭐ star the repository!

[![Star History Chart](https://api.star-history.com/svg?repos=yasinabedini/cyberrecon-toolkit&type=Date)](https://star-history.com/#yasinabedini/cyberrecon-toolkit&Date)

---

## 🙏 Acknowledgments

This toolkit integrates the following excellent open-source projects:

- [Nuclei](https://github.com/projectdiscovery/nuclei) - ProjectDiscovery
- [Katana](https://github.com/projectdiscovery/katana) - ProjectDiscovery
- [Subfinder](https://github.com/projectdiscovery/subfinder) - ProjectDiscovery
- [ReportLab](https://www.reportlab.com/) - PDF generation

---

## 📞 Support

Need help? Have questions?

1. 📖 Check the [Wiki](https://github.com/yasinabedini/cyberrecon-toolkit/wiki)
2. 🐛 Report bugs via [Issues](https://github.com/yasinabedini/cyberrecon-toolkit/issues)
3. 💬 Join discussions in [Discussions](https://github.com/yasinabedini/cyberrecon-toolkit/discussions)

---

<div align="center">

**Made with ❤️ by security researchers, for security researchers**

[⬆ Back to Top](#️-cyberrecon-toolkit)

</div>


---

## 🎁 فایل‌های اضافی پیشنهادی:

### LICENSE (MIT)
```txt
MIT License

Copyright (c) 2025 Yasin Abedini

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
