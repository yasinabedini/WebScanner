"""
Web Crawling & Data Leakage Scanner - Optimized Edition
Deep crawls websites using Katana and detects sensitive data exposure
Author: yAsIn aBeDiNi
Version: 2.0 (Optimized)
"""

import subprocess
import json
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import threading
import time

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[!] Warning: reportlab not installed. PDF generation disabled.")

# ============ COLORS ============

class C:
    """رنگ‌های ANSI"""
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    D = '\033[2m'
    BD = '\033[1m'
    E = '\033[0m'

# ============ REGEX PATTERNS (OPTIMIZED & COMPILED) ============

class SensitivePatterns:
    """بهینه‌سازی شده با compiled regex برای سرعت بالا"""
    
    # Email (بهینه‌شده - دقیق‌تر)
    EMAIL = re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        re.IGNORECASE
    )
    
    # شماره تلفن ایران (بهینه‌شده)
    PHONE_IR = re.compile(
        r'\b(?:0|\+98)?9\d{9}\b|'  # موبایل
        r'\b0[1-8]\d{9}\b'  # ثابت
    )
    
    # کارت اعتباری (Luhn algorithm compatible)
    CREDIT_CARD = re.compile(
        r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    )
    
    # کد ملی ایران (با validation ساده)
    NATIONAL_ID = re.compile(r'\b\d{10}\b')
    
    # IP Address (IPv4)
    IP_ADDRESS = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # API Keys (بهینه‌شده - چند الگو)
    API_KEY = re.compile(
        r'(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|bearer)'
        r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})',
        re.IGNORECASE
    )
    
    # AWS Keys (بهینه‌شده)
    AWS_ACCESS_KEY = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')
    AWS_SECRET_KEY = re.compile(r'\b([A-Za-z0-9/+=]{40})\b')
    
    # JWT Token (بهینه‌شده)
    JWT_TOKEN = re.compile(
        r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'
    )
    
    # Database Connection Strings
    DB_CONNECTION = re.compile(
        r'(?:mongodb|mysql|postgresql|mssql|oracle|redis)://'
        r'[^:\s]+:[^@\s]+@[^\s<>"\']+|'
        r'Server=.*?Password=.*?;',
        re.IGNORECASE
    )
    
    # Private Keys
    PRIVATE_KEY = re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
        re.IGNORECASE
    )
    
    # Social Security Number (US)
    SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    
    # URL با credentials
    URL_WITH_CREDS = re.compile(
        r'https?://[^:\s]+:[^@\s]+@[^\s<>"\']+'
    )
    
    # Passwords در کد (بهینه‌شده)
    PASSWORD_IN_CODE = re.compile(
        r'(?:password|passwd|pwd|pass|secret)\s*[:=]\s*["\']([^"\']{6,})["\']',
        re.IGNORECASE
    )
    
    # GitHub Token
    GITHUB_TOKEN = re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b')
    
    # Slack Token
    SLACK_TOKEN = re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')
    
    # Google API Key
    GOOGLE_API = re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')
    
    # فایل‌های Backup
    BACKUP_FILES = re.compile(
        r'\.(?:bak|backup|old|sql|dump|tar\.gz|zip|rar|7z|db|sqlite|log)$',
        re.IGNORECASE
    )
    
    # Sensitive Endpoints (Static)
    SENSITIVE_ENDPOINTS = [
        '/admin', '/administrator', '/wp-admin', '/cpanel', '/phpmyadmin',
        '/backup', '/backups', '/.git', '/.env', '/config', '/database',
        '/sql', '/dump', '/api/keys', '/credentials', '/.aws', '/.ssh',
        '/swagger', '/api-docs', '/graphql', '/debug', '/trace', '/.svn',
        '/console', '/manager', '/actuator', '/metrics'
    ]
    
    # Sensitive Parameters (Static)
    SENSITIVE_PARAMS = [
        'password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'api_key',
        'apikey', 'access_token', 'auth', 'credential', 'key', 'private',
        'ssn', 'credit_card', 'card_number', 'cvv', 'national_id', 'session',
        'cookie', 'jwt', 'bearer'
    ]

# ============ DATA MODELS ============

@dataclass
class Finding:
    """مدل یافته"""
    type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    data: str
    url: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity,
            'data': self.data,
            'url': self.url,
            'description': self.description,
            'timestamp': self.timestamp
        }

@dataclass
class ScanStats:
    """آمار اسکن"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_urls: int = 0
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    findings_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def risk_score(self) -> float:
        """محاسبه Risk Score"""
        weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
        score = sum(
            self.findings_by_severity.get(sev, 0) * weight
            for sev, weight in weights.items()
        )
        return min(score, 100)

# ============ PROGRESS TRACKER ============

class ProgressTracker:
    """نمایش وضعیت زنده کرال"""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.stats = {
            'urls': 0,
            'findings': 0,
            'by_severity': defaultdict(int),
            'running': False
        }
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.spinner_idx = 0
        self.start_time = None
    
    def start(self):
        self.stats['running'] = True
        self.start_time = datetime.now()
        thread = threading.Thread(target=self._display_loop, daemon=True)
        thread.start()
    
    def stop(self):
        self.stats['running'] = False
        print(f"\r{' ' * 120}\r", end='', flush=True)
    
    def update_url(self):
        with self.lock:
            self.stats['urls'] += 1
    
    def update_finding(self, severity: str):
        with self.lock:
            self.stats['findings'] += 1
            self.stats['by_severity'][severity] += 1
    
    def _display_loop(self):
        while self.stats['running']:
            with self.lock:
                elapsed = (datetime.now() - self.start_time).total_seconds()
                spin = self.spinner[self.spinner_idx % len(self.spinner)]
                self.spinner_idx += 1
                
                # Build severity string
                sev_str = ""
                for sev, icon, color in [
                    ('CRITICAL', '🔴', C.R),
                    ('HIGH', '🟠', C.Y),
                    ('MEDIUM', '🟡', C.Y),
                    ('LOW', '🔵', C.C)
                ]:
                    count = self.stats['by_severity'].get(sev, 0)
                    if count > 0:
                        sev_str += f" {icon}{color}{count}{C.E}"
                
                progress = (
                    f"\r{C.C}{spin}{C.E} "
                    f"Crawling... "
                    f"│ {C.Y}{self.stats['urls']}{C.E} URLs "
                    f"│ {C.G}{self.stats['findings']}{C.E} findings"
                    f"{sev_str} "
                    f"│ {C.D}{elapsed:.0f}s{C.E}"
                )
                
                print(progress, end='', flush=True)
            
            time.sleep(0.1)

# ============ MAIN SCANNER ============

class DataLeakageScanner:
    """اسکنر اصلی"""
    
    def __init__(self, domain: str, output_dir: str = "Leakage-report"):
        self.domain = self._normalize_domain(domain)
        self.clean_domain = self._sanitize_filename(self.domain)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Tool paths
        self.tools_dir = Path("tools")
        self.katana_bin = self.tools_dir / "katana.exe"
        
        # Output files
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.crawl_output = self.output_dir / f"katana_{self.clean_domain}_{ts}.jsonl"
        self.pdf_output = self.output_dir / f"report_{self.clean_domain}_{ts}.pdf"
        
        # Data storage
        self.findings: List[Finding] = []
        self.crawled_urls: Set[str] = set()
        self.stats = ScanStats()
        self.progress = ProgressTracker()
        
        # Unique data sets
        self.emails = set()
        self.phones = set()
        self.api_keys = set()
    
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """نرمال‌سازی دامنه"""
        domain = domain.strip().lower()
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        return domain
    
    @staticmethod
    def _sanitize_filename(name: str) -> str:
        """پاک‌سازی نام فایل"""
        name = re.sub(r'^https?://(www\.)?', '', name)
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
        return name.strip('._- ')[:100] or "unknown"
    
    def print_banner(self):
        """بنر"""
        print(f"""
{C.C}{C.BD}╔══════════════════════════════════════════════════════╗
║                                                      ║
║        🔒 Data Leakage SCANNER - v3.1 🔒             ║
║                                                      ║
║             Author : yAsIn aBeDiNi                   ║
║                                                      ║
║       Github : https://github.com/yasinabedini       ║
║                                                      ║
╚══════════════════════════════════════════════════════╝{C.E}

{C.C}Target:{C.E} {C.Y}{self.domain}{C.E}
{C.C}Date:{C.E} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
""")
    
    def verify_tools(self) -> bool:
        """بررسی ابزار"""
        print(f"\n{C.C}╔══ Tool Verification ══╗{C.E}")
        
        if not self.katana_bin.exists():
            print(f"{C.C}║{C.E} {C.R}✗{C.E} Katana not found: {self.katana_bin}")
            print(f"{C.C}╚═══════════════════════╝{C.E}\n")
            print(f"{C.Y}[!] Download from: https://github.com/projectdiscovery/katana{C.E}")
            return False
        
        print(f"{C.C}║{C.E} {C.G}✓{C.E} Katana: {self.katana_bin}")
        print(f"{C.C}╚═══════════════════════╝{C.E}\n")
        return True
    
    def run_katana(self) -> bool:
        """اجرای Katana"""
        print(f"{C.C}╔══ Starting Leakage Scanner ══════════════════════════╗{C.E}\n")
        
        cmd = [
            str(self.katana_bin),
            "-u", self.domain,
            "-jsonl",
            "-o", str(self.crawl_output),
            "-d", "5",  # depth
            "-c", "20",  # concurrency
            "-jc",  # JavaScript crawl
            "-kf", "all",
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
            "-aff",  # form fill
            "-fx",  # extract forms
            "-silent",
            "-duc"  # disable update check
        ]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            self.progress.start()
            self.stats.start_time = datetime.now()
            
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                self.progress.update_url()
                
                # Real-time detection (optional)
                try:
                    data = json.loads(line)
                    if 'request' in data and 'endpoint' in data['request']:
                        endpoint = data['request']['endpoint']
                        
                        # Quick check for sensitive endpoints
                        for sensitive in SensitivePatterns.SENSITIVE_ENDPOINTS:
                            if sensitive in endpoint.lower():
                                self.progress.update_finding('HIGH')
                                break
                except:
                    pass
            
            process.wait()
            self.progress.stop()
            
            self.stats.end_time = datetime.now()
            
            if process.returncode != 0:
                print(f"\n{C.R}[!] Katana error (code: {process.returncode}){C.E}")
                return False
            
            print(f"\n{C.C}╚══════════════════════════════════════════════════╝{C.E}\n")
            print(f"{C.G}[+] Crawl completed in {self.stats.duration:.1f}s{C.E}\n")
            
            return True
            
        except Exception as e:
            self.progress.stop()
            print(f"{C.R}[!] Error: {e}{C.E}")
            return False
    
    def analyze_results(self) -> bool:
        """تحلیل نتایج"""
        print(f"{C.Y}[*] Analyzing results...{C.E}\n")
        
        if not self.crawl_output.exists():
            print(f"{C.R}[!] Output file not found{C.E}")
            return False
        
        try:
            with open(self.crawl_output, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        self._analyze_entry(data)
                    except:
                        continue
            
            self.stats.total_urls = len(self.crawled_urls)
            self.stats.total_findings = len(self.findings)
            
            # Update stats
            for finding in self.findings:
                self.stats.findings_by_severity[finding.severity] += 1
                self.stats.findings_by_type[finding.type] += 1
            
            self._print_summary()
            
            return True
            
        except Exception as e:
            print(f"{C.R}[!] Analysis error: {e}{C.E}")
            return False
    
    def _analyze_entry(self, data: Dict):
        """تحلیل یک entry"""
        if 'request' not in data:
            return
        
        request = data['request']
        endpoint = request.get('endpoint', '')
        body = data.get('response', {}).get('body', '')
        
        self.crawled_urls.add(endpoint)
        
        # ========== REGEX CHECKS ==========
        
        # 1. Emails
        for match in SensitivePatterns.EMAIL.finditer(body):
            email = match.group(0)
            if email not in self.emails:
                self.emails.add(email)
                self.findings.append(Finding(
                    type='EMAIL',
                    severity='MEDIUM',
                    data=email,
                    url=endpoint,
                    description='Email address exposed'
                ))
        
        # 2. Phone numbers
        for match in SensitivePatterns.PHONE_IR.finditer(body):
            phone = match.group(0)
            if phone not in self.phones and len(phone) >= 10:
                self.phones.add(phone)
                self.findings.append(Finding(
                    type='PHONE',
                    severity='MEDIUM',
                    data=phone,
                    url=endpoint,
                    description='Phone number exposed'
                ))
        
        # 3. API Keys
        for match in SensitivePatterns.API_KEY.finditer(body):
            key = match.group(1) if match.lastindex >= 1 else match.group(0)
            if key not in self.api_keys and len(key) >= 20:
                self.api_keys.add(key)
                self.findings.append(Finding(
                    type='API_KEY',
                    severity='CRITICAL',
                    data=key[:30] + '...' if len(key) > 30 else key,
                    url=endpoint,
                    description='API key or token exposed'
                ))
        
        # 4. AWS Keys
        for match in SensitivePatterns.AWS_ACCESS_KEY.finditer(body):
            self.findings.append(Finding(
                type='AWS_KEY',
                severity='CRITICAL',
                data=match.group(0),
                url=endpoint,
                description='AWS Access Key ID exposed'
            ))
        
        # 5. JWT Tokens
        for match in SensitivePatterns.JWT_TOKEN.finditer(body):
            token = match.group(0)
            self.findings.append(Finding(
                type='JWT_TOKEN',
                severity='HIGH',
                data=token[:40] + '...',
                url=endpoint,
                description='JWT token exposed'
            ))
        
        # 6. Database Connections
        for match in SensitivePatterns.DB_CONNECTION.finditer(body):
            self.findings.append(Finding(
                type='DB_CONNECTION',
                severity='CRITICAL',
                data=match.group(0)[:50] + '...',
                url=endpoint,
                description='Database connection string exposed'
            ))
        
        # 7. Private Keys
        if SensitivePatterns.PRIVATE_KEY.search(body):
            self.findings.append(Finding(
                type='PRIVATE_KEY',
                severity='CRITICAL',
                data='Private key detected',
                url=endpoint,
                description='Private cryptographic key exposed'
            ))
        
        # 8. GitHub Tokens
        for match in SensitivePatterns.GITHUB_TOKEN.finditer(body):
            self.findings.append(Finding(
                type='GITHUB_TOKEN',
                severity='CRITICAL',
                data=match.group(0),
                url=endpoint,
                description='GitHub token exposed'
            ))
        
        # 9. Google API Keys
        for match in SensitivePatterns.GOOGLE_API.finditer(body):
            self.findings.append(Finding(
                type='GOOGLE_API',
                severity='CRITICAL',
                data=match.group(0),
                url=endpoint,
                description='Google API key exposed'
            ))
        
        # 10. Passwords in Code
        for match in SensitivePatterns.PASSWORD_IN_CODE.finditer(body):
            pwd = match.group(1) if match.lastindex >= 1 else '***'
            self.findings.append(Finding(
                type='PASSWORD',
                severity='CRITICAL',
                data='***' + pwd[-4:] if len(pwd) > 4 else '***',
                url=endpoint,
                description='Password found in source code'
            ))
        
        # 11. URLs with Credentials
        for match in SensitivePatterns.URL_WITH_CREDS.finditer(body):
            self.findings.append(Finding(
                type='URL_CREDENTIALS',
                severity='HIGH',
                data=match.group(0)[:50] + '...',
                url=endpoint,
                description='URL containing credentials'
            ))
        
        # 12. Backup Files (in URL)
        if SensitivePatterns.BACKUP_FILES.search(endpoint):
            self.findings.append(Finding(
                type='BACKUP_FILE',
                severity='HIGH',
                data=endpoint.split('/')[-1],
                url=endpoint,
                description='Backup file accessible'
            ))
        
        # 13. Sensitive Endpoints
        for sensitive_path in SensitivePatterns.SENSITIVE_ENDPOINTS:
            if sensitive_path in endpoint.lower():
                self.findings.append(Finding(
                    type='SENSITIVE_ENDPOINT',
                    severity='HIGH',
                    data=sensitive_path,
                    url=endpoint,
                    description=f'Sensitive endpoint: {sensitive_path}'
                ))
                break
        
        # 14. Sensitive Parameters
        for param in SensitivePatterns.SENSITIVE_PARAMS:
            if param.lower() in endpoint.lower():
                self.findings.append(Finding(
                    type='SENSITIVE_PARAM',
                    severity='MEDIUM',
                    data=param,
                    url=endpoint,
                    description=f'Sensitive parameter: {param}'
                ))
                break
    
    def _print_summary(self):
        """خلاصه نتایج"""
        print(f"\n{C.G}╔══════════════════════════════════════════════╗")
        print(f"║         ANALYSIS COMPLETED               ║")
        print(f"╚══════════════════════════════════════════════╝{C.E}\n")
        
        print(f"{C.C}╔══ Summary ═══════════════════════════════════╗{C.E}")
        print(f"{C.C}║{C.E} Duration:    {self.stats.duration:.1f}s")
        print(f"{C.C}║{C.E} URLs:        {self.stats.total_urls}")
        print(f"{C.C}║{C.E} Findings:    {self.stats.total_findings}")
        print(f"{C.C}║{C.E} Risk Score:  {self.stats.risk_score:.1f}/100")
        print(f"{C.C}║{C.E}")
        
        # Severity
        for sev, color in [('CRITICAL', C.R), ('HIGH', C.Y), ('MEDIUM', C.Y), ('LOW', C.C)]:
            count = self.stats.findings_by_severity.get(sev, 0)
            if count > 0:
                print(f"{C.C}║{C.E} {color}■{C.E} {sev:8s}: {count}")
        
        print(f"{C.C}║{C.E}")
        print(f"{C.C}║{C.E} Emails:      {len(self.emails)}")
        print(f"{C.C}║{C.E} Phones:      {len(self.phones)}")
        print(f"{C.C}║{C.E} API Keys:    {len(self.api_keys)}")
        print(f"{C.C}╚══════════════════════════════════════════════╝{C.E}\n")
    
    def generate_pdf(self):
        """تولید PDF"""
        if not REPORTLAB_AVAILABLE:
            print(f"{C.Y}[!] reportlab not installed - skipping PDF{C.E}")
            return
        
        print(f"{C.Y}[*] Generating PDF report...{C.E}")
        
        doc = SimpleDocTemplate(
            str(self.pdf_output),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        # ========== COVER PAGE ========== (خطوط 690-716)
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph("🔍", title_style))
        story.append(Paragraph("DATA LEAKAGE ASSESSMENT", title_style))
        story.append(Spacer(1, 1*cm))
        
        cover_data = [
            ['Target:', self.domain],
            ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],  # کاما اضافه شد
            ['Duration:', f"{self.stats.duration:.1f}s"],
            ['URLs Crawled:', str(self.stats.total_urls)],
            ['Total Findings:', str(self.stats.total_findings)],
            ['Risk Score:', f"{self.stats.risk_score:.1f}/100"]
        ]
        
        t = Table(cover_data, colWidths=[5*cm, 10*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0,0), (0,-1), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 11),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('BACKGROUND', (1,0), (1,-1), colors.HexColor('#ecf0f1')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7'))
        ]))
        story.append(t)
        story.append(PageBreak())

        
        # ========== EXECUTIVE SUMMARY ==========
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Spacer(1, 0.5*cm))
        
        summary_text = f"""
        A comprehensive data leakage assessment was performed on <b>{self.domain}</b> 
        using automated crawling and pattern matching techniques. The scan identified 
        <b>{self.stats.total_findings}</b> potential data exposure issues across 
        <b>{self.stats.total_urls}</b> URLs, resulting in a risk score of 
        <b>{self.stats.risk_score:.1f}/100</b>.
        """
        story.append(Paragraph(summary_text, styles['BodyText']))
        story.append(Spacer(1, 0.5*cm))
        
        # Severity Distribution Table
        sev_data = [['Severity', 'Count', 'Risk Level']]
        for sev, color_hex in [
            ('CRITICAL', '#e74c3c'),
            ('HIGH', '#e67e22'),
            ('MEDIUM', '#f39c12'),
            ('LOW', '#3498db')
        ]:
            count = self.stats.findings_by_severity.get(sev, 0)
            if count > 0:
                sev_data.append([sev, str(count), '●' * min(count, 10)])
        
        if len(sev_data) > 1:
            t = Table(sev_data, colWidths=[4*cm, 3*cm, 8*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, colors.grey)
            ]))
            
            # Color rows
            for i, row in enumerate(sev_data[1:], 1):
                if 'CRITICAL' in row[0]:
                    t.setStyle(TableStyle([('BACKGROUND', (0,i), (-1,i), colors.HexColor('#fadbd8'))]))
                elif 'HIGH' in row[0]:
                    t.setStyle(TableStyle([('BACKGROUND', (0,i), (-1,i), colors.HexColor('#f9e79f'))]))
            
            story.append(t)
        
        story.append(Spacer(1, 0.8*cm))
        
        # ========== FINDINGS BY CATEGORY ==========
        story.append(Paragraph("Findings by Category", heading_style))
        story.append(Spacer(1, 0.3*cm))
        
        # Group findings by type
        findings_by_type = defaultdict(list)
        for finding in self.findings:
            findings_by_type[finding.type].append(finding)
        
        # Category mapping
        category_info = {
            'EMAIL': ('📧 Email Addresses', 'MEDIUM'),
            'PHONE': ('📱 Phone Numbers', 'MEDIUM'),
            'API_KEY': ('🔑 API Keys', 'CRITICAL'),
            'AWS_KEY': ('☁️ AWS Credentials', 'CRITICAL'),
            'GITHUB_TOKEN': ('🔓 GitHub Tokens', 'CRITICAL'),
            'GOOGLE_API': ('🌐 Google API Keys', 'CRITICAL'),
            'JWT_TOKEN': ('🎫 JWT Tokens', 'HIGH'),
            'DB_CONNECTION': ('💾 Database Credentials', 'CRITICAL'),
            'PRIVATE_KEY': ('🔐 Private Keys', 'CRITICAL'),
            'PASSWORD': ('🔒 Passwords', 'CRITICAL'),
            'URL_CREDENTIALS': ('🌍 URLs with Credentials', 'HIGH'),
            'BACKUP_FILE': ('📦 Backup Files', 'HIGH'),
            'SENSITIVE_ENDPOINT': ('🚨 Sensitive Endpoints', 'HIGH'),
            'SENSITIVE_PARAM': ('⚠️ Sensitive Parameters', 'MEDIUM')
        }
        
        for ftype, findings_list in sorted(findings_by_type.items(), 
                                           key=lambda x: len(x[1]), 
                                           reverse=True):
            
            if not findings_list:
                continue
            
            title, default_sev = category_info.get(ftype, (ftype, 'MEDIUM'))
            
            story.append(Paragraph(f"<b>{title}</b> ({len(findings_list)} found)", 
                                  styles['Heading3']))
            story.append(Spacer(1, 0.2*cm))
            
            # Show first 10 of each type
            for finding in findings_list[:10]:
                # Severity color
                sev_color = {
                    'CRITICAL': '#e74c3c',
                    'HIGH': '#e67e22',
                    'MEDIUM': '#f39c12',
                    'LOW': '#3498db'
                }.get(finding.severity, '#95a5a6')
                
                # Create colored box
                box_style = ParagraphStyle(
                    'Box',
                    parent=styles['BodyText'],
                    fontSize=9,
                    leftIndent=10,
                    rightIndent=10,
                    spaceBefore=6,
                    spaceAfter=6,
                    borderColor=colors.HexColor(sev_color),
                    borderWidth=1,
                    borderPadding=8,
                    backColor=colors.HexColor('#f8f9fa')
                )
                
                detail = f"""
                <b>Data:</b> {finding.data}<br/>
                <b>URL:</b> <font size=8>{finding.url}</font><br/>
                <b>Severity:</b> <font color="{sev_color}">{finding.severity}</font>
                """
                
                story.append(Paragraph(detail, box_style))
            
            if len(findings_list) > 10:
                story.append(Paragraph(
                    f"<i>... and {len(findings_list) - 10} more</i>",
                    styles['BodyText']
                ))
            
            story.append(Spacer(1, 0.5*cm))
        
        # ========== RECOMMENDATIONS ==========
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", heading_style))
        story.append(Spacer(1, 0.3*cm))
        
        recommendations = [
            ("Remove Sensitive Data", 
             "Immediately remove all exposed credentials, API keys, and personal information from public-facing pages."),
            ("Implement Access Controls", 
             "Restrict access to sensitive endpoints and administrative panels using proper authentication."),
            ("Secure Backup Files", 
             "Move backup files (.bak, .sql, .dump) outside the web root or implement strict access controls."),
            ("Sanitize Error Messages", 
             "Configure error handling to avoid exposing sensitive technical information in error messages."),
            ("Review Source Code", 
             "Conduct a thorough code review to remove hardcoded credentials and sensitive information."),
            ("Implement Rate Limiting", 
             "Add rate limiting to prevent automated scraping and enumeration attacks."),
            ("Regular Security Audits", 
             "Perform periodic security assessments to identify and remediate data exposure issues.")
        ]
        
        for i, (title, desc) in enumerate(recommendations, 1):
            rec_style = ParagraphStyle(
                'Recommendation',
                parent=styles['BodyText'],
                fontSize=10,
                leftIndent=20,
                spaceBefore=8,
                spaceAfter=8,
                borderColor=colors.HexColor('#27ae60'),
                borderWidth=1,
                borderPadding=10,
                backColor=colors.HexColor('#d5f4e6')
            )
            
            rec_text = f"<b>{i}. {title}</b><br/>{desc}"
            story.append(Paragraph(rec_text, rec_style))
        
        story.append(Spacer(1, 1*cm))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            "Report generated by Data Leakage Scanner v3.3 - Confidential",
            footer_style
        ))
        
        # Build PDF
        try:
            doc.build(story)
            print(f"{C.G}[+] PDF saved: {self.pdf_output}{C.E}\n")
        except Exception as e:
            print(f"{C.R}[!] PDF generation error: {e}{C.E}\n")
    
    def save_json(self):
        """ذخیره JSON"""
        json_output = self.output_dir / f"findings_{self.clean_domain}.json"
        
        data = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'duration': self.stats.duration,
            'statistics': {
                'total_urls': self.stats.total_urls,
                'total_findings': self.stats.total_findings,
                'risk_score': self.stats.risk_score,
                'by_severity': dict(self.stats.findings_by_severity),
                'by_type': dict(self.stats.findings_by_type)
            },
            'findings': [f.to_dict() for f in self.findings]
        }
        
        try:
            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"{C.G}[+] JSON saved: {json_output}{C.E}")
        except Exception as e:
            print(f"{C.R}[!] JSON save error: {e}{C.E}")
    
    def run(self) -> bool:
        """اجرای کامل"""
        self.print_banner()
        
        if not self.verify_tools():
            return False
        
        if not self.run_katana():
            return False
        
        if not self.analyze_results():
            return False
        
        self.generate_pdf()
        self.save_json()
        
        print(f"\n{C.G}{C.BD}✓ Scan completed successfully!{C.E}\n")
        return True


# ============ CLI ============

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='🔍 Data Leakage Scanner - Crawl and detect sensitive data exposure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com -o my_results
        """
    )
    
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('-o', '--output', default='crawl_results',
                       help='Output directory (default: crawl_results)')
    
    args = parser.parse_args()
    
    try:
        scanner = DataLeakageScanner(args.domain, args.output)
        success = scanner.run()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Scan interrupted by user{C.E}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.R}[!] Fatal error: {e}{C.E}")
        sys.exit(1)


if __name__ == '__main__':
    main()
