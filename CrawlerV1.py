"""
Web Crawling & Data Leakage Scanner - Official PDF Report Generator
Deep crawls organizational websites using Katana and detects sensitive data exposure
"""

import subprocess
import json
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set
import shutil

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
except ImportError:
    print("[!] Error: reportlab is required. Install it with: pip install reportlab")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[!] Error: tqdm is required. Install it with: pip install tqdm")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class SensitiveDataPatterns:
    """Patterns for detecting sensitive data leakage"""
    
    # Email patterns
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Iranian phone numbers
    PHONE_IR = r'\b(0|\+98)?(9\d{9}|[1-8]\d{9})\b'
    
    # Credit card patterns (basic)
    CREDIT_CARD = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    
    # Iranian national ID (10 digits)
    NATIONAL_ID = r'\b\d{10}\b'
    
    # IP addresses (private & public)
    IP_ADDRESS = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # API keys and tokens (common patterns)
    API_KEY = r'\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})\b'
    
    # AWS keys
    AWS_KEY = r'AKIA[0-9A-Z]{16}'
    
    # JWT tokens
    JWT_TOKEN = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
    
    # Database connection strings
    DB_CONNECTION = r'(mongodb|mysql|postgresql|mssql|oracle):\/\/[^\s<>"\']+|Server=.*Password=.*'
    
    # Private keys
    PRIVATE_KEY = r'-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'
    
    # Social security numbers (US format, for international orgs)
    SSN = r'\b\d{3}-\d{2}-\d{4}\b'
    
    # URLs with credentials
    URL_WITH_CREDS = r'https?://[^:]+:[^@]+@[^\s<>"\']+'
    
    # Backup file extensions
    BACKUP_FILES = r'\.(bak|backup|old|sql|dump|tar\.gz|zip|rar|7z|db|sqlite)$'
    
    # Common sensitive endpoints
    SENSITIVE_ENDPOINTS = [
        '/admin', '/administrator', '/wp-admin', '/cpanel', '/phpmyadmin',
        '/backup', '/backups', '/.git', '/.env', '/config', '/database',
        '/sql', '/dump', '/api/keys', '/credentials', '/.aws', '/.ssh',
        '/swagger', '/api-docs', '/graphql', '/debug', '/trace'
    ]
    
    # Common sensitive parameters
    SENSITIVE_PARAMS = [
        'password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'api_key',
        'apikey', 'access_token', 'auth', 'credential', 'key', 'private',
        'ssn', 'credit_card', 'card_number', 'cvv', 'national_id'
    ]


class DataLeakageScanner:
    """Main scanner class for crawling and detecting data leakage"""
    
    def __init__(self, domain: str, output_dir: str = "crawl_results"):
        self.domain = domain
        self.clean_domain = self._sanitize_filename(domain)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Tool paths (OFFLINE mode)
        self.tools_dir = Path("tools")
        self.katana_bin = self.tools_dir / "katana.exe"
        
        # Output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.crawl_output = self.output_dir / f"katana_crawl_{timestamp}.jsonl"
        self.pdf_output = self.output_dir / f"data_leakage_report_{self.clean_domain}_{timestamp}.pdf"
        
        # Results storage
        self.crawled_urls: Set[str] = set()
        self.sensitive_findings: List[Dict] = []
        self.emails_found: Set[str] = set()
        self.phones_found: Set[str] = set()
        self.api_keys_found: Set[str] = set()
        self.sensitive_endpoints: List[Dict] = []
        
        # Statistics
        self.total_urls = 0
        self.total_issues = 0
    
    @staticmethod
    def _sanitize_filename(name: str) -> str:
        """Remove invalid characters from filename"""
        name = re.sub(r'^https?://', '', name)
        name = re.sub(r'^www\.', '', name)
        name = re.sub(r'[<>:"/\\|?*]', '_', name)
        name = name.strip('. ')
        return name
    
    def print_banner(self):
        """Display scanner banner"""
        banner = f"""
{Colors.CYAN}{'='*70}
    Web Crawling & Data Leakage Scanner
    Powered by Katana (Project Discovery)
{'='*70}{Colors.END}
{Colors.BOLD}Target Domain:{Colors.END} {self.domain}
{Colors.BOLD}Scan Date:{Colors.END} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{Colors.BOLD}Output Directory:{Colors.END} {self.output_dir}
{Colors.CYAN}{'='*70}{Colors.END}
"""
        print(banner)
    
    def verify_tools(self) -> bool:
        """Verify that Katana exists locally"""
        print(f"\n{Colors.YELLOW}[*] Verifying local tools...{Colors.END}")
        
        if not self.katana_bin.exists():
            print(f"{Colors.RED}[!] Katana binary not found at: {self.katana_bin}{Colors.END}")
            print(f"{Colors.YELLOW}[!] Please download Katana from: https://github.com/projectdiscovery/katana{Colors.END}")
            return False
        print(f"{Colors.GREEN}[+] Katana binary found{Colors.END}")
        
        return True
    
    def run_katana_crawl(self) -> bool:
        """Execute deep crawling with Katana"""
        print(f"\n{Colors.YELLOW}[*] Starting Katana deep crawl...{Colors.END}")
        print(f"{Colors.CYAN}[*] This may take several minutes depending on site size{Colors.END}")
        
        # Katana command with aggressive crawling settings
        cmd = [
            str(self.katana_bin),
            "-u", self.domain,
            "-jsonl",  # JSONL output
            "-o", str(self.crawl_output),
            "-d", "5",  # Maximum depth of 5
            "-c", "20",  # 20 concurrent connections
            "-jc",  # JavaScript crawling
            "-kf", "all",  # Known files (all types)
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2",  # Exclude images/fonts
            "-aff",  # Automatic form fill
            "-fx",  # Extract forms
            "-silent",  # Silent mode
            "-duc"  # Disable update check
        ]
        
        print(f"{Colors.CYAN}[*] Command: {' '.join(cmd)}{Colors.END}\n")
        
        try:
            # Initialize progress bar
            pbar = tqdm(
                desc=f"{Colors.GREEN}Crawling{Colors.END}",
                bar_format='{desc}: {n} URLs discovered | Elapsed: {elapsed}',
                unit=' URLs'
            )
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1
            )
            
            url_count = 0
            
            # Monitor output
            for line in iter(process.stdout.readline, b''):
                try:
                    decoded = line.decode('utf-8', errors='replace').rstrip()
                except:
                    decoded = line.decode('latin-1', errors='replace').rstrip()
                
                if not decoded.strip():
                    continue
                
                # Try to parse as JSON
                try:
                    data = json.loads(decoded)
                    if 'request' in data and 'endpoint' in data['request']:
                        url_count += 1
                        pbar.update(1)
                        
                        # Show interesting findings in real-time
                        endpoint = data['request']['endpoint']
                        
                        # Check for sensitive endpoints
                        for sensitive in SensitiveDataPatterns.SENSITIVE_ENDPOINTS:
                            if sensitive.lower() in endpoint.lower():
                                tqdm.write(f"{Colors.YELLOW}[!] Sensitive endpoint: {endpoint}{Colors.END}")
                                break
                        
                        # Check for sensitive parameters
                        for param in SensitiveDataPatterns.SENSITIVE_PARAMS:
                            if param.lower() in endpoint.lower():
                                tqdm.write(f"{Colors.RED}[!] Sensitive parameter detected: {endpoint}{Colors.END}")
                                break
                
                except json.JSONDecodeError:
                    pass
            
            pbar.close()
            process.wait()
            
            if process.returncode != 0:
                print(f"\n{Colors.RED}[!] Crawl encountered an error (exit code: {process.returncode}){Colors.END}")
                return False
            
            print(f"\n{Colors.GREEN}[+] Crawl completed successfully{Colors.END}")
            print(f"{Colors.CYAN}[*] Total URLs discovered: {url_count}{Colors.END}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error running Katana: {e}{Colors.END}")
            return False
    
    def analyze_crawl_results(self) -> bool:
        """Analyze crawled data for sensitive information"""
        print(f"\n{Colors.YELLOW}[*] Analyzing crawled data for sensitive information...{Colors.END}")
        
        if not self.crawl_output.exists():
            print(f"{Colors.RED}[!] Crawl output file not found{Colors.END}")
            return False
        
        try:
            with open(self.crawl_output, 'r', encoding='utf-8', errors='replace') as f:
                for line in tqdm(f, desc="Analyzing URLs", unit=" lines"):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        self._analyze_entry(data)
                    except json.JSONDecodeError:
                        continue
            
            self.total_urls = len(self.crawled_urls)
            self.total_issues = len(self.sensitive_findings)
            
            print(f"\n{Colors.GREEN}[+] Analysis completed{Colors.END}")
            self._print_summary()
            
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error analyzing results: {e}{Colors.END}")
            return False
    
    def _analyze_entry(self, data: Dict):
        """Analyze single crawl entry for sensitive data"""
        if 'request' not in data:
            return
        
        request = data['request']
        endpoint = request.get('endpoint', '')
        body = data.get('response', {}).get('body', '')
        
        # Add URL to set
        self.crawled_urls.add(endpoint)
        
        # 1. Check for emails
        emails = re.findall(SensitiveDataPatterns.EMAIL, body)
        for email in emails:
            if email not in self.emails_found:
                self.emails_found.add(email)
                self.sensitive_findings.append({
                    'type': 'EMAIL',
                    'severity': 'MEDIUM',
                    'data': email,
                    'url': endpoint,
                    'description': 'Email address exposed in page content'
                })
        
        # 2. Check for phone numbers
        phones = re.findall(SensitiveDataPatterns.PHONE_IR, body)
        for phone in phones:
            phone_clean = ''.join(phone)
            if phone_clean not in self.phones_found and len(phone_clean) >= 10:
                self.phones_found.add(phone_clean)
                self.sensitive_findings.append({
                    'type': 'PHONE',
                    'severity': 'MEDIUM',
                    'data': phone_clean,
                    'url': endpoint,
                    'description': 'Phone number exposed in page content'
                })
        
        # 3. Check for API keys
        api_keys = re.findall(SensitiveDataPatterns.API_KEY, body, re.IGNORECASE)
        for match in api_keys:
            key_value = match[1] if isinstance(match, tuple) else match
            if key_value not in self.api_keys_found:
                self.api_keys_found.add(key_value)
                self.sensitive_findings.append({
                    'type': 'API_KEY',
                    'severity': 'CRITICAL',
                    'data': key_value[:20] + '...' if len(key_value) > 20 else key_value,
                    'url': endpoint,
                    'description': 'Potential API key or token exposed'
                })
        
        # 4. Check for AWS keys
        aws_keys = re.findall(SensitiveDataPatterns.AWS_KEY, body)
        for key in aws_keys:
            self.sensitive_findings.append({
                'type': 'AWS_KEY',
                'severity': 'CRITICAL',
                'data': key,
                'url': endpoint,
                'description': 'AWS Access Key ID exposed'
            })
        
        # 5. Check for JWT tokens
        jwt_tokens = re.findall(SensitiveDataPatterns.JWT_TOKEN, body)
        for token in jwt_tokens:
            self.sensitive_findings.append({
                'type': 'JWT_TOKEN',
                'severity': 'HIGH',
                'data': token[:30] + '...',
                'url': endpoint,
                'description': 'JWT token exposed in response'
            })
        
        # 6. Check for database connection strings
        db_conn = re.findall(SensitiveDataPatterns.DB_CONNECTION, body, re.IGNORECASE)
        for conn in db_conn:
            self.sensitive_findings.append({
                'type': 'DB_CONNECTION',
                'severity': 'CRITICAL',
                'data': conn[:50] + '...',
                'url': endpoint,
                'description': 'Database connection string exposed'
            })
        
        # 7. Check for private keys
        if re.search(SensitiveDataPatterns.PRIVATE_KEY, body):
            self.sensitive_findings.append({
                'type': 'PRIVATE_KEY',
                'severity': 'CRITICAL',
                'data': 'Private key detected',
                'url': endpoint,
                'description': 'Private cryptographic key exposed'
            })
        
        # 8. Check for URLs with credentials
        urls_with_creds = re.findall(SensitiveDataPatterns.URL_WITH_CREDS, body)
        for url in urls_with_creds:
            self.sensitive_findings.append({
                'type': 'URL_CREDENTIALS',
                'severity': 'HIGH',
                'data': url[:50] + '...',
                'url': endpoint,
                'description': 'URL containing credentials exposed'
            })
        
        # 9. Check for sensitive endpoints
        for sensitive_path in SensitiveDataPatterns.SENSITIVE_ENDPOINTS:
            if sensitive_path.lower() in endpoint.lower():
                self.sensitive_endpoints.append({
                    'type': 'SENSITIVE_ENDPOINT',
                    'severity': 'HIGH',
                    'endpoint': endpoint,
                    'pattern': sensitive_path,
                    'description': f'Potentially sensitive endpoint: {sensitive_path}'
                })
        
        # 10. Check for backup files
        if re.search(SensitiveDataPatterns.BACKUP_FILES, endpoint, re.IGNORECASE):
            self.sensitive_findings.append({
                'type': 'BACKUP_FILE',
                'severity': 'HIGH',
                'data': endpoint.split('/')[-1],
                'url': endpoint,
                'description': 'Backup or sensitive file accessible'
            })
        
        # 11. Check for sensitive parameters in URLs
        for param in SensitiveDataPatterns.SENSITIVE_PARAMS:
            if param.lower() in endpoint.lower():
                self.sensitive_findings.append({
                    'type': 'SENSITIVE_PARAM',
                    'severity': 'MEDIUM',
                    'data': param,
                    'url': endpoint,
                    'description': f'URL contains sensitive parameter: {param}'
                })
                break
    
    def _print_summary(self):
        """Print analysis summary"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Analysis Summary:{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"  Total URLs Crawled: {self.total_urls}")
        print(f"  Total Issues Found: {self.total_issues}")
        print(f"  Emails Discovered: {len(self.emails_found)}")
        print(f"  Phone Numbers: {len(self.phones_found)}")
        print(f"  API Keys/Tokens: {len(self.api_keys_found)}")
        print(f"  Sensitive Endpoints: {len(self.sensitive_endpoints)}")
        
        # Severity breakdown
        severity_counts = {}
        for finding in self.sensitive_findings:
            sev = finding.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        if severity_counts:
            print(f"\n{Colors.BOLD}Severity Breakdown:{Colors.END}")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = {
                        'CRITICAL': Colors.RED,
                        'HIGH': Colors.RED,
                        'MEDIUM': Colors.YELLOW,
                        'LOW': Colors.CYAN
                    }.get(severity, Colors.END)
                    print(f"  {color}■{Colors.END} {severity}: {count}")
        
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    def generate_pdf_report(self):
        """Generate professional PDF report"""
        print(f"\n{Colors.YELLOW}[*] Generating PDF report...{Colors.END}")
        
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
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Title Page
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph("Data Leakage Assessment Report", title_style))
        story.append(Spacer(1, 1*cm))
        
        info_data = [
            ["Target Domain:", self.domain],
            ["Scan Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["URLs Crawled:", str(self.total_urls)],
            ["Total Issues:", str(self.total_issues)],
            ["Scanner:", "Katana (Project Discovery)"]
        ]
        
        info_table = Table(info_data, colWidths=[5*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(info_table)
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        story.append(Spacer(1, 0.5*cm))
        
        summary_text = f"""
        This report presents the findings of a comprehensive web crawling and data leakage assessment 
        conducted on <b>{self.domain}</b>. The assessment identified <b>{self.total_issues}</b> potential 
        security issues across <b>{self.total_urls}</b> crawled URLs, including exposed sensitive data, 
        API keys, credentials, and configuration files.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.5*cm))
        
        # Severity summary table
        severity_counts = {}
        for finding in self.sensitive_findings:
            sev = finding.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        summary_data = [["Severity", "Count"]]
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            summary_data.append([severity, str(count)])
        
        summary_table = Table(summary_data, colWidths=[8*cm, 4*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        severity_colors = {
            'CRITICAL': colors.red,
            'HIGH': colors.orangered,
            'MEDIUM': colors.orange,
            'LOW': colors.yellow
        }
        
        for i, severity in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], 1):
            if severity_counts.get(severity, 0) > 0:
                bg_color = severity_colors.get(severity, colors.white)
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, i), (-1, i), bg_color)
                ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.5*cm))
        
        # Key findings summary
        story.append(Paragraph("Key Findings Overview", styles['Heading2']))
        key_findings_data = [
            ["Finding Type", "Count"],
            ["Exposed Email Addresses", str(len(self.emails_found))],
            ["Exposed Phone Numbers", str(len(self.phones_found))],
            ["API Keys/Tokens", str(len(self.api_keys_found))],
            ["Sensitive Endpoints", str(len(self.sensitive_endpoints))]
        ]
        
        key_table = Table(key_findings_data, colWidths=[10*cm, 4*cm])
        key_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
        ]))
        story.append(key_table)
        story.append(PageBreak())
        
        # Detailed Findings by Category
        if self.sensitive_findings:
            story.append(Paragraph("Detailed Findings", styles['Heading1']))
            story.append(Spacer(1, 0.5*cm))
            
            # Group findings by type
            findings_by_type = {}
            for finding in self.sensitive_findings:
                ftype = finding.get('type', 'UNKNOWN')
                if ftype not in findings_by_type:
                    findings_by_type[ftype] = []
                findings_by_type[ftype].append(finding)
            
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            sorted_types = sorted(
                findings_by_type.items(),
                key=lambda x: severity_order.get(x[1][0].get('severity', 'LOW'), 4)
            )
            
            for idx, (ftype, findings) in enumerate(sorted_types, 1):
                # Category header
                type_name = ftype.replace('_', ' ').title()
                story.append(Paragraph(f"{idx}. {type_name} ({len(findings)} instances)", styles['Heading2']))
                story.append(Spacer(1, 0.3*cm))
                
                # Show first 10 instances of each type
                for finding in findings[:10]:
                    details_data = [
                        ["Severity:", finding.get('severity', 'N/A')],
                        ["Data:", finding.get('data', 'N/A')[:100]],
                        ["URL:", finding.get('url', 'N/A')[:80]],
                        ["Description:", finding.get('description', 'N/A')]
                    ]
                    
                    details_table = Table(details_data, colWidths=[3*cm, 13*cm])
                    details_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                    ]))
                    story.append(details_table)
                    story.append(Spacer(1, 0.3*cm))
                
                if len(findings) > 10:
                    story.append(Paragraph(
                        f"<i>... and {len(findings) - 10} more instances</i>",
                        styles['Normal']
                    ))
                
                story.append(Spacer(1, 0.5*cm))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", styles['Heading1']))
        story.append(Spacer(1, 0.5*cm))
        
        recommendations = [
            "<b>1. Immediate Actions:</b>",
            "• Rotate all exposed API keys and tokens immediately",
            "• Remove or restrict access to backup files and sensitive endpoints",
            "• Review and sanitize all exposed credentials in URLs",
            "",
            "<b>2. Data Protection:</b>",
            "• Implement proper redaction for email addresses and phone numbers",
            "• Use environment variables for sensitive configuration data",
            "• Enable access controls on admin panels and debugging endpoints",
            "",
            "<b>3. Long-term Security:</b>",
            "• Implement Content Security Policy (CSP) headers",
            "• Regular security audits and penetration testing",
            "• Developer training on secure coding practices",
            "• Implement automated secret scanning in CI/CD pipelines"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
            story.append(Spacer(1, 0.2*cm))
        
        # Build PDF
        doc.build(story)
        print(f"{Colors.GREEN}[+] PDF report generated: {self.pdf_output}{Colors.END}")
    
    def run(self):
        """Execute complete scan workflow"""
        self.print_banner()
        
        # Step 1: Verify tools
        if not self.verify_tools():
            print(f"\n{Colors.RED}[!] Tool verification failed. Exiting.{Colors.END}")
            return False
        
        # Step 2: Run crawl
        if not self.run_katana_crawl():
            print(f"\n{Colors.RED}[!] Crawl failed. Exiting.{Colors.END}")
            return False
        
        # Step 3: Analyze results
        if not self.analyze_crawl_results():
            print(f"\n{Colors.RED}[!] Analysis failed. Exiting.{Colors.END}")
            return False
        
        # Step 4: Generate PDF
        self.generate_pdf_report()
        
        print(f"\n{Colors.GREEN}{'='*70}")
        print(f"[+] Scan completed successfully!")
        print(f"[+] PDF Report: {self.pdf_output}")
        print(f"{'='*70}{Colors.END}\n")
        
        return True


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <domain>")
        print(f"Example: python {sys.argv[0]} example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    scanner = DataLeakageScanner(domain)
    success = scanner.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
