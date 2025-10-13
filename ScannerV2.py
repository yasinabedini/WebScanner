#!/usr/bin/env python3
"""
Web Asset Security Scanner - Optimized Professional Edition
High-performance vulnerability assessment using Nuclei (offline mode)
Features: Multi-threading, caching, advanced filtering, enhanced reporting
"""

import subprocess
import json
import sys
import re
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from tqdm import tqdm
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[!] Install with: pip install reportlab tqdm")
    sys.exit(1)


# ==================== CONFIGURATION ====================

@dataclass
class ScanConfig:
    """Centralized scan configuration"""
    # Performance
    max_workers: int = 10
    timeout: int = 300
    rate_limit: int = 150
    
    # Severity filtering
    severity_levels: List[str] = field(default_factory=lambda: 
        ["critical", "high", "medium", "low", "info"])
    
    # Template filtering
    exclude_tags: List[str] = field(default_factory=lambda: 
        ["dos", "fuzz"])  # Exclude DoS and fuzzing templates
    
    # Output options
    include_raw_data: bool = False
    max_description_length: int = 1000
    max_findings_per_severity: int = 50
    
    # Report customization
    company_name: str = "Security Assessment Team"
    report_classification: str = "CONFIDENTIAL"


@dataclass
class Vulnerability:
    """Structured vulnerability data model"""
    name: str
    severity: str
    template_id: str
    vuln_type: str
    matched_url: str
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    extracted_data: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'severity': self.severity,
            'template_id': self.template_id,
            'type': self.vuln_type,
            'url': self.matched_url,
            'cvss': self.cvss_score,
            'cves': self.cve_ids
        }


# ==================== UTILITIES ====================

class Colors:
    """Enhanced ANSI color codes with bold variants"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def severity_color(severity: str) -> str:
        """Get color for severity level"""
        return {
            'critical': Colors.RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE,
        }.get(severity.lower(), Colors.END)


class Logger:
    """Thread-safe logger with timestamps"""
    _lock = threading.Lock()
    
    @staticmethod
    def log(level: str, message: str, color: str = Colors.END):
        """Thread-safe logging"""
        with Logger._lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"{color}[{timestamp}] [{level}] {message}{Colors.END}")
    
    @staticmethod
    def info(msg: str):
        Logger.log("INFO", msg, Colors.CYAN)
    
    @staticmethod
    def success(msg: str):
        Logger.log("SUCCESS", msg, Colors.GREEN)
    
    @staticmethod
    def warning(msg: str):
        Logger.log("WARNING", msg, Colors.YELLOW)
    
    @staticmethod
    def error(msg: str):
        Logger.log("ERROR", msg, Colors.RED)
    
    @staticmethod
    def critical(msg: str):
        Logger.log("CRITICAL", msg, Colors.RED + Colors.BOLD)


class DataSanitizer:
    """Enhanced data sanitization and validation"""
    
    @staticmethod
    def sanitize_filename(name: str, max_length: int = 200) -> str:
        """Clean filename with length limit"""
        # Remove protocol
        name = re.sub(r'^https?://', '', name)
        name = re.sub(r'^www\.', '', name)
        # Replace invalid chars
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
        # Remove leading/trailing special chars
        name = name.strip('._- ')
        # Limit length
        if len(name) > max_length:
            name = name[:max_length]
        return name or "unknown"
    
    @staticmethod
    def sanitize_text(text: any, max_length: int = 500, 
                     placeholder: str = "[Content removed]") -> str:
        """Safe text conversion with encoding handling"""
        if text is None:
            return ""
        
        try:
            # Convert to string
            s = str(text)
            # Handle encoding issues
            s = s.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
            # Remove control characters except newlines/tabs
            s = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', s)
            # Truncate if needed
            if len(s) > max_length:
                s = s[:max_length] + "..."
            return s.strip()
        except:
            return placeholder
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    @staticmethod
    def extract_cves(text: str) -> List[str]:
        """Extract CVE identifiers"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))


# ==================== CORE SCANNER ====================

class OptimizedWebScanner:
    """High-performance web vulnerability scanner"""
    
    def __init__(self, domain: str, config: Optional[ScanConfig] = None):
        self.domain = domain
        self.config = config or ScanConfig()
        self.clean_domain = DataSanitizer.sanitize_filename(domain)
        
        # Directory structure
        self.output_dir = Path("scan_results")
        self.output_dir.mkdir(exist_ok=True)
        
        self.cache_dir = self.output_dir / "cache"
        self.cache_dir.mkdir(exist_ok=True)
        
        # Tool paths
        self.tools_dir = Path("tools")
        self.nuclei_bin = self.tools_dir / "nuclei.exe"
        self.templates_dir = self.tools_dir / "nuclei-templates"
        
        # Output files
        self.timestamp = datetime.now()
        ts_str = self.timestamp.strftime("%Y%m%d_%H%M%S")
        self.scan_output = self.output_dir / f"nuclei_{self.clean_domain}_{ts_str}.jsonl"
        self.pdf_output = self.output_dir / f"report_{self.clean_domain}_{ts_str}.pdf"
        self.json_output = self.output_dir / f"findings_{self.clean_domain}_{ts_str}.json"
        
        # Results storage
        self.vulnerabilities: List[Vulnerability] = []
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'templates_loaded': 0,
            'requests_sent': 0,
            'vulnerabilities_found': 0
        }
        
        # Thread-safe counters
        self._stats_lock = threading.Lock()
    
    def print_banner(self):
        """Display enhanced banner"""
        banner = f"""
{Colors.CYAN}{'='*80}
{Colors.BOLD}    WEB ASSET SECURITY SCANNER - OPTIMIZED PROFESSIONAL EDITION{Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.BOLD}Target:{Colors.END}          {self.domain}
{Colors.BOLD}Scan Date:{Colors.END}      {self.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
{Colors.BOLD}Severity Filter:{Colors.END} {', '.join(self.config.severity_levels).upper()}
{Colors.BOLD}Output Dir:{Colors.END}     {self.output_dir.absolute()}
{Colors.BOLD}Classification:{Colors.END} {Colors.RED}{self.config.report_classification}{Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
"""
        print(banner)
    
    def verify_environment(self) -> bool:
        """Comprehensive environment validation"""
        Logger.info("Verifying scan environment...")
        
        checks = [
            (self.nuclei_bin.exists(), f"Nuclei binary: {self.nuclei_bin}"),
            (self.templates_dir.exists(), f"Template directory: {self.templates_dir}"),
            (os.access(self.nuclei_bin, os.X_OK), "Nuclei execution permissions"),
        ]
        
        all_passed = True
        for passed, description in checks:
            if passed:
                Logger.success(f"✓ {description}")
            else:
                Logger.error(f"✗ {description}")
                all_passed = False
        
        # Check template count
        if self.templates_dir.exists():
            template_count = len(list(self.templates_dir.rglob("*.yaml")))
            Logger.info(f"Found {template_count} Nuclei templates")
            self.scan_stats['templates_loaded'] = template_count
        
        return all_passed
    
    def build_nuclei_command(self) -> List[str]:
        """Build optimized Nuclei command with best practices"""
        cmd = [
            str(self.nuclei_bin),
            "-u", self.domain,
            "-t", str(self.templates_dir),
            "-jsonl",
            "-o", str(self.scan_output),
            "-severity", ','.join(self.config.severity_levels),
            "-rl", str(self.config.rate_limit),  # Rate limiting
            "-c", str(self.config.max_workers),  # Concurrency
            "-timeout", "10",  # Per-request timeout
            "-retries", "2",  # Retry failed requests
            "-duc",  # Disable update check
            "-stats",  # Show statistics
            "-si", "10",  # Stats interval
            "-v",  # Verbose for better monitoring
        ]
        
        # Add tag exclusions
        if self.config.exclude_tags:
            cmd.extend(["-etags", ','.join(self.config.exclude_tags)])
        
        return cmd
    
    def run_nuclei_scan(self) -> bool:
        """Execute Nuclei with real-time monitoring"""
        Logger.info("Initializing Nuclei scanner...")
        
        cmd = self.build_nuclei_command()
        Logger.info(f"Command: {' '.join(cmd)}")
        
        self.scan_stats['start_time'] = datetime.now()
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            print(f"\n{Colors.YELLOW}[*] Scan Progress:{Colors.END}\n")
            
            # Real-time output processing
            for line in process.stdout:
                line = line.rstrip()
                if not line:
                    continue
                
                # Colorize output
                if '[critical]' in line.lower():
                    print(f"    {Colors.RED}{line}{Colors.END}")
                elif '[high]' in line.lower():
                    print(f"    {Colors.YELLOW}{line}{Colors.END}")
                elif '[medium]' in line.lower():
                    print(f"    {Colors.CYAN}{line}{Colors.END}")
                else:
                    print(f"    {line}")
            
            process.wait()
            
            self.scan_stats['end_time'] = datetime.now()
            self.scan_stats['duration'] = (
                self.scan_stats['end_time'] - self.scan_stats['start_time']
            ).total_seconds()
            
            if process.returncode != 0:
                Logger.error(f"Scan failed with exit code {process.returncode}")
                return False
            
            Logger.success(f"Scan completed in {self.scan_stats['duration']:.2f} seconds")
            return True
            
        except KeyboardInterrupt:
            Logger.warning("Scan interrupted by user")
            process.kill()
            return False
        except Exception as e:
            Logger.error(f"Scan error: {e}")
            return False
    
    def parse_results_optimized(self) -> bool:
        """Optimized JSONL parsing with validation"""
        Logger.info("Parsing scan results...")
        
        if not self.scan_output.exists():
            Logger.warning("No scan output file found")
            return True
        
        try:
            parsed_count = 0
            skipped_count = 0
            
            with open(self.scan_output, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        # Skip stats entries
                        if 'duration' in data and 'templates' in data:
                            continue
                        
                        # Validate vulnerability entry
                        if 'info' not in data:
                            skipped_count += 1
                            continue
                        
                        vuln = self._parse_vulnerability(data)
                        if vuln:
                            self.vulnerabilities.append(vuln)
                            parsed_count += 1
                        
                    except json.JSONDecodeError as e:
                        Logger.warning(f"Invalid JSON on line {line_num}: {e}")
                        skipped_count += 1
                        continue
            
            Logger.success(f"Parsed {parsed_count} vulnerabilities ({skipped_count} skipped)")
            self.scan_stats['vulnerabilities_found'] = len(self.vulnerabilities)
            
            # Display severity breakdown
            self._print_severity_summary()
            
            return True
            
        except Exception as e:
            Logger.error(f"Parse error: {e}")
            return False
    
    def _parse_vulnerability(self, data: Dict) -> Optional[Vulnerability]:
        """Parse single vulnerability with validation"""
        try:
            info = data.get('info', {})
            
            # Extract classification data
            classification = info.get('classification', {})
            cvss_metrics = classification.get('cvss-metrics', '')
            cvss_score = classification.get('cvss-score', 0.0)
            cve_ids = classification.get('cve-id', [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            
            # Extract all CVEs from description too
            description = info.get('description', '')
            cve_ids.extend(DataSanitizer.extract_cves(description))
            cve_ids = list(set(cve_ids))  # Deduplicate
            
            vuln = Vulnerability(
                name=DataSanitizer.sanitize_text(info.get('name', 'Unknown'), 200),
                severity=info.get('severity', 'unknown').lower(),
                template_id=info.get('id', 'N/A'),
                vuln_type=data.get('type', 'unknown'),
                matched_url=DataSanitizer.sanitize_text(
                    data.get('matched-at') or data.get('host', 'N/A'), 300
                ),
                description=DataSanitizer.sanitize_text(
                    description, self.config.max_description_length
                ),
                remediation=DataSanitizer.sanitize_text(
                    info.get('remediation', ''), 500
                ),
                references=info.get('reference', []),
                cvss_score=float(cvss_score) if cvss_score else 0.0,
                cve_ids=cve_ids,
                extracted_data=data.get('extracted-results', []),
                tags=info.get('tags', []),
                timestamp=datetime.now()
            )
            
            return vuln
            
        except Exception as e:
            Logger.warning(f"Failed to parse vulnerability: {e}")
            return None
    
    def _print_severity_summary(self):
        """Display colorized severity breakdown"""
        if not self.vulnerabilities:
            return
        
        severity_counts = Counter(v.severity for v in self.vulnerabilities)
        
        print(f"\n{Colors.BOLD}Severity Distribution:{Colors.END}")
        print("─" * 50)
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = Colors.severity_color(severity)
                bar = "█" * min(count, 50)
                print(f"{color}{severity.upper():8s} │ {bar} {count}{Colors.END}")
        
        print("─" * 50)
    
    def deduplicate_vulnerabilities(self):
        """Remove duplicate findings"""
        Logger.info("Deduplicating vulnerabilities...")
        
        original_count = len(self.vulnerabilities)
        seen = set()
        unique_vulns = []
        
        for vuln in self.vulnerabilities:
            # Create fingerprint
            fingerprint = (vuln.template_id, vuln.matched_url, vuln.severity)
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique_vulns.append(vuln)
        
        self.vulnerabilities = unique_vulns
        removed = original_count - len(unique_vulns)
        
        if removed > 0:
            Logger.info(f"Removed {removed} duplicate findings")
    
    def export_json_findings(self):
        """Export findings to JSON"""
        try:
            data = {
                'metadata': {
                    'target': self.domain,
                    'scan_date': self.timestamp.isoformat(),
                    'duration': self.scan_stats['duration'],
                    'total_findings': len(self.vulnerabilities)
                },
                'statistics': {
                    'severity_breakdown': dict(Counter(v.severity for v in self.vulnerabilities)),
                    'type_breakdown': dict(Counter(v.vuln_type for v in self.vulnerabilities))
                },
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
            }
            
            with open(self.json_output, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            Logger.success(f"JSON export: {self.json_output}")
            
        except Exception as e:
            Logger.error(f"JSON export failed: {e}")
    
    def generate_professional_pdf(self):
        """Generate enhanced PDF report"""
        Logger.info("Generating PDF report...")
        
        try:
            doc = SimpleDocTemplate(
                str(self.pdf_output),
                pagesize=A4,
                rightMargin=2*cm,
                leftMargin=2*cm,
                topMargin=2*cm,
                bottomMargin=2*cm,
                title=f"Security Report - {self.domain}",
                author=self.config.company_name
            )
            
            story = []
            styles = self._create_custom_styles()
            
            # Cover page
            story.extend(self._create_cover_page(styles))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(styles))
            story.append(PageBreak())
            
            # Severity distribution chart
            story.extend(self._create_severity_chart(styles))
            story.append(PageBreak())
            
            # Detailed findings
            story.extend(self._create_detailed_findings(styles))
            
            # Recommendations
            story.append(PageBreak())
            story.extend(self._create_recommendations(styles))
            
            # Build PDF
            doc.build(story)
            Logger.success(f"PDF report: {self.pdf_output}")
            
        except Exception as e:
            Logger.error(f"PDF generation failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _create_custom_styles(self) -> Dict:
        """Create custom PDF styles"""
        styles = getSampleStyleSheet()
        
        styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5
        ))
        
        styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        styles.add(ParagraphStyle(
            name='Classification',
            fontSize=9,
            textColor=colors.HexColor('#7f8c8d'),
            alignment=TA_RIGHT,
            fontName='Helvetica-Bold'
        ))
        
        return styles
    
    def _create_cover_page(self, styles) -> List:
        """Create professional cover page"""
        elements = []
        
        # Classification header
        elements.append(Paragraph(
            self.config.report_classification,
            styles['Classification']
        ))
        elements.append(Spacer(1, 2*cm))
        
        # Title
        elements.append(Paragraph(
            "Web Security Assessment Report",
            styles['ReportTitle']
        ))
        elements.append(Spacer(1, 1*cm))
        
        # Target info
        info_data = [
            ["Target Domain:", self.domain],
            ["Scan Date:", self.timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan Duration:", f"{self.scan_stats['duration']:.2f} seconds"],
            ["Total Findings:", str(len(self.vulnerabilities))],
            ["Scanner Version:", "Nuclei v3.x (Project Discovery)"],
            ["Report Generated By:", self.config.company_name]
        ]
        
        info_table = Table(info_data, colWidths=[6*cm, 9*cm])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 2*cm))
        
        # Disclaimer
        disclaimer = """
        <para alignment="justify">
        <b>CONFIDENTIALITY NOTICE:</b> This document contains sensitive security 
        information and is intended solely for authorized personnel. Unauthorized 
        disclosure, distribution, or reproduction is strictly prohibited.
        </para>
        """
        elements.append(Paragraph(disclaimer, styles['Normal']))
        
        return elements
    
    def _create_executive_summary(self, styles) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", styles['SectionHeader']))
        elements.append(Spacer(1, 0.5*cm))
        
        # Summary text
        severity_counts = Counter(v.severity for v in self.vulnerabilities)
        critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        
        summary_text = f"""
        <para alignment="justify">
        This security assessment identified <b>{len(self.vulnerabilities)} potential 
        vulnerabilities</b> across the target domain <b>{self.domain}</b>. 
        The scan utilized {self.scan_stats['templates_loaded']} detection templates 
        and completed in {self.scan_stats['duration']:.2f} seconds.
        </para>
        <para alignment="justify" spaceBefore="10">
        <b>Risk Level:</b> {'<font color="red">HIGH - Immediate action required</font>' 
        if critical_high > 0 else '<font color="orange">MEDIUM - Review recommended</font>'}
        </para>
        """
        clean_summary = re.sub(r'<para[^>]*>|</para>', '', summary_text)
        elements.append(Paragraph(clean_summary, styles['Normal']))

        elements.append(Spacer(1, 0.8*cm))
        
        # Severity table with colors
        summary_data = [["Severity", "Count", "Priority"]]
        
        severity_info = {
            'critical': ('IMMEDIATE', colors.red),
            'high': ('HIGH', colors.orangered),
            'medium': ('MEDIUM', colors.orange),
            'low': ('LOW', colors.yellow),
            'info': ('INFORMATIONAL', colors.lightblue)
        }
        
        for severity, (priority, color) in severity_info.items():
            count = severity_counts.get(severity, 0)
            summary_data.append([
                severity.upper(),
                str(count),
                priority
            ])
        
        summary_table = Table(summary_data, colWidths=[5*cm, 3*cm, 5*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Add row colors
        for i, (severity, (_, color)) in enumerate(severity_info.items(), 1):
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, i), (-1, i), color),
            ]))
        
        elements.append(summary_table)
        
        return elements
    
    def _create_severity_chart(self, styles) -> List:
        """Create severity distribution visualization"""
        elements = []
        
        elements.append(Paragraph("Risk Distribution Analysis", styles['SectionHeader']))
        elements.append(Spacer(1, 0.5*cm))
        
        # Calculate percentages
        total = len(self.vulnerabilities)
        severity_counts = Counter(v.severity for v in self.vulnerabilities)
        
        if total > 0:
            chart_data = []
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                percentage = (count / total) * 100
                chart_data.append([
                    severity.upper(),
                    str(count),
                    f"{percentage:.1f}%"
                ])
            
            chart_table = Table(
                [["Severity", "Count", "Percentage"]] + chart_data,
                colWidths=[5*cm, 4*cm, 4*cm]
            )
            chart_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ]))
            
            elements.append(chart_table)
        
        return elements
    
    def _create_detailed_findings(self, styles) -> List:
        """Create detailed vulnerability listings"""
        elements = []
        
        elements.append(Paragraph("Detailed Vulnerability Findings", styles['SectionHeader']))
        elements.append(Spacer(1, 0.5*cm))
        
        if not self.vulnerabilities:
            elements.append(Paragraph(
                "No vulnerabilities were identified during this assessment.",
                styles['Normal']
            ))
            return elements
        
        # Group by severity
        by_severity = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_severity[vuln.severity].append(vuln)
        
        # Process each severity level
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = by_severity.get(severity, [])
            if not vulns:
                continue
            
            # Limit findings per severity
            vulns = vulns[:self.config.max_findings_per_severity]
            
            elements.append(Paragraph(
                f"{severity.upper()} Severity ({len(vulns)} findings)",
                styles['Heading2']
            ))
            elements.append(Spacer(1, 0.3*cm))
            
            for idx, vuln in enumerate(vulns, 1):
                vuln_elements = self._format_vulnerability(vuln, idx, styles)
                elements.extend(vuln_elements)
                elements.append(Spacer(1, 0.5*cm))
            
            if len(by_severity[severity]) > self.config.max_findings_per_severity:
                remaining = len(by_severity[severity]) - self.config.max_findings_per_severity
                elements.append(Paragraph(
                    f"<i>+ {remaining} additional {severity} findings (see JSON export)</i>",
                    styles['Normal']
                ))
            
            elements.append(Spacer(1, 0.8*cm))
        
        return elements
    
    def _format_vulnerability(self, vuln: Vulnerability, idx: int, styles) -> List:
        """Format single vulnerability entry"""
        elements = []
        
        # Title
        title = f"{idx}. {vuln.name}"
        elements.append(Paragraph(title, styles['VulnTitle']))
        
        # Details table
        details_data = [
            ["Severity:", vuln.severity.upper()],
            ["Template ID:", vuln.template_id],
            ["Type:", vuln.vuln_type],
            ["Affected URL:", vuln.matched_url[:100] + "..." if len(vuln.matched_url) > 100 else vuln.matched_url],
        ]
        
        if vuln.cvss_score > 0:
            details_data.append(["CVSS Score:", f"{vuln.cvss_score:.1f}"])
        
        if vuln.cve_ids:
            details_data.append(["CVE IDs:", ", ".join(vuln.cve_ids[:5])])
        
        if vuln.extracted_data:
            extracted = ", ".join(str(e)[:50] for e in vuln.extracted_data[:3])
            details_data.append(["Extracted Data:", extracted])
        
        details_table = Table(details_data, colWidths=[4*cm, 11*cm])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(details_table)
        
        # Description
        if vuln.description:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("<b>Description:</b>", styles['Normal']))
            elements.append(Paragraph(vuln.description, styles['Normal']))
        
        # Remediation
        if vuln.remediation:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
            elements.append(Paragraph(vuln.remediation, styles['Normal']))
        
        # References
        if vuln.references:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("<b>References:</b>", styles['Normal']))
            ref_items = []
            for ref in vuln.references[:5]:
                ref_items.append(ListItem(
                    Paragraph(f'<link href="{ref}">{ref}</link>', styles['Normal']),
                    leftIndent=20
                ))
            if ref_items:
                elements.append(ListFlowable(ref_items, bulletType='bullet'))
        
        return elements
    
    def _create_recommendations(self, styles) -> List:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph("Security Recommendations", styles['SectionHeader']))
        elements.append(Spacer(1, 0.5*cm))
        
        recommendations = [
            ("Immediate Actions", [
                "Address all CRITICAL and HIGH severity findings within 24-48 hours",
                "Implement temporary mitigations for exploitable vulnerabilities",
                "Restrict access to sensitive endpoints until patches are applied",
                "Enable comprehensive security logging and monitoring"
            ]),
            ("Short-term (1-2 weeks)", [
                "Patch all identified software vulnerabilities",
                "Review and harden web server configurations",
                "Implement Web Application Firewall (WAF) rules",
                "Conduct authentication and authorization review",
                "Enable HTTPS with strong TLS configurations"
            ]),
            ("Long-term (1-3 months)", [
                "Establish regular vulnerability scanning schedule (weekly/monthly)",
                "Implement Security Development Lifecycle (SDL) practices",
                "Conduct security awareness training for development teams",
                "Deploy intrusion detection/prevention systems (IDS/IPS)",
                "Establish incident response procedures",
                "Implement automated security testing in CI/CD pipeline"
            ])
        ]
        
        for category, items in recommendations:
            elements.append(Paragraph(f"<b>{category}</b>", styles['Heading3']))
            rec_items = []
            for item in items:
                rec_items.append(ListItem(
                    Paragraph(item, styles['Normal']),
                    leftIndent=20
                ))
            elements.append(ListFlowable(rec_items, bulletType='bullet'))
            elements.append(Spacer(1, 0.5*cm))
        
        return elements
    
    def run(self) -> bool:
        """Execute complete scan workflow"""
        self.print_banner()
        
        # Phase 1: Environment verification
        if not self.verify_environment():
            Logger.critical("Environment validation failed")
            return False
        
        # Phase 2: Execute scan
        if not self.run_nuclei_scan():
            Logger.critical("Scan execution failed")
            return False
        
        # Phase 3: Parse results
        if not self.parse_results_optimized():
            Logger.critical("Results parsing failed")
            return False
        
        # Phase 4: Post-processing
        self.deduplicate_vulnerabilities()
        
        # Phase 5: Export results
        self.export_json_findings()
        self.generate_professional_pdf()
        
        # Final summary
        self._print_final_summary()
        
        return True
    
    def _print_final_summary(self):
        """Print comprehensive scan summary"""
        print(f"\n{Colors.GREEN}{'='*80}")
        print(f"{Colors.BOLD}SCAN COMPLETED SUCCESSFULLY{Colors.END}")
        print(f"{Colors.GREEN}{'='*80}{Colors.END}\n")
        
        summary_items = [
            ("Target", self.domain),
            ("Duration", f"{self.scan_stats['duration']:.2f} seconds"),
            ("Templates Used", str(self.scan_stats['templates_loaded'])),
            ("Vulnerabilities Found", str(len(self.vulnerabilities))),
            ("PDF Report", str(self.pdf_output)),
            ("JSON Export", str(self.json_output)),
        ]
        
        for label, value in summary_items:
            print(f"  {Colors.CYAN}{label:20s}{Colors.END} : {value}")
        
        print(f"\n{Colors.GREEN}{'='*80}{Colors.END}\n")


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point with argument parsing"""
    
    if len(sys.argv) < 2:
        print(f"""
{Colors.CYAN}{'='*80}
    WEB ASSET SECURITY SCANNER - OPTIMIZED EDITION
{'='*80}{Colors.END}

{Colors.BOLD}Usage:{Colors.END}
    python {sys.argv[0]} <domain> [options]

{Colors.BOLD}Examples:{Colors.END}
    python {sys.argv[0]} example.com
    python {sys.argv[0]} https://example.com

{Colors.BOLD}Features:{Colors.END}
    • Offline vulnerability scanning with Nuclei
    • Professional PDF report generation
    • JSON export for integration
    • Real-time scan monitoring
    • Deduplication and optimization
    • CVSS scoring and CVE tracking

{Colors.BOLD}Requirements:{Colors.END}
    • Nuclei binary in tools/nuclei.exe
    • Templates in tools/nuclei-templates/
    • Python packages: reportlab, tqdm

{Colors.CYAN}{'='*80}{Colors.END}
""")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    # Optional: Load custom config
    config = ScanConfig()
    
    try:
        scanner = OptimizedWebScanner(domain, config)
        success = scanner.run()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        Logger.warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        Logger.critical(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
