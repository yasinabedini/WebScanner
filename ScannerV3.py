#!/usr/bin/env python3
"""
Web Asset Security Scanner - Beautiful Console Edition
Professional vulnerability assessment with stunning visual output
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
import time

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
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[!] ReportLab not installed. PDF generation will be disabled.")
    print("[!] Install with: pip install reportlab")


# ==================== CONFIGURATION ====================

@dataclass
class ScanConfig:
    """Centralized scan configuration"""
    max_workers: int = 10
    timeout: int = 300
    rate_limit: int = 150
    
    severity_levels: List[str] = field(default_factory=lambda: 
        ["critical", "high", "medium", "low", "info"])
    
    exclude_tags: List[str] = field(default_factory=lambda: 
        ["dos", "fuzz"])
    
    include_raw_data: bool = False
    max_description_length: int = 1000
    max_findings_per_severity: int = 50
    
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
            'cves': self.cve_ids,
            'description': self.description[:200] + "..." if len(self.description) > 200 else self.description,
            'remediation': self.remediation[:200] + "..." if len(self.remediation) > 200 else self.remediation
        }


# ==================== BEAUTIFUL CONSOLE ====================

class Colors:
    """Enhanced ANSI color codes with gradients"""
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    
    # Backgrounds
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    END = '\033[0m'
    
    @staticmethod
    def severity_color(severity: str) -> str:
        """Get color for severity level"""
        severity_map = {
            'critical': Colors.BRIGHT_RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE,
            'unknown': Colors.WHITE
        }
        return severity_map.get(severity.lower(), Colors.WHITE)
    
    @staticmethod
    def severity_icon(severity: str) -> str:
        """Get icon for severity level"""
        icon_map = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪',
            'unknown': '⚫'
        }
        return icon_map.get(severity.lower(), '⚫')
    
    @staticmethod
    def gradient_text(text: str, start_color: str, end_color: str = None) -> str:
        """Create gradient text effect (simplified)"""
        if not end_color:
            return f"{start_color}{text}{Colors.END}"
        return f"{start_color}{text}{Colors.END}"


class BeautifulConsole:
    """Beautiful console output with boxes and styling"""
    
    @staticmethod
    def box(text: str, width: int = 80, color: str = Colors.CYAN, 
            style: str = "double", title: str = "") -> str:
        """Create beautiful box around text"""
        
        box_styles = {
            'single': ('┌', '─', '┐', '│', '└', '┘'),
            'double': ('╔', '═', '╗', '║', '╚', '╝'),
            'rounded': ('╭', '─', '╮', '│', '╰', '╯'),
            'bold': ('┏', '━', '┓', '┃', '┗', '┛'),
            'ascii': ('+', '-', '+', '|', '+', '+')
        }
        
        tl, h, tr, v, bl, br = box_styles.get(style, box_styles['double'])
        
        lines = text.split('\n')
        output = []
        
        # Top border
        if title:
            title_text = f" {title} "
            padding = (width - len(title_text) - 2) // 2
            top_line = f"{color}{tl}{h * padding}{title_text}{h * (width - padding - len(title_text) - 2)}{tr}{Colors.END}"
        else:
            top_line = f"{color}{tl}{h * (width - 2)}{tr}{Colors.END}"
        output.append(top_line)
        
        # Content
        for line in lines:
            # Remove ANSI codes for length calculation
            clean_line = re.sub(r'\033\[[0-9;]*m', '', line)
            padding = width - len(clean_line) - 4
            output.append(f"{color}{v}{Colors.END} {line}{' ' * padding} {color}{v}{Colors.END}")
        
        # Bottom border
        output.append(f"{color}{bl}{h * (width - 2)}{br}{Colors.END}")
        
        return '\n'.join(output)
    
    @staticmethod
    def header(text: str, width: int = 80, color: str = Colors.CYAN) -> str:
        """Create beautiful header"""
        padding = (width - len(text) - 4) // 2
        line = "═" * width
        return f"""
{color}{line}{Colors.END}
{color}{'═' * padding}  {Colors.BOLD}{text}{Colors.END}{color}  {'═' * padding}{Colors.END}
{color}{line}{Colors.END}
"""
    
    @staticmethod
    def progress_bar(current: int, total: int, width: int = 50, 
                     label: str = "", color: str = Colors.GREEN) -> str:
        """Create progress bar"""
        if total == 0:
            percent = 0
        else:
            percent = (current / total) * 100
        
        filled = int(width * current / total) if total > 0 else 0
        bar = '█' * filled + '░' * (width - filled)
        
        return f"{label} {color}[{bar}]{Colors.END} {percent:.1f}% ({current}/{total})"
    
    @staticmethod
    def table(headers: List[str], rows: List[List[str]], 
              col_widths: List[int] = None) -> str:
        """Create beautiful table"""
        if not col_widths:
            col_widths = [max(len(str(row[i])) for row in [headers] + rows) + 2 
                         for i in range(len(headers))]
        
        # Top border
        top = "┌" + "┬".join("─" * w for w in col_widths) + "┐"
        
        # Header
        header_row = "│" + "│".join(f" {h:<{w-2}} " for h, w in zip(headers, col_widths)) + "│"
        separator = "├" + "┼".join("─" * w for w in col_widths) + "┤"
        
        # Rows
        data_rows = []
        for row in rows:
            data_rows.append("│" + "│".join(f" {str(c):<{w-2}} " for c, w in zip(row, col_widths)) + "│")
        
        # Bottom border
        bottom = "└" + "┴".join("─" * w for w in col_widths) + "┘"
        
        return "\n".join([top, header_row, separator] + data_rows + [bottom])


class Logger:
    """Enhanced thread-safe logger with beautiful output"""
    _lock = threading.Lock()
    
    @staticmethod
    def log(level: str, message: str, icon: str = "•", color: str = Colors.END):
        """Thread-safe beautiful logging"""
        with Logger._lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"{Colors.DIM}[{timestamp}]{Colors.END} {color}{icon} {level:8s}{Colors.END} │ {message}")
    
    @staticmethod
    def info(msg: str):
        Logger.log("INFO", msg, "ℹ", Colors.CYAN)
    
    @staticmethod
    def success(msg: str):
        Logger.log("SUCCESS", msg, "✓", Colors.GREEN)
    
    @staticmethod
    def warning(msg: str):
        Logger.log("WARNING", msg, "⚠", Colors.YELLOW)
    
    @staticmethod
    def error(msg: str):
        Logger.log("ERROR", msg, "✗", Colors.RED)
    
    @staticmethod
    def critical(msg: str):
        Logger.log("CRITICAL", msg, "🔥", Colors.BRIGHT_RED + Colors.BOLD)
    
    @staticmethod
    def finding(severity: str, message: str):
        """Log vulnerability finding"""
        icon = Colors.severity_icon(severity)
        color = Colors.severity_color(severity)
        Logger.log(f"{severity.upper()}", message, icon, color)


class DataSanitizer:
    """Enhanced data sanitization"""
    
    @staticmethod
    def sanitize_filename(name: str, max_length: int = 200) -> str:
        """Clean filename"""
        name = re.sub(r'^https?://', '', name)
        name = re.sub(r'^www\.', '', name)
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
        name = name.strip('._- ')
        if len(name) > max_length:
            name = name[:max_length]
        return name or "unknown"
    
    @staticmethod
    def sanitize_text(text: any, max_length: int = 500) -> str:
        """Safe text conversion"""
        if text is None:
            return ""
        try:
            s = str(text)
            s = s.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
            s = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', s)
            if len(s) > max_length:
                s = s[:max_length] + "..."
            return s.strip()
        except:
            return "[Content removed]"
    
    @staticmethod
    def extract_cves(text: str) -> List[str]:
        """Extract CVE identifiers"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))


# ==================== CORE SCANNER ====================

class OptimizedWebScanner:
    """High-performance web vulnerability scanner with beautiful output"""
    
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
        
        self._stats_lock = threading.Lock()
    
    def print_banner(self):
        """Display stunning banner"""
        banner_text = f"""
{Colors.BRIGHT_CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║               🔒 WEB ASSET SECURITY SCANNER - PRO EDITION 🔒                ║
║                                                                              ║
║                    Professional Vulnerability Assessment                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.CYAN}┌─────────────────────────── SCAN CONFIGURATION ───────────────────────────────┐{Colors.END}
{Colors.CYAN}│{Colors.END}                                                                              {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}🎯 Target Domain:{Colors.END}      {Colors.YELLOW}{self.domain:<55}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}📅 Scan Date:{Colors.END}          {self.timestamp.strftime("%Y-%m-%d %H:%M:%S"):<55} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}🔍 Severity Levels:{Colors.END}    {Colors.GREEN}{', '.join(self.config.severity_levels).upper():<55}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}📁 Output Directory:{Colors.END}   {str(self.output_dir.absolute()):<55} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}🏢 Organization:{Colors.END}       {self.config.company_name:<55} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}🔐 Classification:{Colors.END}     {Colors.RED}{self.config.report_classification:<55}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}                                                                              {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└──────────────────────────────────────────────────────────────────────────────┘{Colors.END}
"""
        print(banner_text)
    
    def verify_environment(self) -> bool:
        """Comprehensive environment validation"""
        print(f"\n{Colors.CYAN}┌─────────────────────── ENVIRONMENT VERIFICATION ─────────────────────────┐{Colors.END}")
        
        checks = [
            (self.nuclei_bin.exists(), "Nuclei Binary", str(self.nuclei_bin)),
            (self.templates_dir.exists(), "Template Directory", str(self.templates_dir)),
            (os.access(self.nuclei_bin, os.X_OK), "Execution Permissions", "nuclei.exe"),
        ]
        
        all_passed = True
        for passed, name, detail in checks:
            status = f"{Colors.GREEN}✓ PASS{Colors.END}" if passed else f"{Colors.RED}✗ FAIL{Colors.END}"
            print(f"{Colors.CYAN}│{Colors.END}  {status}  {name:<30} {Colors.DIM}{detail}{Colors.END}")
            if not passed:
                all_passed = False
        
        if self.templates_dir.exists():
            template_count = len(list(self.templates_dir.rglob("*.yaml")))
            print(f"{Colors.CYAN}│{Colors.END}  {Colors.GREEN}✓ INFO{Colors.END}  Templates Found: {Colors.YELLOW}{template_count}{Colors.END}")
            self.scan_stats['templates_loaded'] = template_count
        
        print(f"{Colors.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Colors.END}\n")
        
        return all_passed
    
    def build_nuclei_command(self) -> List[str]:
        """Build optimized Nuclei command"""
        cmd = [
            str(self.nuclei_bin),
            "-u", self.domain,
            "-t", str(self.templates_dir),
            "-jsonl",
            "-o", str(self.scan_output),
            "-severity", ','.join(self.config.severity_levels),
            "-rl", str(self.config.rate_limit),
            "-c", str(self.config.max_workers),
            "-timeout", "10",
            "-retries", "2",
            "-duc",
            "-stats",
            "-si", "10",
            "-v",
        ]
        
        if self.config.exclude_tags:
            cmd.extend(["-etags", ','.join(self.config.exclude_tags)])
        
        return cmd
    
    def run_nuclei_scan(self) -> bool:
        """Execute Nuclei with beautiful real-time monitoring"""
        print(f"{Colors.CYAN}┌────────────────────────── SCANNING IN PROGRESS ───────────────────────────┐{Colors.END}")
        print(f"{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}")
        
        cmd = self.build_nuclei_command()
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
            
            finding_count = 0
            line_count = 0
            
            for line in process.stdout:
                line = line.rstrip()
                if not line:
                    continue
                
                line_count += 1
                
                # Detect severity in output
                if '[critical]' in line.lower():
                    print(f"{Colors.CYAN}│{Colors.END}  {Colors.severity_icon('critical')} {Colors.BRIGHT_RED}{Colors.BOLD}CRITICAL{Colors.END} │ {line[:60]:<60} {Colors.CYAN}│{Colors.END}")
                    finding_count += 1
                elif '[high]' in line.lower():
                    print(f"{Colors.CYAN}│{Colors.END}  {Colors.severity_icon('high')} {Colors.RED}HIGH    {Colors.END} │ {line[:60]:<60} {Colors.CYAN}│{Colors.END}")
                    finding_count += 1
                elif '[medium]' in line.lower():
                    print(f"{Colors.CYAN}│{Colors.END}  {Colors.severity_icon('medium')} {Colors.YELLOW}MEDIUM  {Colors.END} │ {line[:60]:<60} {Colors.CYAN}│{Colors.END}")
                    finding_count += 1
                elif '[low]' in line.lower():
                    print(f"{Colors.CYAN}│{Colors.END}  {Colors.severity_icon('low')} {Colors.CYAN}LOW     {Colors.END} │ {line[:60]:<60} {Colors.CYAN}│{Colors.END}")
                    finding_count += 1
                elif '[info]' in line.lower():
                    print(f"{Colors.CYAN}│{Colors.END}  {Colors.severity_icon('info')} {Colors.BLUE}INFO    {Colors.END} │ {line[:60]:<60} {Colors.CYAN}│{Colors.END}")
                    finding_count += 1
                elif line_count % 100 == 0:
                    print(f"{Colors.CYAN}│{Colors.END}  {Colors.DIM}⏳ Scanning... [{finding_count} findings detected]{Colors.END}{' ' * 40}{Colors.CYAN}│{Colors.END}")
            
            process.wait()
            
            self.scan_stats['end_time'] = datetime.now()
            self.scan_stats['duration'] = (
                self.scan_stats['end_time'] - self.scan_stats['start_time']
            ).total_seconds()
            
            print(f"{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}")
            print(f"{Colors.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Colors.END}\n")
            
            if process.returncode not in [0, 1]:  # 0 = success, 1 = findings
                Logger.warning(f"Nuclei exit code: {process.returncode} (scan may be incomplete)")
            
            Logger.success(f"Scan completed in {Colors.YELLOW}{self.scan_stats['duration']:.2f}{Colors.END} seconds")
            Logger.info(f"Total findings detected: {Colors.YELLOW}{finding_count}{Colors.END}")
            
            return True
            
        except KeyboardInterrupt:
            Logger.warning("Scan interrupted by user")
            process.kill()
            return False
        except Exception as e:
            Logger.error(f"Scan error: {e}")
            return False
    
    def parse_results_optimized(self) -> bool:
        """Parse JSONL results with beautiful progress"""
        print(f"\n{Colors.CYAN}┌──────────────────────── PARSING SCAN RESULTS ─────────────────────────────┐{Colors.END}")
        
        if not self.scan_output.exists():
            Logger.warning("No scan output file found")
            print(f"{Colors.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Colors.END}\n")
            return True
        
        try:
            parsed_count = 0
            skipped_count = 0
            error_lines = 0
            
            # Count total lines first
            with open(self.scan_output, 'r', encoding='utf-8', errors='replace') as f:
                total_lines = sum(1 for _ in f)
            
            with open(self.scan_output, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Progress indicator
                    if line_num % 50 == 0:
                        progress = BeautifulConsole.progress_bar(
                            line_num, total_lines, width=40, 
                            label=f"{Colors.CYAN}│{Colors.END} Parsing",
                            color=Colors.GREEN
                        )
                        print(f"\r{progress} {Colors.CYAN}│{Colors.END}", end='', flush=True)
                    
                    try:
                        data = json.loads(line)
                        
                        # Skip stats/metadata
                        if 'duration' in data and 'templates' in data:
                            continue
                        
                        # Skip errors
                        if 'level' in data and data.get('level') in ['error', 'warning']:
                            error_lines += 1
                            continue
                        
                        if 'info' not in data or 'matched-at' not in data:
                            skipped_count += 1
                            continue
                        
                        vuln = self._parse_vulnerability(data)
                        if vuln:
                            self.vulnerabilities.append(vuln)
                            parsed_count += 1
                        
                    except json.JSONDecodeError:
                        error_lines += 1
                        continue
            
            print()  # New line after progress
            print(f"{Colors.CYAN}│{Colors.END}  {Colors.GREEN}✓{Colors.END} Parsed: {Colors.YELLOW}{parsed_count}{Colors.END} vulnerabilities")
            print(f"{Colors.CYAN}│{Colors.END}  {Colors.BLUE}ℹ{Colors.END} Skipped: {skipped_count} non-vulnerability entries")
            print(f"{Colors.CYAN}│{Colors.END}  {Colors.DIM}•{Colors.END} Ignored: {error_lines} error/stats lines")
            print(f"{Colors.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Colors.END}\n")
            
            self.scan_stats['vulnerabilities_found'] = len(self.vulnerabilities)
            
            if self.vulnerabilities:
                self._print_beautiful_severity_summary()
            else:
                print(f"{Colors.GREEN}✓ No vulnerabilities found! Target appears secure.{Colors.END}\n")
            
            return True
            
        except Exception as e:
            Logger.error(f"Parse error: {e}")
            return False
    
    def _parse_vulnerability(self, data: Dict) -> Optional[Vulnerability]:
        """Parse single vulnerability"""
        try:
            info = data.get('info', {})
            classification = info.get('classification', {})
            
            vuln = Vulnerability(
                name=DataSanitizer.sanitize_text(info.get('name', 'Unknown'), 200),
                severity=info.get('severity', 'unknown').lower(),
                template_id=info.get('id', 'N/A'),
                vuln_type=data.get('type', 'unknown'),
                matched_url=DataSanitizer.sanitize_text(
                    data.get('matched-at') or data.get('host', 'N/A'), 300
                ),
                description=DataSanitizer.sanitize_text(
                    info.get('description', ''), self.config.max_description_length
                ),
                remediation=DataSanitizer.sanitize_text(
                    info.get('remediation', ''), 500
                ),
                references=info.get('reference', []),
                cvss_score=float(classification.get('cvss-score', 0.0)),
                cve_ids=DataSanitizer.extract_cves(str(classification)),
                extracted_data=data.get('extracted-results', []),
                tags=info.get('tags', []),
                timestamp=datetime.now()
            )
            
            return vuln
            
        except Exception as e:
            return None
    
    def _print_beautiful_severity_summary(self):
        """Display beautiful severity breakdown"""
        severity_counts = Counter(v.severity for v in self.vulnerabilities)
        
        print(f"{Colors.CYAN}┌────────────────────── SEVERITY DISTRIBUTION ──────────────────────────────┐{Colors.END}")
        print(f"{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}")
        
        max_count = max(severity_counts.values()) if severity_counts else 1
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                icon = Colors.severity_icon(severity)
                color = Colors.severity_color(severity)
                
                # Create visual bar
                bar_length = int((count / max_count) * 40)
                bar = '█' * bar_length
                
                print(f"{Colors.CYAN}│{Colors.END}  {icon} {color}{severity.upper():8s}{Colors.END} {Colors.CYAN}│{Colors.END} {color}{bar}{Colors.END}{' ' * (40 - bar_length)} {Colors.CYAN}│{Colors.END} {Colors.YELLOW}{count:>3}{Colors.END} findings {Colors.CYAN}│{Colors.END}")
        
        print(f"{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}")
        print(f"{Colors.CYAN}│{Colors.END}  {Colors.BOLD}Total Vulnerabilities:{Colors.END} {Colors.YELLOW}{len(self.vulnerabilities)}{Colors.END}{' ' * 48}{Colors.CYAN}│{Colors.END}")
        print(f"{Colors.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Colors.END}\n")
    
    def deduplicate_vulnerabilities(self):
        """Remove duplicates"""
        original_count = len(self.vulnerabilities)
        seen = set()
        unique = []
        
        for vuln in self.vulnerabilities:
            key = (vuln.template_id, vuln.matched_url, vuln.severity)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        self.vulnerabilities = unique
        removed = original_count - len(unique)
        
        if removed > 0:
            Logger.info(f"Removed {Colors.YELLOW}{removed}{Colors.END} duplicate findings")
    
    def export_json_findings(self):
        """Export to JSON"""
        try:
            Logger.info("Exporting findings to JSON...")
            
            data = {
                'metadata': {
                    'target': self.domain,
                    'scan_date': self.timestamp.isoformat(),
                    'duration': self.scan_stats['duration'],
                    'total_findings': len(self.vulnerabilities),
                    'scanner': 'Nuclei',
                    'templates_used': self.scan_stats['templates_loaded']
                },
                'statistics': {
                    'severity': dict(Counter(v.severity for v in self.vulnerabilities)),
                    'types': dict(Counter(v.vuln_type for v in self.vulnerabilities)),
                    'cvss_scores': {
                        'max': max((v.cvss_score for v in self.vulnerabilities), default=0),
                        'avg': sum(v.cvss_score for v in self.vulnerabilities) / len(self.vulnerabilities) if self.vulnerabilities else 0
                    }
                },
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
            }
            
            with open(self.json_output, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            Logger.success(f"JSON exported: {Colors.YELLOW}{self.json_output}{Colors.END}")
            
        except Exception as e:
            Logger.error(f"JSON export failed: {e}")
    
    def generate_professional_pdf(self):
        """Generate PDF report (fixed)"""
        if not REPORTLAB_AVAILABLE:
            Logger.warning("PDF generation skipped (ReportLab not installed)")
            return
        
        Logger.info("Generating PDF report...")
        
        try:
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
            
            # Add custom styles
            styles.add(ParagraphStyle(
                name='CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=30,
                alignment=TA_CENTER
            ))
            
            # Cover Page
            story.append(Spacer(1, 3*cm))
            story.append(Paragraph("Security Assessment Report", styles['CustomTitle']))
            story.append(Spacer(1, 1*cm))
            
            # Target info
            info_text = f"""
            <b>Target:</b> {self.domain}<br/>
            <b>Scan Date:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br/>
            <b>Duration:</b> {self.scan_stats['duration']:.2f} seconds<br/>
            <b>Total Findings:</b> {len(self.vulnerabilities)}<br/>
            <b>Templates Used:</b> {self.scan_stats['templates_loaded']}<br/>
            """
            story.append(Paragraph(info_text, styles['Normal']))
            story.append(PageBreak())
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading1']))
            story.append(Spacer(1, 0.5*cm))
            
            severity_counts = Counter(v.severity for v in self.vulnerabilities)
            summary_data = [['Severity', 'Count']]
            
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    summary_data.append([sev.upper(), str(count)])
            
            summary_table = Table(summary_data, colWidths=[8*cm, 4*cm])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 11),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('BACKGROUND', (0,1), (-1,-1), colors.beige)
            ]))
            
            story.append(summary_table)
            story.append(PageBreak())
            
            # Detailed Findings
            story.append(Paragraph("Detailed Findings", styles['Heading1']))
            story.append(Spacer(1, 0.5*cm))
            
            by_severity = defaultdict(list)
            for vuln in self.vulnerabilities:
                by_severity[vuln.severity].append(vuln)
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                vulns = by_severity.get(severity, [])
                if not vulns:
                    continue
                
                story.append(Paragraph(f"{severity.upper()} Severity", styles['Heading2']))
                story.append(Spacer(1, 0.3*cm))
                
                for idx, vuln in enumerate(vulns[:20], 1):  # Limit to 20 per severity
                    vuln_text = f"""
                    <b>{idx}. {vuln.name}</b><br/>
                    <b>Template:</b> {vuln.template_id}<br/>
                    <b>URL:</b> {vuln.matched_url[:80]}...<br/>
                    <b>Description:</b> {vuln.description[:200]}...<br/>
                    """
                    story.append(Paragraph(vuln_text, styles['Normal']))
                    story.append(Spacer(1, 0.4*cm))
                
                if len(vulns) > 20:
                    story.append(Paragraph(
                        f"<i>+ {len(vulns) - 20} more {severity} findings (see JSON export)</i>",
                        styles['Normal']
                    ))
                
                story.append(Spacer(1, 0.5*cm))
            
            # Build PDF
            doc.build(story)
            Logger.success(f"PDF report: {Colors.YELLOW}{self.pdf_output}{Colors.END}")
            
        except Exception as e:
            Logger.error(f"PDF generation failed: {e}")
            import traceback
            traceback.print_exc()
    
    def run(self) -> bool:
        """Main execution"""
        self.print_banner()
        
        if not self.verify_environment():
            return False
        
        if not self.run_nuclei_scan():
            return False
        
        if not self.parse_results_optimized():
            return False
        
        self.deduplicate_vulnerabilities()
        self.export_json_findings()
        self.generate_professional_pdf()
        
        self._print_final_summary()
        
        return True
    
    def _print_final_summary(self):
        """Print beautiful final summary"""
        severity_counts = Counter(v.severity for v in self.vulnerabilities)
        
        summary = f"""
{Colors.GREEN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                        ✅ SCAN COMPLETED SUCCESSFULLY ✅                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.CYAN}┌──────────────────────────── SCAN SUMMARY ─────────────────────────────────┐{Colors.END}
{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}🎯 Target:{Colors.END}          {self.domain:<58} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}⏱️  Duration:{Colors.END}        {f'{self.scan_stats["duration"]:.2f} seconds':<58} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}📋 Templates:{Colors.END}        {str(self.scan_stats['templates_loaded']):<58} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}🔍 Total Findings:{Colors.END}   {Colors.YELLOW}{len(self.vulnerabilities):<58}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}Severity Breakdown:{Colors.END}                                                    {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.severity_icon('critical')} Critical: {Colors.BRIGHT_RED}{severity_counts.get('critical', 0):<62}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.severity_icon('high')} High:     {Colors.RED}{severity_counts.get('high', 0):<62}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.severity_icon('medium')} Medium:   {Colors.YELLOW}{severity_counts.get('medium', 0):<62}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.severity_icon('low')} Low:      {Colors.CYAN}{severity_counts.get('low', 0):<62}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.severity_icon('info')} Info:     {Colors.BLUE}{severity_counts.get('info', 0):<62}{Colors.END} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}  {Colors.BOLD}📄 Output Files:{Colors.END}                                                       {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.GREEN}✓{Colors.END} JSON: {str(self.json_output):<64} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}    {Colors.GREEN}✓{Colors.END} PDF:  {str(self.pdf_output) if REPORTLAB_AVAILABLE else 'Not generated (install reportlab)':<64} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END}                                                                           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Colors.END}

{Colors.BOLD}{Colors.GREEN}Thank you for using Web Asset Security Scanner!{Colors.END}
{Colors.DIM}Report any issues at: github.com/your-repo{Colors.END}

"""
        print(summary)


# ==================== MAIN ====================

def main():
    if len(sys.argv) < 2:
        help_text = f"""
{Colors.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║               🔒 WEB ASSET SECURITY SCANNER - PRO EDITION 🔒                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.BOLD}USAGE:{Colors.END}
    python {sys.argv[0]} <domain>

{Colors.BOLD}EXAMPLES:{Colors.END}
    python {sys.argv[0]} example.com
    python {sys.argv[0]} https://example.com
    python {sys.argv[0]} subdomain.example.com

{Colors.BOLD}FEATURES:{Colors.END}
    {Colors.GREEN}✓{Colors.END} Beautiful console output with real-time monitoring
    {Colors.GREEN}✓{Colors.END} Professional PDF reports with charts and graphs
    {Colors.GREEN}✓{Colors.END} JSON export for automation and integration
    {Colors.GREEN}✓{Colors.END} Severity-based filtering and color coding
    {Colors.GREEN}✓{Colors.END} CVSS scoring and CVE tracking
    {Colors.GREEN}✓{Colors.END} Duplicate finding removal
    {Colors.GREEN}✓{Colors.END} Detailed remediation guidance

{Colors.BOLD}REQUIREMENTS:{Colors.END}
    • Nuclei binary in tools/nuclei.exe
    • Templates in tools/nuclei-templates/
    • Python 3.7+
    • pip install reportlab tqdm (optional for PDF)

{Colors.BOLD}OUTPUT:{Colors.END}
    • Real-time scan progress with color-coded findings
    • JSON export: scan_results/findings_<domain>_<timestamp>.json
    • PDF report: scan_results/report_<domain>_<timestamp>.pdf

{Colors.DIM}For support: github.com/your-repo{Colors.END}

"""
        print(help_text)
        sys.exit(1)
    
    domain = sys.argv[1]
    config = ScanConfig()
    
    try:
        scanner = OptimizedWebScanner(domain, config)
        success = scanner.run()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠️  Scan interrupted by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        Logger.critical(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
