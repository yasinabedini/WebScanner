"""
Nuclei Security Scanner - Professional Edition
Author: yAsIn aBeDiNi
Version: 4.5 (Final)
Description: Advanced wrapper for Nuclei with real-time progress tracking and professional PDF reports
"""

import subprocess
import json
import sys
import re
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
import threading
import hashlib
import argparse
import time

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_CENTER
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ============ COLOR SYSTEM ============
class C: 
    """رنگ‌های ANSI ساده"""
    R = '\033[91m'   # Red
    G = '\033[92m'   # Green
    Y = '\033[93m'   # Yellow
    B = '\033[94m'   # Blue
    M = '\033[95m'   # Magenta
    C = '\033[96m'   # Cyan
    W = '\033[97m'   # White
    D = '\033[2m'    # Dim
    BD = '\033[1m'   # Bold
    E = '\033[0m'    # End
    
    SEVERITY = {
        'critical': f'{R}{BD}',
        'high': R,
        'medium': Y,
        'low': C,
        'info': B,
        'unknown': W
    }
    
    ICON = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': '⚪'
    }

# ============ CONFIGURATION ============
@dataclass
class Config:
    """Scan Setting"""
    # Nuclei settings
    max_workers: int = 15
    rate_limit: int = 150
    timeout: int = 10
    retries: int = 2
    
    # Filtering
    severity: List[str] = field(default_factory=lambda: ['critical', 'high', 'medium', 'low', 'info'])
    exclude_tags: List[str] = field(default_factory=lambda: ['dos', 'fuzz'])
    include_tags: List[str] = field(default_factory=list)
    
    # Output
    output_dir: Path = Path("scans")
    enable_pdf: bool = True
    enable_html: bool = True
    enable_cache: bool = True
    
    # Advanced
    min_cvss: float = 0.0
    max_cvss: float = 10.0
    cve_filter: List[str] = field(default_factory=list)
    
    # Tools
    nuclei_bin: Path = Path("tools/nuclei.exe")
    templates_dir: Path = Path("tools/nuclei-templates")
    
    def __post_init__(self):
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "cache").mkdir(exist_ok=True)

# ============ DATA MODELS ============

@dataclass
class Vulnerability:
    """Vulnerability Model"""
    name: str
    severity: str
    template_id: str
    matched_url: str
    vuln_type: str = "unknown"
    description: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def matches_filter(self, config: Config) -> bool:
        """Check Filters"""
        if config.min_cvss > 0 and self.cvss_score < config.min_cvss:
            return False
        if config.max_cvss < 10 and self.cvss_score > config.max_cvss:
            return False
        if config.cve_filter and not any(cve in self.cve_ids for cve in config.cve_filter):
            return False
        return True
    
    def to_dict(self) -> Dict:
        return asdict(self)

# ============ UTILITIES ============

class Logger:
    """System Log thread-safe"""
    _lock = threading.Lock()
    
    @staticmethod
    def _log(level: str, msg: str, icon: str = "•", color: str = C.W):
        with Logger._lock:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"{C.D}[{ts}]{C.E} {color}{icon} {level:8s}{C.E} │ {msg}")
    
    @staticmethod
    def info(msg): Logger._log("INFO", msg, "ℹ", C.C)
    
    @staticmethod
    def success(msg): Logger._log("SUCCESS", msg, "✓", C.G)
    
    @staticmethod
    def warn(msg): Logger._log("WARNING", msg, "⚠", C.Y)
    
    @staticmethod
    def error(msg): Logger._log("ERROR", msg, "✗", C.R)
    
    @staticmethod
    def finding(sev: str, msg: str):
        Logger._log(sev.upper(), msg, C.ICON.get(sev, '•'), C.SEVERITY.get(sev, C.W))


# ============ PROGRESS TRACKER ============

class ProgressTracker:
    """Real-time progress indicator"""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.stats = {
            'scanned': 0,
            'found': 0,
            'by_severity': defaultdict(int),
            'last_update': datetime.now(),
            'running': False
        }
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.spinner_idx = 0
    
    def start(self):
        """Start progress display"""
        self.stats['running'] = True
        self.stats['last_update'] = datetime.now()
        thread = threading.Thread(target=self._display_loop, daemon=True)
        thread.start()
    
    def stop(self):
        """Stop progress display"""
        self.stats['running'] = False
        print(f"\r{' ' * 120}\r", end='', flush=True)
    
    def update(self, severity: str = None):
        """Update progress"""
        with self.lock:
            self.stats['scanned'] += 1
            if severity:
                self.stats['found'] += 1
                self.stats['by_severity'][severity] += 1
    
    def _display_loop(self):
        """Display loop"""
        while self.stats['running']:
            with self.lock:
                elapsed = (datetime.now() - self.stats['last_update']).total_seconds()
                
                # Build progress line
                spin = self.spinner[self.spinner_idx % len(self.spinner)]
                self.spinner_idx += 1
                
                severity_str = ""
                if self.stats['found'] > 0:
                    sev_parts = []
                    for sev in ['critical', 'high', 'medium', 'low']:
                        count = self.stats['by_severity'].get(sev, 0)
                        if count > 0:
                            color = C.SEVERITY.get(sev, C.W)
                            icon = C.ICON.get(sev, '•')
                            sev_parts.append(f"{icon}{color}{count}{C.E}")
                    severity_str = " │ " + " ".join(sev_parts) if sev_parts else ""
                
                progress = (
                    f"\r{C.C}{spin}{C.E} "
                    f"Scanning... "
                    f"│ {C.Y}{self.stats['scanned']}{C.E} requests "
                    f"│ {C.G}{self.stats['found']}{C.E} findings"
                    f"{severity_str} "
                    f"│ {C.D}{elapsed:.0f}s{C.E}"
                )
                
                print(progress, end='', flush=True)
            
            time.sleep(0.1)


class Cache:
    """Manage Cache"""
    
    @staticmethod
    def get_hash(domain: str, config: Config) -> str:
        """Create Hash for Cache"""
        data = f"{domain}_{config.severity}_{config.exclude_tags}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    @staticmethod
    def load(cache_file: Path) -> Optional[List[Dict]]:
        """Load From cache"""
        if not cache_file.exists():
            return None
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)                
                cached_time = datetime.fromisoformat(data['timestamp'])
                if (datetime.now() - cached_time).total_seconds() < 86400:
                    Logger.info(f"Loaded from cache ({cache_file.name})")
                    return data['vulnerabilities']
        except:
            pass
        return None
    
    @staticmethod
    def save(cache_file: Path, vulns: List[Dict]):
        """Save in Cache"""
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'vulnerabilities': vulns
                }, f, indent=2)
        except Exception as e:
            Logger.warn(f"Cache save failed: {e}")


class Sanitizer:
    """Clear Data"""
    
    @staticmethod
    def clean_filename(name: str, max_len: int = 150) -> str:
        name = re.sub(r'^https?://(www\.)?', '', name)
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
        return name[:max_len].strip('._- ') or "unknown"
    
    @staticmethod
    def clean_text(text: any, max_len: int = 500) -> str:
        if text is None:
            return ""
        try:
            s = str(text)
            s = s.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
            s = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', s)
            return s[:max_len].strip()
        except:
            return ""
    
    @staticmethod
    def extract_cves(text: str) -> List[str]:
        return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.I)))

# ============ CORE SCANNER ============

class NucleiScanner:
    """Main Scanner"""
    
    def __init__(self, targets: List[str], config: Config):
        self.targets = targets
        self.config = config
        self.vulnerabilities: List[Vulnerability] = []
        self.progress = ProgressTracker()
        self.stats = {
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'templates': 0,
            'findings': 0
        }
    
    def run(self) -> bool:
        """Main Scanner"""
        self._print_banner()
        
        if not self._verify_env():
            return False
        
        # Check Cache
        if self.config.enable_cache and len(self.targets) == 1:
            cache_hash = Cache.get_hash(self.targets[0], self.config)
            cache_file = self.config.output_dir / "cache" / f"{cache_hash}.json"
            cached = Cache.load(cache_file)
            if cached:
                self.vulnerabilities = [Vulnerability(**v) for v in cached]
                self._print_results()
                self._export_results()
                return True
        
        # Scan
        if not self._run_scan():
            return False
        
        if not self._parse_results():
            return False
        
        # Filter
        self._filter_results()
        
        # Save Cache
        if self.config.enable_cache and len(self.targets) == 1:
            cache_hash = Cache.get_hash(self.targets[0], self.config)
            cache_file = self.config.output_dir / "cache" / f"{cache_hash}.json"
            Cache.save(cache_file, [v.to_dict() for v in self.vulnerabilities])
        
        # Output
        self._export_results()
        self._print_results()
        
        return True
    
    def _verify_env(self) -> bool:
        """Check env"""
        print(f"\n{C.C}╔══ Environment Check ══╗{C.E}")
        
        checks = [
            (self.config.nuclei_bin.exists(), "Nuclei Binary", str(self.config.nuclei_bin)),
            (self.config.templates_dir.exists(), "Templates", str(self.config.templates_dir)),
        ]
        
        for passed, name, detail in checks:
            status = f"{C.G}✓{C.E}" if passed else f"{C.R}✗{C.E}"
            print(f"{C.C}║{C.E} {status} {name:<20} {C.D}{detail}{C.E}")
            if not passed:
                Logger.error(f"{name} not found!")
                return False
        
        # شمارش templates
        if self.config.templates_dir.exists():
            count = len(list(self.config.templates_dir.rglob("*.yaml")))
            self.stats['templates'] = count
            print(f"{C.C}║{C.E} {C.G}ℹ{C.E} Templates: {C.Y}{count}{C.E}")
        
        print(f"{C.C}╚═══════════════════════╝{C.E}\n")
        return True
    
    def _build_command(self) -> List[str]:
        """Create nuclei command"""
        # Create temp target file
        target_file = self.config.output_dir / f"targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(target_file, 'w') as f:
            f.write('\n'.join(self.targets))
        
        output_file = self.config.output_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        
        cmd = [
            str(self.config.nuclei_bin),
            "-l", str(target_file),
            "-t", str(self.config.templates_dir),
            "-jsonl",
            "-o", str(output_file),
            "-severity", ','.join(self.config.severity),
            "-rl", str(self.config.rate_limit),
            "-c", str(self.config.max_workers),
            "-timeout", str(self.config.timeout),
            "-retries", str(self.config.retries),
            "-duc",  # disable update check
            "-stats",
            "-v"
        ]
        
        if self.config.exclude_tags:
            cmd.extend(["-etags", ','.join(self.config.exclude_tags)])
        
        if self.config.include_tags:
            cmd.extend(["-tags", ','.join(self.config.include_tags)])
        
        self._output_file = output_file
        self._target_file = target_file
        
        return cmd
    
    def _run_scan(self) -> bool:
        """اجرای اسکن"""
        print(f"{C.C}╔══ Scanning ══════════════════════════════════════╗{C.E}\n")
        
        cmd = self._build_command()
        self.stats['start_time'] = datetime.now()
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            # شروع Progress Tracker
            self.progress.start()
            
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                # Update progress for every line
                self.progress.update()
                
                # Detect findings
                if any(f'[{s}]' in line.lower() for s in ['critical', 'high', 'medium', 'low']):
                    severity = next((s for s in ['critical', 'high', 'medium', 'low'] 
                                   if f'[{s}]' in line.lower()), 'unknown')
                    self.progress.update(severity)
            
            process.wait()
            
            # توقف Progress Tracker
            self.progress.stop()
            
            self.stats['end_time'] = datetime.now()
            self.stats['duration'] = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            
            print(f"\n{C.C}╚══════════════════════════════════════════════════╝{C.E}\n")
            
            Logger.success(f"Scan completed in {C.Y}{self.stats['duration']:.1f}s{C.E}")
            
            return True
            
        except KeyboardInterrupt:
            self.progress.stop()
            Logger.warn("Interrupted by user")
            process.kill()
            return False
        except Exception as e:
            self.progress.stop()
            Logger.error(f"Scan failed: {e}")
            return False
    
    def _parse_results(self) -> bool:
        """پردازش نتایج"""
        if not self._output_file.exists():
            Logger.warn("No results file")
            return True
        
        Logger.info("Parsing results...")
        
        try:
            with open(self._output_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                                                
                        if 'info' not in data or 'matched-at' not in data:
                            continue
                        
                        vuln = self._parse_vuln(data)
                        if vuln:
                            self.vulnerabilities.append(vuln)
                            
                    except json.JSONDecodeError:
                        continue
            
            self.stats['findings'] = len(self.vulnerabilities)
            Logger.success(f"Parsed {C.Y}{len(self.vulnerabilities)}{C.E} findings")
            
            return True
            
        except Exception as e:
            Logger.error(f"Parse error: {e}")
            return False
    
    def _parse_vuln(self, data: Dict) -> Optional[Vulnerability]:
        """Vulnerability Parse"""
        try:
            info = data.get('info', {})
            classification = info.get('classification', {})
            
            return Vulnerability(
                name=Sanitizer.clean_text(info.get('name', 'Unknown'), 200),
                severity=info.get('severity', 'unknown').lower(),
                template_id=info.get('id', 'N/A'),
                matched_url=Sanitizer.clean_text(data.get('matched-at', ''), 300),
                vuln_type=data.get('type', 'unknown'),
                description=Sanitizer.clean_text(info.get('description', ''), 500),
                remediation=Sanitizer.clean_text(info.get('remediation', ''), 500),
                cvss_score=float(classification.get('cvss-score', 0.0)),
                cve_ids=Sanitizer.extract_cves(str(classification)),
                references=info.get('reference', []),
                tags=info.get('tags', [])
            )
        except:
            return None
    
    def _filter_results(self):
        """Filter result"""
        original = len(self.vulnerabilities)

        self.vulnerabilities = [
            v for v in self.vulnerabilities
            if v.matches_filter(self.config)
        ]
        
        # Remove duplicates
        seen = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v.template_id, v.matched_url, v.severity)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        self.vulnerabilities = unique
        
        removed = original - len(unique)
        if removed > 0:
            Logger.info(f"Filtered out {C.Y}{removed}{C.E} duplicates/filtered")
    
    def _export_results(self):
        """Output"""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = Sanitizer.clean_filename(self.targets[0] if len(self.targets) == 1 else "multi")
        
        # JSON
        json_file = self.config.output_dir / f"report_{target_name}_{ts}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'targets': self.targets,
                    'scan_date': datetime.now().isoformat(),
                    'duration': self.stats['duration'],
                    'total_findings': len(self.vulnerabilities)
                },
                'statistics': {
                    'severity': dict(Counter(v.severity for v in self.vulnerabilities)),
                    'cvss_avg': sum(v.cvss_score for v in self.vulnerabilities) / len(self.vulnerabilities) if self.vulnerabilities else 0
                },
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
            }, f, indent=2)
        
        Logger.success(f"JSON: {C.Y}{json_file.name}{C.E}")
        
        # HTML
        if self.config.enable_html:
            self._generate_html(target_name, ts)
        
        # PDF
        if self.config.enable_pdf and REPORTLAB_AVAILABLE:
            self._generate_pdf(target_name, ts)
        elif self.config.enable_pdf and not REPORTLAB_AVAILABLE:
            Logger.warn("PDF generation disabled - install reportlab: pip install reportlab")
    
    def _generate_pdf(self, target_name: str, ts: str):
        """Create Professional PDF Report"""
        try:
            pdf_file = self.config.output_dir / f"report_{target_name}_{ts}.pdf"
            
            doc = SimpleDocTemplate(
                str(pdf_file), 
                pagesize=A4,
                rightMargin=2*cm,
                leftMargin=2*cm,
                topMargin=2*cm,
                bottomMargin=2*cm
            )
            
            story = []
            styles = getSampleStyleSheet()
            
            # ========== CUSTOM STYLES ==========
            
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=28,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=30,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#34495e'),
                spaceAfter=12,
                spaceBefore=12,
                fontName='Helvetica-Bold',
                borderWidth=1,
                borderColor=colors.HexColor('#3498db'),
                borderPadding=5,
                backColor=colors.HexColor('#ecf0f1')
            )
            
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#2c3e50')
            )
            
            # ========== COVER PAGE ==========
            
            story.append(Spacer(1, 3*cm))
            
            # Logo/Icon (text-based)
            story.append(Paragraph("🔒", title_style))
            
            # Title
            story.append(Paragraph("SECURITY VULNERABILITY REPORT", title_style))
            story.append(Spacer(1, 1*cm))
            
            # Target info box
            target_box = [
                ['Target(s):', ', '.join(self.targets[:3]) + ('...' if len(self.targets) > 3 else '')],
                ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Duration:', f"{self.stats['duration']:.1f} seconds"],
                ['Templates:', str(self.stats['templates'])],
                ['Total Findings:', str(len(self.vulnerabilities))]
            ]
            
            t = Table(target_box, colWidths=[5*cm, 10*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0,0), (0,-1), colors.whitesmoke),
                ('BACKGROUND', (1,0), (1,-1), colors.HexColor('#ecf0f1')),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7')),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(t)
            
            story.append(PageBreak())
            
            # ========== EXECUTIVE SUMMARY ==========
            
            story.append(Paragraph("📊 EXECUTIVE SUMMARY", heading_style))
            story.append(Spacer(1, 0.5*cm))
            
            sev_counts = Counter(v.severity for v in self.vulnerabilities)
            total = len(self.vulnerabilities)
            
            # Risk score calculation
            risk_score = (
                sev_counts.get('critical', 0) * 10 +
                sev_counts.get('high', 0) * 7 +
                sev_counts.get('medium', 0) * 4 +
                sev_counts.get('low', 0) * 2 +
                sev_counts.get('info', 0) * 0.5
            )
            
            summary_text = f"""
            This security assessment identified <b>{total} vulnerabilities</b> across the scanned targets.
            The overall risk score is <b>{risk_score:.1f}/100</b>.
            Immediate attention is required for <b>{sev_counts.get('critical', 0)} critical</b> 
            and <b>{sev_counts.get('high', 0)} high</b> severity findings.
            """
            story.append(Paragraph(summary_text, normal_style))
            story.append(Spacer(1, 1*cm))
            
            # ========== SEVERITY DISTRIBUTION ==========
            
            story.append(Paragraph("📈 SEVERITY DISTRIBUTION", heading_style))
            story.append(Spacer(1, 0.5*cm))
            
            # Color mapping
            severity_colors = {
                'critical': colors.HexColor('#e74c3c'),
                'high': colors.HexColor('#e67e22'),
                'medium': colors.HexColor('#f39c12'),
                'low': colors.HexColor('#3498db'),
                'info': colors.HexColor('#95a5a6')
            }
            
            chart_data = [['Severity', 'Count', 'Percentage', 'Risk Impact']]
            
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = sev_counts.get(sev, 0)
                if count > 0:
                    pct = (count / total * 100) if total > 0 else 0
                    impact = '●' * min(int(pct / 20) + 1, 5)
                    chart_data.append([
                        sev.upper(),
                        str(count),
                        f"{pct:.1f}%",
                        impact
                    ])
            
            t = Table(chart_data, colWidths=[4*cm, 3*cm, 3*cm, 5*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 11),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7')),
                ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,1), (-1,-1), 10),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            
            # Color-code severity column
            for i, sev in enumerate(['critical', 'high', 'medium', 'low', 'info'], 1):
                if i < len(chart_data):
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0,i), (0,i), severity_colors.get(sev, colors.grey)),
                        ('TEXTCOLOR', (0,i), (0,i), colors.whitesmoke)
                    ]))
            
            story.append(t)
            story.append(PageBreak())
            
            # ========== DETAILED FINDINGS ==========
            
            story.append(Paragraph(f"🔍 DETAILED FINDINGS ({total} Total)", heading_style))
            story.append(Spacer(1, 0.5*cm))
            
            # Sort by severity
            sorted_vulns = sorted(
                self.vulnerabilities,
                key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.severity)
            )
            
            for idx, v in enumerate(sorted_vulns, 1):
                # Finding header
                finding_title = ParagraphStyle(
                    'FindingTitle',
                    parent=styles['Heading3'],
                    fontSize=12,
                    textColor=colors.whitesmoke,
                    backColor=severity_colors.get(v.severity, colors.grey),
                    borderPadding=8,
                    fontName='Helvetica-Bold'
                )
                
                story.append(Paragraph(
                    f"{idx}. [{v.severity.upper()}] {v.name}",
                    finding_title
                ))
                story.append(Spacer(1, 0.3*cm))
                
                # Finding details
                details = [
                    ['Template ID:', v.template_id],
                    ['Type:', v.vuln_type],
                    ['CVSS Score:', f"{v.cvss_score:.1f}/10.0"],
                    ['Matched URL:', v.matched_url[:80] + ('...' if len(v.matched_url) > 80 else '')]
                ]
                
                if v.cve_ids:
                    details.append(['CVE IDs:', ', '.join(v.cve_ids)])
                
                t = Table(details, colWidths=[4*cm, 11*cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#ecf0f1')),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#bdc3c7')),
                    ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 9),
                    ('ALIGN', (0,0), (0,-1), 'RIGHT'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('RIGHTPADDING', (0,0), (-1,-1), 8),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(t)
                
                # Description
                if v.description:
                    story.append(Spacer(1, 0.2*cm))
                    story.append(Paragraph(f"<b>Description:</b> {v.description[:300]}", normal_style))
                
                # Remediation
                if v.remediation:
                    story.append(Spacer(1, 0.1*cm))
                    rem_style = ParagraphStyle(
                        'Remediation',
                        parent=normal_style,
                        backColor=colors.HexColor('#d5f4e6'),
                        borderPadding=5
                    )
                    story.append(Paragraph(f"<b>💡 Remediation:</b> {v.remediation[:300]}", rem_style))
                
                story.append(Spacer(1, 0.5*cm))
                
                # Page break every 3 findings
                if idx % 3 == 0 and idx < len(sorted_vulns):
                    story.append(PageBreak())
            
            # ========== FOOTER ==========
            story.append(PageBreak())
            story.append(Spacer(1, 5*cm))
            
            footer_style = ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#7f8c8d'),
                alignment=TA_CENTER
            )
            
            story.append(Paragraph(
                f"Generated by Nuclei Scanner v4.5 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                footer_style
            ))
            story.append(Paragraph(
                "This report is confidential and intended for authorized personnel only.",
                footer_style
            ))
            
            # ========== BUILD PDF ==========
            doc.build(story)
            
            Logger.success(f"PDF: {C.Y}{pdf_file.name}{C.E}")
            
        except Exception as e:
            Logger.error(f"PDF generation failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _generate_html(self, target_name: str, ts: str):
        """Create HTML"""
        try:
            html_file = self.config.output_dir / f"report_{target_name}_{ts}.html"
            
            sev_counts = Counter(v.severity for v in self.vulnerabilities)
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Report - {target_name}</title>
    <style>
        body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: white; padding: 15px; border-radius: 5px; flex: 1; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .critical {{ background: #e74c3c; color: white; }}
        .high {{ background: #e67e22; color: white; }}
        .medium {{ background: #f39c12; color: white; }}
        .low {{ background: #3498db; color: white; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }}
        .finding.critical {{ border-left-color: #e74c3c; }}
        .finding.high {{ border-left-color: #e67e22; }}
        .finding.medium {{ border-left-color: #f39c12; }}
        .finding.low {{ border-left-color: #3498db; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Scan Report</h1>
        <p>Target: {', '.join(self.targets)}</p>
        <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Duration: {self.stats['duration']:.1f}s</p>
    </div>
    
    <div class="stats">
        <div class="stat-box critical">
            <h2>{sev_counts.get('critical', 0)}</h2>
            <p>Critical</p>
        </div>
        <div class="stat-box high">
            <h2>{sev_counts.get('high', 0)}</h2>
            <p>High</p>
        </div>
        <div class="stat-box medium">
            <h2>{sev_counts.get('medium', 0)}</h2>
            <p>Medium</p>
        </div>
        <div class="stat-box low">
            <h2>{sev_counts.get('low', 0)}</h2>
            <p>Low</p>
        </div>
    </div>
    
    <h2>Detailed Findings ({len(self.vulnerabilities)})</h2>
"""
            
            for v in sorted(self.vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.severity)):
                html += f"""
    <div class="finding {v.severity}">
        <h3>{v.name}</h3>
        <p><strong>Severity:</strong> {v.severity.upper()} | <strong>CVSS:</strong> {v.cvss_score}</p>
        <p><strong>URL:</strong> {v.matched_url}</p>
        <p><strong>Template:</strong> {v.template_id}</p>
        {f'<p><strong>CVEs:</strong> {", ".join(v.cve_ids)}</p>' if v.cve_ids else ''}
        {f'<p>{v.description}</p>' if v.description else ''}
    </div>
"""
            
            html += """
</body>
</html>
"""
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            Logger.success(f"HTML: {C.Y}{html_file.name}{C.E}")
            
        except Exception as e:
            Logger.error(f"HTML generation failed: {e}")
    
    def _print_results(self):
        """Show Result"""
        sev_counts = Counter(v.severity for v in self.vulnerabilities)
        
        print(f"\n{C.G}╔══════════════════════════════════════════════╗")
        print(f"║        SCAN COMPLETED SUCCESSFULLY       ║")
        print(f"╚══════════════════════════════════════════════╝{C.E}\n")
        
        print(f"{C.C}╔══ Summary ═══════════════════════════════════╗{C.E}")
        print(f"{C.C}║{C.E} Duration:    {self.stats['duration']:.1f}s")
        print(f"{C.C}║{C.E} Templates:   {self.stats['templates']}")
        print(f"{C.C}║{C.E} Findings:    {len(self.vulnerabilities)}")
        print(f"{C.C}║{C.E}")
        
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = sev_counts.get(sev, 0)
            if count > 0:
                icon = C.ICON.get(sev, '•')
                color = C.SEVERITY.get(sev, C.W)
                print(f"{C.C}║{C.E} {icon} {color}{sev.upper():8s}{C.E}: {count}")
        
        print(f"{C.C}╚══════════════════════════════════════════════╝{C.E}\n")
    
    def _print_banner(self):
        """بنر"""
        print(f"""
{C.C}{C.BD}╔══════════════════════════════════════════════════════╗
║                                                      ║
║        🔒 Web SECURITY SCANNER - v4.3 🔒             ║
║                                                      ║
║             Author : yAsIn aBeDiNi                   ║
║                                                      ║
║       Github : https://github.com/yasinabedini       ║
║                                                      ║
╚══════════════════════════════════════════════════════╝{C.E}

{C.C}Target(s):{C.E} {C.Y}{', '.join(self.targets)}{C.E}
{C.C}Severity:{C.E} {', '.join(self.config.severity)}
""")

# ============ CLI ============

def parse_args():
    """Argument Parse"""
    parser = argparse.ArgumentParser(
        description='Nuclei Security Scanner - Professional Wrapper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single domain
  python scanner.py example.com
  
  # Scan multiple domains
  python scanner.py example.com test.com
  
  # Input from file
  python scanner.py -i domains.txt
  
  # Only Critical and High vulnerabilities
  python scanner.py example.com -s critical,high
  
  # CVSS filter
  python scanner.py example.com --min-cvss 7.0
  
  # More workers
  python scanner.py example.com -w 20 -r 300
  
  # Without PDF output
  python scanner.py example.com --no-pdf
        """
    )
    
    # Target
    parser.add_argument('targets', nargs='*', help='Domain(s) to scan')
    parser.add_argument('-i', '--input', help='Input file with domains (one per line)')
    
    # Scan options
    parser.add_argument('-s', '--severity', default='critical,high,medium,low,info',
                       help='Severity levels (default: all)')
    parser.add_argument('-w', '--workers', type=int, default=15,
                       help='Max workers (default: 15)')
    parser.add_argument('-r', '--rate-limit', type=int, default=150,
                       help='Rate limit (default: 150)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Timeout in seconds (default: 10)')
    
    # Filtering
    parser.add_argument('--min-cvss', type=float, default=0.0,
                       help='Minimum CVSS score (0-10)')
    parser.add_argument('--max-cvss', type=float, default=10.0,
                       help='Maximum CVSS score (0-10)')
    parser.add_argument('--cve', action='append',
                       help='Filter by CVE ID (can be used multiple times)')
    parser.add_argument('--exclude-tags', 
                       help='Tags to exclude (comma-separated)')
    parser.add_argument('--include-tags',
                       help='Tags to include (comma-separated)')
    
    # Output
    parser.add_argument('-o', '--output', default='scans',
                       help='Output directory (default: scans)')
    parser.add_argument('--no-pdf', action='store_true',
                       help='Disable PDF generation')
    parser.add_argument('--no-html', action='store_true',
                       help='Disable HTML generation')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable caching')
    
    # Tools
    parser.add_argument('--nuclei-bin', default='tools/nuclei.exe',
                       help='Path to nuclei binary')
    parser.add_argument('--templates', default='tools/nuclei-templates',
                       help='Path to templates directory')
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Get targets
    targets = []
    
    if args.input:
        try:
            with open(args.input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            Logger.error(f"Cannot read input file: {e}")
            sys.exit(1)
    
    if args.targets:
        targets.extend(args.targets)
    
    if not targets:
        Logger.error("No targets specified! Use domain(s) or -i file")
        sys.exit(1)
    
    # Build config
    config = Config(
        max_workers=args.workers,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        severity=args.severity.split(','),
        exclude_tags=args.exclude_tags.split(',') if args.exclude_tags else ['dos', 'fuzz'],
        include_tags=args.include_tags.split(',') if args.include_tags else [],
        output_dir=Path(args.output),
        enable_pdf=not args.no_pdf,
        enable_html=not args.no_html,
        enable_cache=not args.no_cache,
        min_cvss=args.min_cvss,
        max_cvss=args.max_cvss,
        cve_filter=args.cve or [],
        nuclei_bin=Path(args.nuclei_bin),
        templates_dir=Path(args.templates)
    )
    
    # Run scanner
    try:
        scanner = NucleiScanner(targets, config)
        success = scanner.run()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n{C.Y}⚠ Interrupted by user{C.E}")
        sys.exit(130)
    except Exception as e:
        Logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
