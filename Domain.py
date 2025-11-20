#!/usr/bin/env python3
"""
SubdomainPortScanner v2.0 - Optimized Edition
Offline Subdomain Enumeration & Port Scanning Tool
Author: yAsIn aBeDiNi
"""

import subprocess
import socket
import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Set, Optional
import threading
from collections import defaultdict
from dataclasses import dataclass, field

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from tqdm import tqdm
    REPORTLAB_AVAILABLE = True
except ImportError as e:
    print(f"[!] Missing library: {e}")
    print("[!] Install: pip install reportlab tqdm")
    REPORTLAB_AVAILABLE = False


# ============ COLORS ============

class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    BD = '\033[1m'
    E = '\033[0m'


# ============ DATA MODELS ============

@dataclass
class PortInfo:
    """Port information"""
    port: int
    service: str
    risk: str
    
@dataclass
class HostResult:
    """Host scan result"""
    hostname: str
    ip: Optional[str]
    open_ports: List[PortInfo] = field(default_factory=list)
    scan_time: float = 0.0


# ============ PORT SCANNER ============

class PortScanner:
    """Optimized multi-threaded port scanner"""
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        6379: "Redis", 9200: "Elasticsearch", 1433: "MSSQL"
    }
    
    EXTENDED_PORTS = list(range(1, 1001)) + [
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 
        8080, 8443, 8888, 9090, 9200, 27017, 50000
    ]
    
    RISK_LEVELS = {
        'CRITICAL': {21, 23, 3389, 5900, 445},  # FTP, Telnet, RDP, VNC, SMB
        'HIGH': {22, 3306, 5432, 6379, 9200, 27017, 1433},  # SSH, DBs
        'MEDIUM': {25, 110, 143, 8080, 8443, 8888},  # Mail, Alt-HTTP
    }
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
    
    def check_port(self, host: str, port: int) -> Tuple[bool, str]:
        """Check single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    return True, service
        except:
            pass
        return False, ""
    
    def scan_host(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Scan multiple ports"""
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.check_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports[port] = service
                except:
                    pass
        
        return open_ports
    
    @staticmethod
    def assess_risk(port: int) -> str:
        """Assess port risk level"""
        for risk, ports in PortScanner.RISK_LEVELS.items():
            if port in ports:
                return risk
        return "LOW"


# ============ SUBDOMAIN ENUMERATOR ============

class SubdomainEnumerator:
    """Optimized subdomain discovery"""
    
    def __init__(self, subfinder_path: str = "./tools/subfinder.exe"):
        self.subfinder_path = Path(subfinder_path)
        if not self.subfinder_path.exists():
            raise FileNotFoundError(f"Subfinder not found: {subfinder_path}")
    
    def enumerate(self, domain: str, output_dir: Path) -> List[str]:
        """Discover subdomains using Subfinder"""
        print(f"\n{C.Y}[*] Enumerating subdomains...{C.E}")
        
        output_file = output_dir / f"subdomains_{domain}_{datetime.now():%Y%m%d_%H%M%S}.txt"
        
        cmd = [
            str(self.subfinder_path),
            "-d", domain,
            "-o", str(output_file),
            "-silent",
            "-all"
        ]
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if process.returncode != 0:
                print(f"{C.R}[!] Subfinder error: {process.stderr}{C.E}")
                return []
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                print(f"{C.G}[+] Found {len(subdomains)} subdomains{C.E}")
                return subdomains
            
            return []
            
        except subprocess.TimeoutExpired:
            print(f"{C.R}[!] Subfinder timeout{C.E}")
            return []
        except Exception as e:
            print(f"{C.R}[!] Error: {e}{C.E}")
            return []


# ============ MAIN SCANNER ============

class SubdomainPortScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, domain: str, scan_mode: str = "common", 
                 timeout: float = 1.0, max_workers: int = 100):
        self.domain = domain
        self.scan_mode = scan_mode
        self.timestamp = datetime.now()
        
        # Initialize components
        self.enumerator = SubdomainEnumerator()
        self.port_scanner = PortScanner(timeout=timeout, max_workers=max_workers)
        
        # Output directories
        self.output_dir = Path("data")
        self.report_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)
        self.report_dir.mkdir(exist_ok=True)
        
        # Results
        self.subdomains: List[str] = []
        self.results: List[HostResult] = []
        self.failed_hosts: Set[str] = set()
        
        # Stats
        self.stats = {
            "total_subdomains": 0,
            "active_hosts": 0,
            "total_open_ports": 0,
            "scan_duration": 0.0
        }
    
    def print_banner(self):
        """Display banner"""
        print(f"""
{C.C}{C.BD}╔══════════════════════════════════════════════════════╗
║                                                      ║
║    🔍 SUBDOMAIN PORT SCANNER v2.0 🔍                ║
║              Powered by Subfinder                    ║
║                                                      ║
╚══════════════════════════════════════════════════════╝{C.E}

{C.C}Target:{C.E} {C.Y}{self.domain}{C.E}
{C.C}Mode:{C.E} {self.scan_mode.upper()}
{C.C}Date:{C.E} {self.timestamp:%Y-%m-%d %H:%M:%S}
""")
    
    def get_ports(self) -> List[int]:
        """Get port list based on mode"""
        if self.scan_mode == "common":
            return list(PortScanner.COMMON_PORTS.keys())
        elif self.scan_mode == "extended":
            return PortScanner.EXTENDED_PORTS
        elif self.scan_mode == "full":
            return list(range(1, 65536))
        return list(PortScanner.COMMON_PORTS.keys())
    
    def resolve_host(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def run(self) -> bool:
        """Execute scan"""
        self.print_banner()
        
        start_time = datetime.now()
        
        # Phase 1: Subdomain Enumeration
        print(f"{C.C}╔══ PHASE 1: Subdomain Discovery ══════════════════╗{C.E}")
        self.subdomains = self.enumerator.enumerate(self.domain, self.output_dir)
        self.stats["total_subdomains"] = len(self.subdomains)
        print(f"{C.C}╚══════════════════════════════════════════════════╝{C.E}\n")
        
        if not self.subdomains:
            print(f"{C.R}[!] No subdomains found{C.E}")
            return False
        
        # Phase 2: DNS Resolution
        print(f"{C.C}╔══ PHASE 2: DNS Resolution ═══════════════════════╗{C.E}")
        live_hosts = []
        
        with tqdm(total=len(self.subdomains), desc="Resolving", unit="host") as pbar:
            for subdomain in self.subdomains:
                ip = self.resolve_host(subdomain)
                if ip:
                    live_hosts.append((subdomain, ip))
                    tqdm.write(f"{C.G}  [✓] {subdomain} → {ip}{C.E}")
                else:
                    self.failed_hosts.add(subdomain)
                pbar.update(1)
        
        self.stats["active_hosts"] = len(live_hosts)
        print(f"{C.C}╚══════════════════════════════════════════════════╝{C.E}")
        print(f"{C.G}[+] Active: {len(live_hosts)}/{len(self.subdomains)}{C.E}\n")
        
        if not live_hosts:
            print(f"{C.R}[!] No active hosts{C.E}")
            return False
        
        # Phase 3: Port Scanning
        print(f"{C.C}╔══ PHASE 3: Port Scanning ════════════════════════╗{C.E}")
        ports = self.get_ports()
        print(f"{C.Y}[*] Scanning {len(ports)} ports per host...{C.E}\n")
        
        with tqdm(total=len(live_hosts), desc="Scanning", unit="host") as pbar:
            for hostname, ip in live_hosts:
                scan_start = datetime.now()
                open_ports = self.port_scanner.scan_host(ip, ports)
                scan_duration = (datetime.now() - scan_start).total_seconds()
                
                if open_ports:
                    port_infos = [
                        PortInfo(
                            port=p, 
                            service=s, 
                            risk=PortScanner.assess_risk(p)
                        )
                        for p, s in open_ports.items()
                    ]
                    
                    result = HostResult(
                        hostname=hostname,
                        ip=ip,
                        open_ports=port_infos,
                        scan_time=scan_duration
                    )
                    self.results.append(result)
                    self.stats["total_open_ports"] += len(open_ports)
                    
                    # Display
                    ports_str = ", ".join([
                        f"{p.port}({p.service})" 
                        for p in sorted(port_infos, key=lambda x: x.port)
                    ])
                    tqdm.write(f"{C.G}  [✓] {hostname}: {ports_str}{C.E}")
                
                pbar.update(1)
        
        print(f"{C.C}╚══════════════════════════════════════════════════╝{C.E}\n")
        
        # Calculate duration
        self.stats["scan_duration"] = (datetime.now() - start_time).total_seconds()
        
        # Summary
        self.print_summary()
        
        return True
    
    def print_summary(self):
        """Print results summary"""
        print(f"{C.G}╔══════════════════════════════════════════════════╗")
        print(f"║             SCAN COMPLETED                   ║")
        print(f"╚══════════════════════════════════════════════════╝{C.E}\n")
        
        print(f"{C.C}╔══ Summary ═══════════════════════════════════════╗{C.E}")
        print(f"{C.C}║{C.E} Subdomains:     {self.stats['total_subdomains']}")
        print(f"{C.C}║{C.E} Active Hosts:   {self.stats['active_hosts']}")
        print(f"{C.C}║{C.E} Vulnerable:     {len(self.results)}")
        print(f"{C.C}║{C.E} Open Ports:     {self.stats['total_open_ports']}")
        print(f"{C.C}║{C.E} Duration:       {self.stats['scan_duration']:.1f}s")
        print(f"{C.C}╚══════════════════════════════════════════════════╝{C.E}\n")
        
        if self.results:
            print(f"{C.Y}[TOP 5 FINDINGS]{C.E}\n")
            for result in sorted(self.results, 
                               key=lambda x: len(x.open_ports), 
                               reverse=True)[:5]:
                print(f"{C.B}  • {result.hostname}{C.E} ({result.ip})")
                for port in sorted(result.open_ports, key=lambda x: x.port):
                    risk_color = {
                        'CRITICAL': C.R,
                        'HIGH': C.Y,
                        'MEDIUM': C.Y,
                        'LOW': C.C
                    }.get(port.risk, C.W)
                    print(f"    {port.port:5d} | {port.service:20s} | {risk_color}{port.risk}{C.E}")
                print()
    
    def generate_pdf(self) -> bool:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            print(f"{C.Y}[!] reportlab not installed - skipping PDF{C.E}")
            return False
        
        print(f"{C.Y}[*] Generating PDF...{C.E}")
        
        pdf_file = self.report_dir / f"{self.domain}_portscan_{self.timestamp:%Y%m%d_%H%M%S}.pdf"
        
        doc = SimpleDocTemplate(str(pdf_file), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph("🔍", title_style))
        story.append(Paragraph("Subdomain & Port Scan Report", title_style))
        story.append(Spacer(1, 1*cm))
        
        # Summary Table
        summary_data = [
            ['Metric', 'Value'],
            ['Target', self.domain],
            ['Scan Date', self.timestamp.strftime('%Y-%m-%d %H:%M:%S')],
            ['Mode', self.scan_mode.upper()],
            ['Subdomains', str(self.stats['total_subdomains'])],
            ['Active Hosts', str(self.stats['active_hosts'])],
            ['Vulnerable Hosts', str(len(self.results))],
            ['Open Ports', str(self.stats['total_open_ports'])],
            ['Duration', f"{self.stats['scan_duration']:.1f}s"]
        ]
        
        t = Table(summary_data, colWidths=[6*cm, 8*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0,0), (0,-1), colors.whitesmoke),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTSIZE', (0,0), (-1,-1), 11),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('BACKGROUND', (1,0), (1,-1), colors.HexColor('#ecf0f1')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#bdc3c7'))
        ]))
        story.append(t)
        story.append(PageBreak())
        
        # Detailed Findings
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12
        )
        
        story.append(Paragraph("Detailed Findings", heading_style))
        story.append(Spacer(1, 0.5*cm))
        
        for result in sorted(self.results, key=lambda x: len(x.open_ports), reverse=True):
            story.append(Paragraph(f"<b>{result.hostname}</b> ({result.ip})", styles['Heading3']))
            
            port_data = [['Port', 'Service', 'Risk']]
            for port in sorted(result.open_ports, key=lambda x: x.port):
                port_data.append([str(port.port), port.service, port.risk])
            
            t = Table(port_data, colWidths=[3*cm, 6*cm, 4*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('BACKGROUND', (0,1), (-1,-1), colors.lightblue)
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5*cm))
        
        try:
            doc.build(story)
            print(f"{C.G}[+] PDF saved: {pdf_file}{C.E}\n")
            return True
        except Exception as e:
            print(f"{C.R}[!] PDF error: {e}{C.E}")
            return False


# ============ CLI ============

def main():
    parser = argparse.ArgumentParser(
        description='🔍 Subdomain Port Scanner v2.0 - Optimized Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com -m extended
  %(prog)s example.com -m full -t 2.0 -w 200

Scan Modes:
  common   - Top 20 common ports (fast)
  extended - Top 1000 ports + services (balanced)
  full     - All 65535 ports (slow)

Author: yAsIn aBeDiNi
GitHub: https://github.com/yasinabedini
        """
    )
    
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('-m', '--mode', 
                       choices=['common', 'extended', 'full'],
                       default='common',
                       help='Scan mode (default: common)')
    parser.add_argument('-t', '--timeout', 
                       type=float, 
                       default=1.0,
                       help='Port timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', 
                       type=int, 
                       default=100,
                       help='Max concurrent threads (default: 100)')
    parser.add_argument('--no-pdf', 
                       action='store_true',
                       help='Skip PDF generation')
    
    args = parser.parse_args()
    
    try:
        scanner = SubdomainPortScanner(
            domain=args.domain,
            scan_mode=args.mode,
            timeout=args.timeout,
            max_workers=args.workers
        )
        
        success = scanner.run()
        
        if success and not args.no_pdf:
            scanner.generate_pdf()
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Scan interrupted{C.E}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.R}[!] Fatal error: {e}{C.E}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
