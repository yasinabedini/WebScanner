#!/usr/bin/env python3
"""
SubdomainPortScanner - Offline Subdomain Enumeration & Port Scanning Tool
Uses Subfinder for subdomain discovery and native Python socket for port scanning
Generates professional PDF reports with detailed findings
"""

import subprocess
import socket
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Set
import threading
from collections import defaultdict

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from tqdm import tqdm
except ImportError as e:
    print(f"[ERROR] Missing required library: {e}")
    print("[INFO] Install: pip install reportlab tqdm")
    sys.exit(1)


class PortScanner:
    """Efficient multi-threaded port scanner using Python sockets"""
    
    # Common ports with service identification
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport"
    }
    
    # Extended port list for comprehensive scanning
    EXTENDED_PORTS = list(range(1, 1001)) + [1433, 1521, 3306, 3389, 5432, 5900, 
                                               6379, 8080, 8443, 8888, 9090, 9200, 
                                               27017, 50000, 50070]
    
    def __init__(self, timeout: float = 1.5, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.lock = threading.Lock()
    
    def check_port(self, host: str, port: int) -> Tuple[bool, str]:
        """Check if a single port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, "Unknown")
                return True, service
            return False, ""
        except socket.gaierror:
            return False, ""
        except socket.timeout:
            return False, ""
        except Exception:
            return False, ""
    
    def scan_host(self, host: str, ports: List[int] = None) -> Dict[int, str]:
        """Scan multiple ports on a single host"""
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.check_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports[port] = service
                except Exception:
                    pass
        
        return open_ports


class SubdomainEnumerator:
    """Subdomain discovery using Subfinder"""
    
    def __init__(self, subfinder_path: str = "./tools/subfinder.exe"):
        self.subfinder_path = Path(subfinder_path)
        if not self.subfinder_path.exists():
            raise FileNotFoundError(f"Subfinder not found at: {subfinder_path}")
    
    def enumerate(self, domain: str, output_file: str = None) -> List[str]:
        """Run Subfinder to discover subdomains"""
        print(f"\n[*] Starting subdomain enumeration for: {domain}")
        
        if output_file is None:
            output_file = f"data/subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        os.makedirs("data", exist_ok=True)
        
        cmd = [
            str(self.subfinder_path),
            "-d", domain,
            "-o", output_file,
            "-silent"
        ]
        
        try:
            print(f"[*] Running command: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=300)  # 5 min timeout
            
            if process.returncode != 0:
                print(f"[!] Subfinder error: {stderr}")
                return []
            
            # Read discovered subdomains
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                print(f"[+] Found {len(subdomains)} subdomains")
                return subdomains
            else:
                print("[!] No output file generated")
                return []
                
        except subprocess.TimeoutExpired:
            print("[!] Subfinder timed out after 5 minutes")
            process.kill()
            return []
        except Exception as e:
            print(f"[!] Error running Subfinder: {e}")
            return []


class SubdomainPortScanner:
    """Main scanner class combining subdomain enumeration and port scanning"""
    
    def __init__(self, domain: str, scan_mode: str = "common"):
        self.domain = domain
        self.scan_mode = scan_mode  # "common", "extended", or "full"
        self.timestamp = datetime.now()
        
        # Initialize components
        self.enumerator = SubdomainEnumerator()
        self.port_scanner = PortScanner()
        
        # Results storage
        self.subdomains: List[str] = []
        self.scan_results: Dict[str, Dict[int, str]] = {}
        self.failed_hosts: Set[str] = set()
        
        # Statistics
        self.stats = {
            "total_subdomains": 0,
            "active_hosts": 0,
            "total_open_ports": 0,
            "scan_duration": 0
        }
    
    def get_port_list(self) -> List[int]:
        """Get port list based on scan mode"""
        if self.scan_mode == "common":
            return list(PortScanner.COMMON_PORTS.keys())
        elif self.scan_mode == "extended":
            return PortScanner.EXTENDED_PORTS
        elif self.scan_mode == "full":
            return list(range(1, 65536))
        else:
            return list(PortScanner.COMMON_PORTS.keys())
    
    def resolve_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain resolves to IP"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
    
    def run_scan(self):
        """Execute complete scanning workflow"""
        print("\n" + "="*70)
        print(f"  SubdomainPortScanner v1.0 - Target: {self.domain}")
        print("="*70)
        
        start_time = datetime.now()
        
        # Step 1: Subdomain Enumeration
        print("\n[PHASE 1] Subdomain Enumeration")
        print("-" * 70)
        self.subdomains = self.enumerator.enumerate(self.domain)
        self.stats["total_subdomains"] = len(self.subdomains)
        
        if not self.subdomains:
            print("[!] No subdomains found. Exiting...")
            return
        
        # Step 2: Validate Live Subdomains
        print(f"\n[PHASE 2] Validating {len(self.subdomains)} Subdomains")
        print("-" * 70)
        live_subdomains = []
        
        with tqdm(total=len(self.subdomains), desc="Resolving DNS", unit="host") as pbar:
            for subdomain in self.subdomains:
                if self.resolve_subdomain(subdomain):
                    live_subdomains.append(subdomain)
                    tqdm.write(f"  [✓] {subdomain}")
                else:
                    self.failed_hosts.add(subdomain)
                pbar.update(1)
        
        print(f"\n[+] Active hosts: {len(live_subdomains)}/{len(self.subdomains)}")
        self.stats["active_hosts"] = len(live_subdomains)
        
        if not live_subdomains:
            print("[!] No active hosts to scan. Exiting...")
            return
        
        # Step 3: Port Scanning
        print(f"\n[PHASE 3] Port Scanning ({self.scan_mode.upper()} mode)")
        print("-" * 70)
        ports_to_scan = self.get_port_list()
        print(f"[*] Scanning {len(ports_to_scan)} ports per host...")
        
        with tqdm(total=len(live_subdomains), desc="Scanning hosts", unit="host") as pbar:
            for subdomain in live_subdomains:
                open_ports = self.port_scanner.scan_host(subdomain, ports_to_scan)
                
                if open_ports:
                    self.scan_results[subdomain] = open_ports
                    self.stats["total_open_ports"] += len(open_ports)
                    
                    # Display findings in real-time
                    ports_str = ", ".join([f"{p}({s})" for p, s in sorted(open_ports.items())])
                    tqdm.write(f"  [✓] {subdomain}: {ports_str}")
                
                pbar.update(1)
        
        # Calculate duration
        end_time = datetime.now()
        self.stats["scan_duration"] = (end_time - start_time).total_seconds()
        
        # Display summary
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary to console"""
        print("\n" + "="*70)
        print("  SCAN SUMMARY")
        print("="*70)
        print(f"  Target Domain      : {self.domain}")
        print(f"  Scan Mode          : {self.scan_mode.upper()}")
        print(f"  Total Subdomains   : {self.stats['total_subdomains']}")
        print(f"  Active Hosts       : {self.stats['active_hosts']}")
        print(f"  Hosts with Open Ports: {len(self.scan_results)}")
        print(f"  Total Open Ports   : {self.stats['total_open_ports']}")
        print(f"  Scan Duration      : {self.stats['scan_duration']:.2f} seconds")
        print("="*70)
        
        if self.scan_results:
            print("\n[TOP FINDINGS]")
            for host, ports in sorted(self.scan_results.items(), 
                                     key=lambda x: len(x[1]), 
                                     reverse=True)[:5]:
                print(f"\n  {host}")
                for port, service in sorted(ports.items()):
                    risk = self.assess_port_risk(port, service)
                    print(f"    • Port {port:5d} | {service:20s} | Risk: {risk}")
    
    def assess_port_risk(self, port: int, service: str) -> str:
        """Assess risk level for exposed port"""
        critical_ports = {21, 23, 3389, 5900}  # FTP, Telnet, RDP, VNC
        high_risk_ports = {22, 445, 3306, 5432, 6379, 9200, 27017}  # SSH, SMB, Databases
        medium_risk_ports = {25, 110, 143, 8080, 8443}  # Mail, Alt-HTTP
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_pdf_report(self, output_file: str = None):
        """Generate comprehensive PDF report"""
        if output_file is None:
            output_file = f"reports/{self.domain}_portscan_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
        
        os.makedirs("reports", exist_ok=True)
        
        print(f"\n[*] Generating PDF report: {output_file}")
        
        doc = SimpleDocTemplate(output_file, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("Subdomain & Port Scan Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        summary_data = [
            ["Metric", "Value"],
            ["Target Domain", self.domain],
            ["Scan Date", self.timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan Mode", self.scan_mode.upper()],
            ["Total Subdomains", str(self.stats['total_subdomains'])],
            ["Active Hosts", str(self.stats['active_hosts'])],
            ["Hosts with Open Ports", str(len(self.scan_results))],
            ["Total Open Ports", str(self.stats['total_open_ports'])],
            ["Scan Duration", f"{self.stats['scan_duration']:.2f} seconds"]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Risk Distribution
        story.append(Paragraph("Risk Assessment", heading_style))
        risk_counts = defaultdict(int)
        for host, ports in self.scan_results.items():
            for port, service in ports.items():
                risk = self.assess_port_risk(port, service)
                risk_counts[risk] += 1
        
        risk_data = [["Risk Level", "Count", "Percentage"]]
        total_ports = sum(risk_counts.values())
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = risk_counts.get(risk, 0)
            percentage = (count / total_ports * 100) if total_ports > 0 else 0
            risk_data.append([risk, str(count), f"{percentage:.1f}%"])
        
        risk_table = Table(risk_data, colWidths=[2*inch, 2*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(risk_table)
        story.append(PageBreak())
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        
        for host in sorted(self.scan_results.keys()):
            ports = self.scan_results[host]
            story.append(Paragraph(f"<b>{host}</b>", styles['Heading3']))
            
            port_data = [["Port", "Service", "Risk Level"]]
            for port, service in sorted(ports.items()):
                risk = self.assess_port_risk(port, service)
                port_data.append([str(port), service, risk])
            
            port_table = Table(port_data, colWidths=[1.5*inch, 2.5*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue)
            ]))
            story.append(port_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", heading_style))
        
        recommendations = [
            "1. <b>Critical Priority:</b> Immediately disable or restrict access to critical services (FTP, Telnet, RDP, VNC) exposed to the internet.",
            "2. <b>High Priority:</b> Implement firewall rules to limit database and administrative service access to authorized IP ranges only.",
            "3. <b>Medium Priority:</b> Review and harden configurations for web services on non-standard ports (8080, 8443).",
            "4. <b>General:</b> Implement network segmentation to isolate sensitive services from public-facing infrastructure.",
            "5. <b>Monitoring:</b> Set up continuous monitoring and alerting for unauthorized port openings or service changes.",
            "6. <b>Patching:</b> Ensure all services are running latest security patches and updates.",
            "7. <b>Authentication:</b> Enforce strong authentication mechanisms (MFA) for all administrative interfaces."
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        # Build PDF
        doc.build(story)
        print(f"[+] Report generated successfully: {output_file}")


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("  SubdomainPortScanner v1.0")
    print("  Offline Subdomain Enumeration & Port Scanning")
    print("="*70 + "\n")
    
    if len(sys.argv) < 2:
        print("Usage: python SubdomainPortScanner.py <domain> [scan_mode]")
        print("\nScan Modes:")
        print("  common   - Scan top 20 common ports (default)")
        print("  extended - Scan top 1000 ports + common services")
        print("  full     - Scan all 65535 ports (slow)")
        print("\nExample:")
        print("  python SubdomainPortScanner.py example.com")
        print("  python SubdomainPortScanner.py example.com extended")
        sys.exit(1)
    
    domain = sys.argv[1]
    scan_mode = sys.argv[2] if len(sys.argv) > 2 else "common"
    
    if scan_mode not in ["common", "extended", "full"]:
        print(f"[!] Invalid scan mode: {scan_mode}")
        print("[!] Valid modes: common, extended, full")
        sys.exit(1)
    
    try:
        scanner = SubdomainPortScanner(domain, scan_mode)
        scanner.run_scan()
        
        if scanner.scan_results:
            scanner.generate_pdf_report()
        else:
            print("\n[!] No results to generate report")
        
        print("\n[✓] Scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
