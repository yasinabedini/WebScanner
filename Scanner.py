#!/usr/bin/env python3
"""
Enterprise Web Security Scanner
Automated reconnaissance and vulnerability scanning tool
"""

import subprocess
import argparse
import json
import sys
import os
from pathlib import Path
from datetime import datetime
import logging
from typing import List, Optional
import time

class EnterpriseWebScanner:
    """Main scanner class orchestrating all security tools"""
    
    def __init__(self, domain: str, output_dir: str = "results", verbose: bool = False, tools_dir: str = None):
        self.domain = domain
        self.output_dir = Path(output_dir) / domain
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        
        # Setup tools directory
        if tools_dir:
            self.tools_dir = Path(tools_dir)
        else:
            script_dir = Path(__file__).parent
            self.tools_dir = script_dir / 'tools'
        
        # Setup logging
        self.setup_logging()
        
        # Tool availability check
        self.required_tools = ['subfinder', 'httpx', 'katana', 'nuclei', 'naabu']
        self.check_tools()
        
    def get_tool_path(self, tool_name: str) -> str:
        """Get full path to tool executable"""
        if self.tools_dir.exists():
            tool_exe = self.tools_dir / f"{tool_name}.exe"
            if tool_exe.exists():
                return str(tool_exe)
            
            tool_bin = self.tools_dir / tool_name
            if tool_bin.exists():
                return str(tool_bin)
        
        return tool_name
    
    def setup_logging(self):
        """Configure logging system"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = logging.DEBUG if self.verbose else logging.INFO
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(log_format))
        
        log_file = self.output_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(log_format))
        
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
    def check_tools(self):
        """Verify all required tools are installed"""
        missing_tools = []
        
        self.logger.info(f"Checking tools in: {self.tools_dir}")
        
        for tool in self.required_tools:
            tool_path = self.get_tool_path(tool)
            
            try:
                subprocess.run([tool_path, '-h'], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL, 
                             check=True,
                             timeout=5)
                self.logger.debug(f"✓ {tool} is available at {tool_path}")
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                missing_tools.append(tool)
                self.logger.error(f"✗ {tool} not found at {tool_path}")
        
        if missing_tools:
            self.logger.critical(f"Missing tools: {', '.join(missing_tools)}")
            self.logger.critical(f"Please ensure tools are in: {self.tools_dir}")
            sys.exit(1)
        
        self.logger.info("✓ All tools are available")
    
    def run_command(self, cmd: List[str], description: str) -> bool:
        """Execute command with error handling and logging"""
        self.logger.info(f"Running: {description}")
        self.logger.debug(f"Command: {' '.join(cmd)}")
        
        try:
            start_time = time.time()
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            elapsed_time = time.time() - start_time
            
            if result.stdout and self.verbose:
                self.logger.debug(f"Output:\n{result.stdout}")
            
            if result.stderr and self.verbose:
                self.logger.debug(f"Errors:\n{result.stderr}")
            
            self.logger.info(f"✓ {description} completed in {elapsed_time:.2f}s")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"✗ {description} failed with exit code {e.returncode}")
            if e.stdout:
                self.logger.debug(f"stdout: {e.stdout}")
            if e.stderr:
                self.logger.error(f"stderr: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"✗ Unexpected error in {description}: {str(e)}")
            return False
    
    def run_subfinder(self) -> bool:
        """Run Subfinder for subdomain enumeration"""
        output_file = self.output_dir / f"subdomains_{self.domain}.txt"
        
        cmd = [
            self.get_tool_path('subfinder'),
            '-d', self.domain,
            '-all',
            '-recursive',
            '-o', str(output_file),
            '-silent'
        ]
        
        success = self.run_command(cmd, "Subfinder (subdomain enumeration)")
        
        if success and output_file.exists():
            with open(output_file, 'r') as f:
                subdomain_count = sum(1 for _ in f)
            self.logger.info(f"Found {subdomain_count} subdomains")
        
        return success
    
    def run_httpx(self) -> bool:
        """Run httpx for HTTP probing"""
        input_file = self.output_dir / f"subdomains_{self.domain}.txt"
        output_file = self.output_dir / f"httpx_{self.domain}.json"
        
        if not input_file.exists():
            self.logger.error("Subdomain file not found. Run subfinder first.")
            return False
        
        cmd = [
            self.get_tool_path('httpx'),
            '-l', str(input_file),
            '-json',
            '-o', str(output_file),
            '-title',
            '-status-code',
            '-tech-detect',
            '-follow-redirects',
            '-random-agent',
            '-silent'
        ]
        
        success = self.run_command(cmd, "httpx (HTTP probing)")
        
        if success and output_file.exists():
            alive_count = sum(1 for _ in open(output_file))
            self.logger.info(f"Found {alive_count} alive hosts")
        
        return success
    
    def clean_httpx_output(self, httpx_file: Path) -> List[str]:
        """Extract clean URLs from httpx JSON output"""
        urls = []
        
        if not httpx_file.exists():
            self.logger.warning(f"File {httpx_file} does not exist")
            return urls
        
        try:
            with open(httpx_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        if 'url' in data:
                            urls.append(data['url'])
                        
                        if 'final_url' in data and data['final_url'] != data.get('url'):
                            urls.append(data['final_url'])
                            
                    except json.JSONDecodeError as e:
                        self.logger.debug(f"JSON parse error: {line[:50]}... | {e}")
                        continue
            
            urls = list(set(urls))
            
            self.logger.info(f"Extracted {len(urls)} unique URLs")
            return urls
            
        except Exception as e:
            self.logger.error(f"Error reading httpx file: {e}")
            return urls
    
    def run_katana(self) -> bool:
        """Run Katana for web crawling"""
        urls = self.clean_httpx_output(self.output_dir / f"httpx_{self.domain}.json")
        
        if not urls:
            self.logger.warning("No valid URLs found for Katana")
            return False
        
        input_file = self.output_dir / f"katana_input_{self.domain}.txt"
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(urls))
        
        self.logger.info(f"Saved {len(urls)} URLs to Katana input file")
        
        output_file = self.output_dir / f"katana_{self.domain}.txt"
        
        cmd = [
            self.get_tool_path('katana'),
            '-list', str(input_file),
            '-d', '3',
            '-jc',
            '-kf', 'all',
            '-fx',
            '-o', str(output_file),
            '-silent'
        ]
        
        success = self.run_command(cmd, "Katana (web crawling)")
        
        if success and output_file.exists():
            endpoint_count = sum(1 for _ in open(output_file))
            self.logger.info(f"Discovered {endpoint_count} endpoints")
        
        return success
    
    def run_nuclei(self) -> bool:
        """Run Nuclei for vulnerability scanning"""
        urls = self.clean_httpx_output(self.output_dir / f"httpx_{self.domain}.json")
        
        if not urls:
            self.logger.warning("No valid URLs found for Nuclei")
            return False
        
        input_file = self.output_dir / f"nuclei_input_{self.domain}.txt"
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(urls))
        
        self.logger.info(f"Saved {len(urls)} URLs to Nuclei input file")
        
        output_file = self.output_dir / f"nuclei_{self.domain}.json"
        
        # Update Nuclei templates first
        self.logger.info("Updating Nuclei templates...")
        try:
            subprocess.run(
                [self.get_tool_path('nuclei'), '-update-templates'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60
            )
        except Exception as e:
            self.logger.warning(f"Template update failed: {e}")
        
        # Run Nuclei with corrected flags
        cmd = [
            self.get_tool_path('nuclei'),
            '-l', str(input_file),
            '-s', 'critical,high,medium',  # Use -s instead of -severity
            '-jsonl',  # Use -jsonl for line-delimited JSON
            '-o', str(output_file),
            '-silent',
            '-t ./nuclei-templates',
            '-nc'  # No color in output
        ]
        
        # Try to run Nuclei
        self.logger.info(f"Running: Nuclei (vulnerability scanning)")
        self.logger.debug(f"Command: {' '.join(cmd)}")
        
        try:
            start_time = time.time()
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            elapsed_time = time.time() - start_time
            
            if result.stdout and self.verbose:
                self.logger.debug(f"Output:\n{result.stdout}")
            
            if result.stderr:
                self.logger.warning(f"Stderr: {result.stderr}")
            
            # Nuclei returns exit code 1 when vulnerabilities are found
            # Only consider it failed if exit code is 2 or higher
            if result.returncode >= 2:
                self.logger.error(f"✗ Nuclei failed with exit code {result.returncode}")
                return False
            
            self.logger.info(f"✓ Nuclei (vulnerability scanning) completed in {elapsed_time:.2f}s")
            
            if output_file.exists():
                vuln_count = sum(1 for _ in open(output_file) if _.strip())
                self.logger.info(f"Found {vuln_count} vulnerabilities")
            else:
                self.logger.info("No vulnerabilities found")
            
            return True
            
        except Exception as e:
            self.logger.error(f"✗ Unexpected error in Nuclei: {str(e)}")
            return False
    
    def run_naabu(self, top_ports: int = 1000) -> bool:
        """Run Naabu for port scanning"""
        input_file = self.output_dir / f"subdomains_{self.domain}.txt"
        output_file = self.output_dir / f"naabu_{self.domain}.txt"
        
        if not input_file.exists():
            self.logger.error("Subdomain file not found. Run subfinder first.")
            return False
        
        cmd = [
            self.get_tool_path('naabu'),
            '-list', str(input_file),
            '-top-ports', str(top_ports),
            '-o', str(output_file),
            '-silent'
        ]
        
        success = self.run_command(cmd, f"Naabu (port scanning - top {top_ports} ports)")
        
        if success and output_file.exists():
            open_ports = sum(1 for _ in open(output_file))
            self.logger.info(f"Found {open_ports} open ports")
        
        return success
    
    def generate_html_report(self):
        """Generate HTML report"""
        report_file = self.output_dir / f"report_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        self.logger.info("Generating HTML report...")
        
        # Read vulnerability data
        vulnerabilities = []
        nuclei_file = self.output_dir / f"nuclei_{self.domain}.json"
        if nuclei_file.exists():
            with open(nuclei_file, 'r') as f:
                for line in f:
                    try:
                        vuln = json.loads(line.strip())
                        vulnerabilities.append(vuln)
                    except:
                        continue
        
        # Count statistics
        subdomain_count = 0
        subdomain_file = self.output_dir / f"subdomains_{self.domain}.txt"
        if subdomain_file.exists():
            subdomain_count = sum(1 for _ in open(subdomain_file))
        
        alive_count = 0
        httpx_file = self.output_dir / f"httpx_{self.domain}.json"
        if httpx_file.exists():
            alive_count = sum(1 for _ in open(httpx_file))
        
        endpoint_count = 0
        katana_file = self.output_dir / f"katana_{self.domain}.txt"
        if katana_file.exists():
            endpoint_count = sum(1 for _ in open(katana_file))
        
        port_count = 0
        naabu_file = self.output_dir / f"naabu_{self.domain}.txt"
        if naabu_file.exists():
            port_count = sum(1 for _ in open(naabu_file))
        
        # Count severity
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('info', {}).get('severity', 'unknown').lower()
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {self.domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header p {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card h3 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            margin-bottom: 30px;
        }}
        
        .severity-section h2 {{
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .severity-item {{
            padding: 15px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .severity-item.critical {{
            background: #fee;
            border-left: 4px solid #dc3545;
        }}
        
        .severity-item.high {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
        }}
        
        .severity-item.medium {{
            background: #fff9c4;
            border-left: 4px solid #ffc107;
        }}
        
        .severity-item.low {{
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
        }}
        
        .severity-item.info {{
            background: #f3e5f5;
            border-left: 4px solid #9c27b0;
        }}
        
        .severity-label {{
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        
        .severity-count {{
            font-size: 1.5em;
            font-weight: bold;
        }}
        
        .vuln-list {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }}
        
        .vuln-list h2 {{
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .vuln-item {{
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            background: #f9f9f9;
            border-left: 4px solid #667eea;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }}
        
        .vuln-title {{
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
        }}
        
        .vuln-severity {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .vuln-severity.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .vuln-severity.high {{
            background: #ff9800;
            color: white;
        }}
        
        .vuln-severity.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .vuln-severity.low {{
            background: #2196f3;
            color: white;
        }}
        
        .vuln-details {{
            margin-top: 10px;
            color: #666;
            font-size: 0.95em;
        }}
        
        .vuln-details p {{
            margin: 5px 0;
        }}
        
        .vuln-url {{
            color: #667eea;
            word-break: break-all;
        }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 40px;
        }}
        
        @media print {{
            .stat-card {{
                break-inside: avoid;
            }}
            .vuln-item {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Scan Report</h1>
            <p>Target: <strong>{self.domain}</strong></p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Subdomains</h3>
                <div class="number">{subdomain_count}</div>
            </div>
            <div class="stat-card">
                <h3>Alive Hosts</h3>
                <div class="number">{alive_count}</div>
            </div>
            <div class="stat-card">
                <h3>Endpoints</h3>
                <div class="number">{endpoint_count:,}</div>
            </div>
            <div class="stat-card">
                <h3>Open Ports</h3>
                <div class="number">{port_count}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities</h3>
                <div class="number">{len(vulnerabilities)}</div>
            </div>
        </div>
        
        <div class="severity-section">
            <h2>📊 Vulnerability Severity Breakdown</h2>
            <div class="severity-grid">
                <div class="severity-item critical">
                    <span class="severity-label">Critical</span>
                    <span class="severity-count">{severity_count['critical']}</span>
                </div>
                <div class="severity-item high">
                    <span class="severity-label">High</span>
                    <span class="severity-count">{severity_count['high']}</span>
                </div>
                <div class="severity-item medium">
                    <span class="severity-label">Medium</span>
                    <span class="severity-count">{severity_count['medium']}</span>
                </div>
                <div class="severity-item low">
                    <span class="severity-label">Low</span>
                    <span class="severity-count">{severity_count['low']}</span>
                </div>
                <div class="severity-item info">
                    <span class="severity-label">Info</span>
                    <span class="severity-count">{severity_count['info']}</span>
                </div>
            </div>
        </div>
        
        <div class="vuln-list">
            <h2>🔍 Detailed Vulnerabilities</h2>
"""
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                info = vuln.get('info', {})
                severity = info.get('severity', 'unknown').lower()
                name = info.get('name', 'Unknown')
                description = info.get('description', 'No description available')
                matched_at = vuln.get('matched-at', vuln.get('host', 'N/A'))
                template_id = vuln.get('template-id', 'N/A')
                
                html_content += f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-title">{name}</div>
                    <span class="vuln-severity {severity}">{severity}</span>
                </div>
                <div class="vuln-details">
                    <p><strong>Template:</strong> {template_id}</p>
                    <p><strong>URL:</strong> <span class="vuln-url">{matched_at}</span></p>
                    <p><strong>Description:</strong> {description}</p>
                </div>
            </div>
"""
        else:
            html_content += """
            <p style="text-align: center; padding: 40px; color: #666;">
                ✅ No vulnerabilities detected
            </p>
"""
        
        html_content += """
        </div>
        
        <footer>
            <p>Generated by Enterprise Web Security Scanner</p>
            <p>All results saved in: """ + str(self.output_dir) + """</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"✓ HTML report saved to: {report_file}")
        return report_file
    
    def generate_report(self):
        """Generate final scan report"""
        report_file = self.output_dir / f"report_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        self.logger.info("Generating final report...")
        
        with open(report_file, 'w', encoding='utf-8') as report:
            report.write(f"{'='*80}\n")
            report.write(f"SECURITY SCAN REPORT\n")
            report.write(f"Target: {self.domain}\n")
            report.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report.write(f"{'='*80}\n\n")
            
            subdomain_file = self.output_dir / f"subdomains_{self.domain}.txt"
            if subdomain_file.exists():
                count = sum(1 for _ in open(subdomain_file))
                report.write(f"[+] Subdomains Found: {count}\n")
            
            httpx_file = self.output_dir / f"httpx_{self.domain}.json"
            if httpx_file.exists():
                count = sum(1 for _ in open(httpx_file))
                report.write(f"[+] Alive Hosts: {count}\n")
            
            katana_file = self.output_dir / f"katana_{self.domain}.txt"
            if katana_file.exists():
                count = sum(1 for _ in open(katana_file))
                report.write(f"[+] Discovered Endpoints: {count}\n")
            
            nuclei_file = self.output_dir / f"nuclei_{self.domain}.json"
            if nuclei_file.exists():
                count = sum(1 for _ in open(nuclei_file) if _.strip())
                report.write(f"[+] Vulnerabilities Found: {count}\n")
                
                if count > 0:
                    severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                    with open(nuclei_file, 'r') as f:
                        for line in f:
                            try:
                                vuln = json.loads(line.strip())
                                severity = vuln.get('info', {}).get('severity', 'unknown').lower()
                                severity_count[severity] = severity_count.get(severity, 0) + 1
                            except:
                                continue
                    
                    report.write(f"\n  Severity Breakdown:\n")
                    for severity, count in severity_count.items():
                        if count > 0:
                            report.write(f"    - {severity.capitalize()}: {count}\n")
            
            naabu_file = self.output_dir / f"naabu_{self.domain}.txt"
            if naabu_file.exists():
                count = sum(1 for _ in open(naabu_file))
                report.write(f"[+] Open Ports: {count}\n")
            
            report.write(f"\n{'='*80}\n")
            report.write(f"All results saved in: {self.output_dir}\n")
            report.write(f"{'='*80}\n")
        
        self.logger.info(f"Report saved to: {report_file}")
        
        with open(report_file, 'r') as f:
            print("\n" + f.read())
        
        # Generate HTML report
        html_file = self.generate_html_report()
        print(f"\n📄 HTML Report: {html_file}")
        print(f"💡 Tip: Open the HTML file in your browser for a better view!")
    
    def run_full_scan(self, skip_subdomain: bool = False, skip_ports: bool = False):
        """Execute complete security scan workflow"""
        self.logger.info(f"Starting security scan for {self.domain}")
        self.logger.info(f"Output directory: {self.output_dir}")
        
        start_time = time.time()
        
        if not skip_subdomain:
            self.logger.info("\n[Phase 1/5] Subdomain Enumeration")
            if not self.run_subfinder():
                self.logger.error("Subfinder failed. Aborting scan.")
                return
        else:
            self.logger.info("\n[Phase 1/5] Skipping subdomain enumeration")
        
        self.logger.info("\n[Phase 2/5] HTTP Probing")
        if not self.run_httpx():
            self.logger.error("httpx failed. Aborting scan.")
            return
        
        self.logger.info("\n[Phase 3/5] Web Crawling")
        self.run_katana()
        
        self.logger.info("\n[Phase 4/5] Vulnerability Scanning")
        self.run_nuclei()
        
        if not skip_ports:
            self.logger.info("\n[Phase 5/5] Port Scanning")
            self.run_naabu()
        else:
            self.logger.info("\n[Phase 5/5] Skipping port scanning")
        
        elapsed_time = time.time() - start_time
        self.logger.info(f"\nTotal scan time: {elapsed_time:.2f}s ({elapsed_time/60:.2f} minutes)")
        
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(
        description='Enterprise Web Security Scanner - Automated reconnaissance and vulnerability scanning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com -v
  %(prog)s -d example.com --skip-ports
  %(prog)s -d example.com -o /path/to/results
  %(prog)s -d example.com --tools-dir ./custom_tools
        """
    )
    
    parser.add_argument('-d', '--domain', 
                       required=True,
                       help='Target domain to scan')
    
    parser.add_argument('-o', '--output',
                       default='results',
                       help='Output directory for results (default: results)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--skip-subdomain',
                       action='store_true',
                       help='Skip subdomain enumeration phase')
    
    parser.add_argument('--skip-ports',
                       action='store_true',
                       help='Skip port scanning phase')
    
    parser.add_argument('--tools-dir',
                       default=None,
                       help='Custom tools directory (default: ./tools)')
    
    args = parser.parse_args()
    
    scanner = EnterpriseWebScanner(
        domain=args.domain,
        output_dir=args.output,
        verbose=args.verbose,
        tools_dir=args.tools_dir
    )
    
    try:
        scanner.run_full_scan(
            skip_subdomain=args.skip_subdomain,
            skip_ports=args.skip_ports
        )
    except KeyboardInterrupt:
        scanner.logger.warning("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        scanner.logger.critical(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
