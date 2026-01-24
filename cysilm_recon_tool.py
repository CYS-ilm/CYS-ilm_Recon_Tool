#!/usr/bin/env python3
"""
CYS-ILM RECONNAISSANCE TOOL v2.0
Professional Security Assessment Tool
Author: CYS-ILM Security Team
Department: Cyber Security
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import warnings
warnings.filterwarnings('ignore')

# Import internal modules
try:
    from modules.passive_recon import PassiveReconnaissance
    from modules.active_recon import ActiveReconnaissance
    from modules.reporting import ReportGenerator
    from utils.logger import setup_logger
    from utils.validator import validate_input, sanitize_target
except ImportError as e:
    print(f"❌ Failed to import modules: {str(e)}")
    print("Make sure all module files exist and requirements are installed.")
    sys.exit(1)

# Version information
__version__ = "2.0.0"
__author__ = "CYS-ILM Security Team"
__license__ = "Corporate Confidential"
__tool_name__ = "CYS_ilm_recon_tool"


class CYSilmReconTool:
    """Main controller for CYS-ILM reconnaissance operations."""
    
    def __init__(self, target: str, verbose: bool = False, output_dir: str = "outputs"):
        """Initialize the reconnaissance tool.
        
        Args:
            target: Domain or IP address to scan
            verbose: Enable verbose logging
            output_dir: Directory for output files
        """
        self.target = sanitize_target(target)
        self.verbose = verbose
        self.output_dir = output_dir
        
        # Setup logging
        self.logger = setup_logger("CYSilmRecon", verbose)
        
        # Initialize modules
        self.passive = PassiveReconnaissance(verbose)
        self.active = ActiveReconnaissance(verbose)
        
        # Initialize all result structures to avoid key errors
        self.results = {
            "metadata": {
                "target": self.target,
                "start_time": datetime.now().isoformat(),
                "tool_version": __version__,
                "execution_mode": "professional",
                "scan_id": f"SCAN_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            },
            "passive": {
                "whois": {"note": "Not executed"},
                "dns": {"note": "Not executed"},
                "subdomains": {"note": "Not executed"},
                "reverse_lookup": {"note": "Not executed"},
                "related_domains": {"note": "Not executed"}
            },
            "active": {
                "port_scan": {"note": "Not executed"},
                "banners": {"note": "Not executed"},
                "technologies": {"note": "Not executed"},
                "http_headers": {"note": "Not executed"},
                "vulnerability_checks": {"note": "Not executed"}
            },
            "findings": [],
            "risk_assessment": {}
        }
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def run_comprehensive_scan(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reconnaissance scan based on selected options.
        
        Args:
            options: Dictionary of scan options
            
        Returns:
            Complete scan results
        """
        try:
            # Validate target
            if not validate_input(self.target):
                raise ValueError(f"Invalid target: {self.target}")
            
            self.logger.info(f"🚀 Starting CYS-ILM reconnaissance on: {self.target}")
            self.logger.info(f"📋 Scan ID: {self.results['metadata']['scan_id']}")
            
            # Determine what to run based on options
            run_passive = options.get('passive', False)
            run_active = options.get('active', False)
            
            self.logger.debug(f"Will run - Passive: {run_passive}, Active: {run_active}")
            
            # PHASE 1: PASSIVE RECONNAISSANCE (only if requested)
            if run_passive:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 1: PASSIVE INFORMATION GATHERING")
                self.logger.info("=" * 60)
                self._execute_passive_recon(options)
            else:
                self.logger.info("⏭️  Skipping passive reconnaissance")
                self.results['passive'] = {"note": "Passive reconnaissance not requested"}
            
            # PHASE 2: ACTIVE RECONNAISSANCE (only if requested)
            if run_active:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 2: ACTIVE DISCOVERY AND ENUMERATION")
                self.logger.info("=" * 60)
                self._execute_active_recon(options)
            else:
                self.logger.info("⏭️  Skipping active reconnaissance")
                self.results['active'] = {"note": "Active reconnaissance not requested"}
            
            # PHASE 3: ANALYSIS AND REPORTING
            self.logger.info("=" * 60)
            self.logger.info("PHASE 3: ANALYSIS AND RISK ASSESSMENT")
            self.logger.info("=" * 60)
            
            self._analyze_results()
            self._generate_risk_assessment()
            
            # Update metadata
            self.results['metadata']['end_time'] = datetime.now().isoformat()
            self.results['metadata']['status'] = 'completed'
            
            self.logger.info("✅ Scan completed successfully!")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {str(e)}")
            self.results['metadata']['status'] = 'failed'
            self.results['metadata']['error'] = str(e)
            raise
    
    def _execute_passive_recon(self, options: Dict[str, Any]):
        """Execute passive reconnaissance modules."""
        try:
            if options.get('whois', False) or options.get('all', False):
                self.logger.info("🔍 Performing WHOIS lookup...")
                self.results['passive']['whois'] = self.passive.whois_lookup(self.target)
            
            if options.get('dns', False) or options.get('all', False):
                self.logger.info("🌐 Enumerating DNS records...")
                self.results['passive']['dns'] = self.passive.dns_enumeration(
                    self.target, 
                    record_types=['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
                )
            
            if options.get('subdomains', False) or options.get('all', False):
                self.logger.info("🔎 Discovering subdomains...")
                self.results['passive']['subdomains'] = self.passive.subdomain_discovery(
                    self.target,
                    use_crtsh=True,
                    use_otx=False,  # Disabled due to rate limits
                    use_virustotal=False,
                    brute_force=False,
                    depth=1
                )
            
            if options.get('all', False):
                self.logger.info("📊 Performing reverse IP lookup...")
                self.results['passive']['reverse_lookup'] = self.passive.reverse_ip_lookup(self.target)
                
                self.logger.info("🔗 Finding related domains...")
                self.results['passive']['related_domains'] = self.passive.find_related_domains(self.target)
                
        except Exception as e:
            self.logger.error(f"Passive recon failed: {str(e)}")
    
    def _execute_active_recon(self, options: Dict[str, Any]):
        """Execute active reconnaissance modules."""
        try:
            ports = options.get('ports', '1-1000')
            scan_type = options.get('scan_type', 'quick')
            
            if options.get('scan', False) or options.get('all', False):
                self.logger.info(f"📡 Performing port scan ({scan_type} mode)...")
                self.results['active']['port_scan'] = self.active.comprehensive_port_scan(
                    self.target,
                    ports=ports,
                    scan_type=scan_type,
                    timing_template=3
                )
            
            if options.get('banners', False) or options.get('all', False):
                self.logger.info("🚩 Grabbing service banners...")
                self.results['active']['banners'] = self.active.banner_grabbing(self.target)
            
            if options.get('tech', False) or options.get('all', False):
                self.logger.info("🛠️ Detecting web technologies...")
                self.results['active']['technologies'] = self.active.technology_detection(self.target)
            
            if options.get('all', False):
                self.logger.info("📝 Performing HTTP header analysis...")
                self.results['active']['http_headers'] = self.active.http_header_analysis(self.target)
                
                self.logger.info("🔒 Checking common vulnerabilities...")
                self.results['active']['vulnerability_checks'] = self.active.basic_vulnerability_checks(self.target)
                
        except Exception as e:
            self.logger.error(f"Active recon failed: {str(e)}")
    
    def _analyze_results(self):
        """Analyze results and generate findings - safe version."""
        findings = []
        
        try:
            # Analyze passive results
            passive = self.results.get('passive', {})
            if passive and passive.get('note') != 'Passive reconnaissance not requested':
                
                # WHOIS findings
                whois_data = passive.get('whois', {})
                if whois_data and whois_data.get('note') != 'Not executed':
                    findings.append({
                        "severity": "INFO",
                        "category": "Registration",
                        "title": "WHOIS information retrieved",
                        "description": "Domain registration details obtained",
                        "recommendation": "Review domain registration for accuracy."
                    })
                
                # DNS findings
                dns_data = passive.get('dns', {})
                if dns_data and dns_data.get('note') != 'Not executed':
                    if isinstance(dns_data, dict) and 'records' in dns_data:
                        total_records = sum(len(records) for records in dns_data['records'].values() 
                                          if isinstance(records, list))
                        if total_records > 0:
                            findings.append({
                                "severity": "INFO",
                                "category": "DNS",
                                "title": f"Enumerated {total_records} DNS records",
                                "description": "DNS configuration analyzed",
                                "recommendation": "Review DNS records for accuracy."
                            })
                
                # Subdomain findings
                subdomains_data = passive.get('subdomains', {})
                if subdomains_data and subdomains_data.get('note') != 'Not executed':
                    valid_count = subdomains_data.get('total_valid', 0)
                    if valid_count > 0:
                        findings.append({
                            "severity": "INFO",
                            "category": "Infrastructure",
                            "title": f"Discovered {valid_count} subdomains",
                            "description": f"Found {valid_count} valid subdomains",
                            "recommendation": "Monitor all subdomains."
                        })
            
            # Analyze active results
            active = self.results.get('active', {})
            if active and active.get('note') != 'Active reconnaissance not requested':
                
                # Port scan findings
                port_scan = active.get('port_scan', {})
                if port_scan and port_scan.get('note') != 'Not executed':
                    open_ports = port_scan.get('open_ports', [])
                    if isinstance(open_ports, list) and open_ports:
                        findings.append({
                            "severity": "INFO",
                            "category": "Network",
                            "title": f"Found {len(open_ports)} open ports",
                            "description": "Port scanning completed",
                            "recommendation": "Review open ports for security."
                        })
                
                # Technology findings
                technologies = active.get('technologies', {})
                if technologies and technologies.get('note') != 'Not executed':
                    if isinstance(technologies, dict):
                        tech_count = sum(len(techs) for techs in technologies.values() 
                                        if isinstance(techs, list))
                        if tech_count > 0:
                            findings.append({
                                "severity": "INFO",
                                "category": "Web",
                                "title": f"Detected {tech_count} technologies",
                                "description": "Various web technologies identified",
                                "recommendation": "Keep technologies updated."
                            })
        
        except Exception as e:
            self.logger.warning(f"Analysis had issues: {str(e)}")
            findings.append({
                "severity": "INFO",
                "category": "System",
                "title": "Analysis completed with some issues",
                "description": f"Some data analysis failed: {str(e)}",
                "recommendation": "Review raw scan data for complete results."
            })
        
        # Always add at least one finding
        if not findings:
            findings.append({
                "severity": "INFO",
                "category": "Scan",
                "title": "Reconnaissance completed",
                "description": f"Scan completed on {self.target}",
                "recommendation": "Review detailed report."
            })
        
        self.results['findings'] = findings
    
    def _generate_risk_assessment(self):
        """Generate basic risk assessment - safe version."""
        try:
            risk_score = 0
            factors = []
            
            # Calculate based on findings
            for finding in self.results.get('findings', []):
                severity = finding.get('severity', 'INFO')
                if severity == 'HIGH':
                    risk_score += 10
                elif severity == 'MEDIUM':
                    risk_score += 5
                elif severity == 'LOW':
                    risk_score += 2
                else:
                    risk_score += 1
                factors.append(f"{severity.lower()}_finding")
            
            # Determine risk level
            if risk_score >= 20:
                risk_level = "HIGH"
            elif risk_score >= 10:
                risk_level = "MEDIUM"
            elif risk_score >= 5:
                risk_level = "LOW"
            else:
                risk_level = "INFO"
            
            self.results['risk_assessment'] = {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "factors_considered": factors,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.warning(f"Risk assessment failed: {str(e)}")
            self.results['risk_assessment'] = {
                "risk_score": 0,
                "risk_level": "INFO",
                "factors_considered": ["assessment_error"],
                "timestamp": datetime.now().isoformat(),
                "note": f"Risk assessment incomplete: {str(e)}"
            }


def main():
    """Command-line interface for the reconnaissance tool."""
    parser = argparse.ArgumentParser(
        description=f'CYS-ILM Reconnaissance Tool v{__version__}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{__author__}
{__license__}

EXAMPLES:
  # Full comprehensive scan
  python3 CYS_ilm_recon_tool.py example.com --all --output html
  
  # Passive reconnaissance only
  python3 CYS_ilm_recon_tool.py example.com --passive --dns --subdomains
  
  # Active reconnaissance only
  python3 CYS_ilm_recon_tool.py example.com --active --scan --tech
  
  # Quick security assessment
  python3 CYS_ilm_recon_tool.py example.com --quick
  
  # Custom port scan
  python3 CYS_ilm_recon_tool.py example.com --active --ports 1-1000 --scan-type quick
  
  # Specific modules only
  python3 CYS_ilm_recon_tool.py example.com --whois --dns --tech
        """
    )
    
    # Required arguments
    parser.add_argument('target', help='Target domain or IP address')
    
    # Scan modes
    scan_group = parser.add_argument_group('Scan Modes')
    scan_group.add_argument('--all', action='store_true', 
                          help='Perform comprehensive reconnaissance')
    scan_group.add_argument('--passive', action='store_true', 
                          help='Perform passive reconnaissance only')
    scan_group.add_argument('--active', action='store_true', 
                          help='Perform active reconnaissance only')
    scan_group.add_argument('--quick', action='store_true', 
                          help='Quick scan (common ports and basic checks)')
    
    # Passive reconnaissance options
    passive_group = parser.add_argument_group('Passive Reconnaissance')
    passive_group.add_argument('--whois', action='store_true', 
                             help='Perform WHOIS lookup')
    passive_group.add_argument('--dns', action='store_true', 
                             help='Enumerate DNS records')
    passive_group.add_argument('--subdomains', action='store_true', 
                             help='Discover subdomains')
    
    # Active reconnaissance options
    active_group = parser.add_argument_group('Active Reconnaissance')
    active_group.add_argument('--scan', action='store_true', 
                            help='Perform port scanning')
    active_group.add_argument('--ports', default='1-1000',
                            help='Ports to scan (default: 1-1000)')
    active_group.add_argument('--scan-type', choices=['quick', 'standard', 'comprehensive'],
                            default='quick', help='Scan intensity level')
    active_group.add_argument('--banners', action='store_true',
                            help='Grab service banners')
    active_group.add_argument('--tech', action='store_true',
                            help='Detect web technologies')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', choices=['txt', 'html', 'json', 'all'],
                            default='txt', help='Output format')
    output_group.add_argument('--output-dir', default='outputs',
                            help='Output directory (default: outputs/)')
    output_group.add_argument('--no-report', action='store_true',
                            help='Skip report generation')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--timeout', type=int, default=10,
                          help='Timeout in seconds (default: 10)')
    
    # Verbosity options
    verbosity_group = parser.add_argument_group('Verbosity Options')
    verbosity_group.add_argument('-v', '--verbose', action='count', default=0,
                               help='Increase verbosity level (-v, -vv, -vvv)')
    verbosity_group.add_argument('-q', '--quiet', action='store_true',
                               help='Suppress non-essential output')
    
    # Additional options
    parser.add_argument('--version', action='version', 
                       version=f'CYS-ILM Recon Tool v{__version__}')
    
    args = parser.parse_args()
    
    try:
        # Set verbosity
        verbose = args.verbose > 0
        if args.quiet:
            verbose = False
        
        # Determine scan options
        scan_options = {
            'passive': False,
            'active': False,
            'whois': False,
            'dns': False,
            'subdomains': False,
            'scan': False,
            'banners': False,
            'tech': False,
            'ports': args.ports,
            'scan_type': args.scan_type,
            'timeout': args.timeout
        }
        
        # Set based on scan modes
        if args.all:
            scan_options.update({
                'passive': True,
                'active': True,
                'whois': True,
                'dns': True,
                'subdomains': True,
                'scan': True,
                'banners': True,
                'tech': True
            })
        elif args.passive:
            scan_options.update({
                'passive': True,
                'whois': args.whois or True,
                'dns': args.dns or True,
                'subdomains': args.subdomains or True
            })
        elif args.active:
            scan_options.update({
                'active': True,
                'scan': args.scan or True,
                'banners': args.banners or True,
                'tech': args.tech or True
            })
        elif args.quick:
            scan_options.update({
                'passive': True,
                'active': True,
                'whois': True,
                'dns': True,
                'scan': True,
                'tech': True,
                'ports': '21,22,23,25,53,80,110,143,443,445,993,995,8080',
                'scan_type': 'quick'
            })
        else:
            # Individual module selection
            if args.whois or args.dns or args.subdomains:
                scan_options['passive'] = True
                scan_options['whois'] = args.whois
                scan_options['dns'] = args.dns
                scan_options['subdomains'] = args.subdomains
            
            if args.scan or args.banners or args.tech:
                scan_options['active'] = True
                scan_options['scan'] = args.scan
                scan_options['banners'] = args.banners
                scan_options['tech'] = args.tech
        
        # If nothing selected, default to passive
        if not any([scan_options['passive'], scan_options['active']]):
            scan_options['passive'] = True
            scan_options['whois'] = True
            scan_options['dns'] = True
        
        # Initialize and run tool
        tool = CYSilmReconTool(
            target=args.target,
            verbose=verbose,
            output_dir=args.output_dir
        )
        
        results = tool.run_comprehensive_scan(scan_options)
        
        # Generate reports if requested
        if not args.no_report:
            reporter = ReportGenerator(results, args.output_dir)
            
            reports_generated = []
            
            if args.output in ['txt', 'all']:
                try:
                    txt_report = reporter.generate_text_report()
                    reports_generated.append(f"📄 Text: {txt_report}")
                except Exception as e:
                    print(f"⚠️  Failed to generate text report: {str(e)}")
            
            if args.output in ['html', 'all']:
                try:
                    html_report = reporter.generate_html_report()
                    reports_generated.append(f"🌐 HTML: {html_report}")
                except Exception as e:
                    print(f"⚠️  Failed to generate HTML report: {str(e)}")
            
            if args.output in ['json', 'all']:
                try:
                    json_report = reporter.generate_json_report()
                    reports_generated.append(f"📊 JSON: {json_report}")
                except Exception as e:
                    print(f"⚠️  Failed to generate JSON report: {str(e)}")
            
            # Print summary
            if not args.quiet:
                if reports_generated:
                    print(f"\n📁 Reports saved:")
                    for report in reports_generated:
                        print(f"  {report}")
                
                print(f"\n✅ CYS-ILM reconnaissance completed successfully!")
                print(f"🎯 Target: {args.target}")
                print(f"⏱️  Duration: {results['metadata'].get('end_time', 'N/A')}")
                
                # Show quick findings
                findings = results.get('findings', [])
                if findings:
                    print(f"\n🔍 Key Findings ({len(findings)}):")
                    for finding in findings[:3]:  # Show first 3
                        print(f"  • [{finding.get('severity', 'INFO')}] {finding.get('title', 'N/A')}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())