"""
Professional Reporting Module
Generate comprehensive reports in multiple formats
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
import logging
from jinja2 import Template


class ReportGenerator:
    """Generate professional reconnaissance reports."""
    
    def __init__(self, results: Dict[str, Any], output_dir: str = "outputs"):
        """Initialize report generator.
        
        Args:
            results: Reconnaissance results
            output_dir: Output directory
        """
        self.logger = logging.getLogger(__name__)
        self.results = results
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_text_report(self) -> str:
        """Generate comprehensive text report."""
        try:
            target = self.results['metadata']['target']
            filename = f"recon_{target}_{self.timestamp}.txt"
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self._format_text_report())
            
            self.logger.info(f"Text report saved to {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate text report: {str(e)}")
            raise
    
    def generate_html_report(self) -> str:
        """Generate professional HTML report."""
        try:
            target = self.results['metadata']['target']
            filename = f"recon_{target}_{self.timestamp}.html"
            filepath = os.path.join(self.output_dir, filename)
            
            # Generate HTML content
            html_content = self._generate_html_content()
            
            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved to {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def generate_json_report(self) -> str:
        """Generate JSON report with all data."""
        try:
            target = self.results['metadata']['target']
            filename = f"recon_{target}_{self.timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            self.logger.info(f"JSON report saved to {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        summary = []
        
        # Header
        summary.append("=" * 70)
        summary.append("EXECUTIVE SUMMARY")
        summary.append("=" * 70)
        summary.append(f"Target: {self.results['metadata']['target']}")
        summary.append(f"Scan ID: {self.results['metadata']['scan_id']}")
        summary.append(f"Date: {self.results['metadata']['start_time']}")
        summary.append("")
        
        # Risk Assessment
        risk = self.results.get('risk_assessment', {})
        if risk:
            summary.append("RISK ASSESSMENT:")
            summary.append(f"  Risk Level: {risk.get('risk_level', 'N/A')}")
            summary.append(f"  Risk Score: {risk.get('risk_score', 'N/A')}/100")
            summary.append("")
        
        # Key Findings
        summary.append("KEY FINDINGS:")
        
        # Open ports
        active = self.results.get('active', {})
        port_scan = active.get('port_scan', {})
        open_ports = port_scan.get('open_ports', [])
        if open_ports:
            summary.append(f"  • Open Ports: {len(open_ports)} discovered")
            critical_ports = [p['port'] for p in open_ports if p['port'] in [22, 23, 21, 3389]]
            if critical_ports:
                summary.append(f"    Critical services: {', '.join(map(str, critical_ports))}")
        
        # Subdomains
        passive = self.results.get('passive', {})
        subdomains = passive.get('subdomains', {})
        if subdomains:
            valid_count = subdomains.get('total_valid', 0)
            if valid_count > 0:
                summary.append(f"  • Subdomains: {valid_count} discovered")
        
        # Technologies
        technologies = active.get('technologies', {})
        tech_count = sum(len(techs) for techs in technologies.values())
        if tech_count > 0:
            summary.append(f"  • Technologies: {tech_count} identified")
        
        # Vulnerabilities
        vuln_checks = active.get('vulnerability_checks', {})
        if vuln_checks.get('issues'):
            summary.append(f"  • Security Issues: {len(vuln_checks['issues'])} found")
        
        summary.append("")
        summary.append("DETAILED REPORTS:")
        summary.append("  • Full report available in output directory")
        summary.append("  • Risk mitigation recommendations included")
        summary.append("=" * 70)
        
        return '\n'.join(summary)
    
    def _format_text_report(self) -> str:
        """Format comprehensive text report."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("CYS-ilm RECONNAISSANCE REPORT")
        lines.append("=" * 80)
        lines.append(f"Target: {self.results['metadata']['target']}")
        lines.append(f"Scan ID: {self.results['metadata']['scan_id']}")
        lines.append(f"Start Time: {self.results['metadata']['start_time']}")
        lines.append(f"End Time: {self.results['metadata'].get('end_time', 'N/A')}")
        lines.append(f"Tool Version: {self.results['metadata']['tool_version']}")
        lines.append("")
        
        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        lines.append(self.generate_executive_summary())
        lines.append("")
        
        # Risk Assessment
        risk = self.results.get('risk_assessment', {})
        if risk:
            lines.append("RISK ASSESSMENT")
            lines.append("-" * 80)
            lines.append(f"Risk Level: {risk.get('risk_level', 'N/A')}")
            lines.append(f"Risk Score: {risk.get('risk_score', 'N/A')}")
            lines.append(f"Factors: {', '.join(risk.get('factors_considered', []))}")
            lines.append("")
        
        # Passive Reconnaissance
        passive = self.results.get('passive', {})
        if passive:
            lines.append("PASSIVE RECONNAISSANCE")
            lines.append("=" * 80)
            
            # WHOIS
            if 'whois' in passive and passive['whois']:
                lines.append("\nWHOIS INFORMATION")
                lines.append("-" * 40)
                whois_data = passive['whois']
                for key, value in whois_data.items():
                    if value and key != 'raw_data':
                        if isinstance(value, list):
                            lines.append(f"  {key}:")
                            for item in value:
                                lines.append(f"    • {item}")
                        else:
                            lines.append(f"  {key}: {value}")
            
            # DNS Records
            if 'dns' in passive and passive['dns']:
                lines.append("\nDNS ENUMERATION")
                lines.append("-" * 40)
                dns_data = passive['dns']
                
                # Summary
                if 'summary' in dns_data:
                    summary = dns_data['summary']
                    lines.append(f"  Total Records: {summary.get('total_records', 0)}")
                    lines.append(f"  IP Addresses: {', '.join(summary.get('ip_addresses', []))}")
                    lines.append("")
                
                # Detailed records
                if 'records' in dns_data:
                    for record_type, records in dns_data['records'].items():
                        if records and record_type not in ['error']:
                            lines.append(f"  {record_type} Records:")
                            for record in records:
                                lines.append(f"    • {record}")
            
            # Subdomains
            if 'subdomains' in passive and passive['subdomains']:
                lines.append("\nSUBDOMAIN DISCOVERY")
                lines.append("-" * 40)
                subdomain_data = passive['subdomains']
                
                lines.append(f"  Total Discovered: {subdomain_data.get('total_discovered', 0)}")
                lines.append(f"  Valid Subdomains: {subdomain_data.get('total_valid', 0)}")
                
                if 'validated_subdomains' in subdomain_data:
                    lines.append("\n  Valid Subdomains:")
                    for subdomain in subdomain_data['validated_subdomains'][:20]:  # First 20
                        lines.append(f"    • {subdomain['subdomain']} ({subdomain['ip_address']})")
                    
                    if len(subdomain_data['validated_subdomains']) > 20:
                        lines.append(f"    ... and {len(subdomain_data['validated_subdomains']) - 20} more")
        
        # Active Reconnaissance
        active = self.results.get('active', {})
        if active:
            lines.append("\n\nACTIVE RECONNAISSANCE")
            lines.append("=" * 80)
            
            # Port Scan Results
            if 'port_scan' in active and active['port_scan']:
                lines.append("\nPORT SCAN RESULTS")
                lines.append("-" * 40)
                port_data = active['port_scan']
                
                stats = port_data.get('statistics', {})
                lines.append(f"  Total Ports Scanned: {stats.get('total_ports_scanned', 0)}")
                lines.append(f"  Open Ports: {stats.get('open_count', 0)}")
                lines.append(f"  Filtered Ports: {stats.get('filtered_count', 0)}")
                
                if port_data.get('open_ports'):
                    lines.append("\n  Open Ports Details:")
                    for port_info in port_data['open_ports'][:15]:  # First 15
                        lines.append(f"    • {port_info['port']}/tcp - {port_info['service']}")
                        if port_info.get('product'):
                            lines.append(f"      Product: {port_info['product']} {port_info.get('version', '')}")
                        if port_info.get('script_output'):
                            lines.append(f"      Scripts: {len(port_info['script_output'])} executed")
            
            # Technologies
            if 'technologies' in active and active['technologies']:
                lines.append("\nTECHNOLOGY DETECTION")
                lines.append("-" * 40)
                tech_data = active['technologies']
                
                for category, tech_list in tech_data.items():
                    if tech_list and category not in ['error']:
                        lines.append(f"  {category.replace('_', ' ').title()}:")
                        for tech in tech_list[:10]:  # First 10
                            lines.append(f"    • {tech}")
                        if len(tech_list) > 10:
                            lines.append(f"      ... and {len(tech_list) - 10} more")
            
            # Vulnerability Checks
            if 'vulnerability_checks' in active and active['vulnerability_checks']:
                lines.append("\nVULNERABILITY CHECKS")
                lines.append("-" * 40)
                vuln_data = active['vulnerability_checks']
                
                for check_type, findings in [('issues', vuln_data.get('issues', [])),
                                           ('warnings', vuln_data.get('warnings', [])),
                                           ('info', vuln_data.get('info', []))]:
                    if findings:
                        lines.append(f"  {check_type.title()}:")
                        for finding in findings[:5]:  # First 5
                            lines.append(f"    • {finding}")
        
        # Findings and Recommendations
        findings = self.results.get('findings', [])
        if findings:
            lines.append("\n\nFINDINGS AND RECOMMENDATIONS")
            lines.append("=" * 80)
            
            for finding in findings:
                lines.append(f"\n[{finding.get('severity', 'INFO')}] {finding.get('title', 'N/A')}")
                lines.append(f"Category: {finding.get('category', 'General')}")
                lines.append(f"Description: {finding.get('description', 'N/A')}")
                lines.append(f"Recommendation: {finding.get('recommendation', 'N/A')}")
                lines.append("-" * 40)
        
        # Footer
        lines.append("\n" + "=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated by CYS-ilm Reconnaissance Tool v{self.results['metadata']['tool_version']}")
        lines.append("CYS-ilm Security Team - Confidential")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def _generate_html_content(self) -> str:
        """Generate HTML report content."""
        # HTML template with CSS
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYS-ilm Reconnaissance Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #00b4db, #0083b0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .metadata {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .metadata-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .metadata-label {
            font-weight: 600;
            color: #495057;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .metadata-value {
            color: #2c3e50;
            font-size: 1.1em;
            margin-top: 5px;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }
        
        .risk-high {
            background: #dc3545;
            color: white;
        }
        
        .risk-medium {
            background: #ffc107;
            color: #212529;
        }
        
        .risk-low {
            background: #28a745;
            color: white;
        }
        
        .risk-info {
            background: #17a2b8;
            color: white;
        }
        
        .section {
            padding: 30px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .section-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
            color: white;
            font-size: 1.5em;
        }
        
        .section-title {
            font-size: 1.8em;
            color: #2c3e50;
            font-weight: 600;
        }
        
        .subsection {
            margin-bottom: 25px;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
            border: 1px solid #e9ecef;
        }
        
        .subsection-title {
            font-size: 1.3em;
            color: #495057;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #dee2e6;
            font-weight: 600;
        }
        
        .data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        
        .data-item {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }
        
        .data-label {
            font-weight: 600;
            color: #495057;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .data-value {
            color: #2c3e50;
            margin-top: 5px;
            font-size: 1em;
            word-break: break-word;
        }
        
        .table-container {
            overflow-x: auto;
            margin-top: 15px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
            color: #495057;
        }
        
        tr:hover {
            background-color: #f8f9fa;
        }
        
        .port-open {
            background-color: #d4edda !important;
            color: #155724;
        }
        
        .port-filtered {
            background-color: #fff3cd !important;
            color: #856404;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-high {
            background: #dc3545;
            color: white;
        }
        
        .severity-medium {
            background: #ffc107;
            color: #212529;
        }
        
        .severity-low {
            background: #28a745;
            color: white;
        }
        
        .severity-info {
            background: #17a2b8;
            color: white;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 25px;
            text-align: center;
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .footer p {
            margin: 5px 0;
        }
        
        .timestamp {
            font-size: 0.8em;
            color: #adb5bd;
            margin-top: 10px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border: 2px solid transparent;
            transition: all 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            border-color: #667eea;
        }
        
        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }
        
        .summary-label {
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                border-radius: 10px;
                margin: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .section {
                padding: 20px;
            }
            
            .data-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-cards {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 480px) {
            .summary-cards {
                grid-template-columns: 1fr;
            }
            
            .metadata-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .tech-tag {
            display: inline-block;
            background: #e9ecef;
            padding: 3px 8px;
            border-radius: 12px;
            margin: 2px;
            font-size: 0.85em;
            color: #495057;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 CYS-ilm Reconnaissance Report</h1>
            <p>Comprehensive Security Assessment</p>
        </div>
        
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Target</div>
                    <div class="metadata-value">{{ target }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Scan ID</div>
                    <div class="metadata-value">{{ scan_id }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Start Time</div>
                    <div class="metadata-value">{{ start_time }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Risk Level</div>
                    <div class="metadata-value">
                        <span class="risk-badge {{ risk_class }}">{{ risk_level }}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <div class="section-icon">📊</div>
                <div class="section-title">Executive Summary</div>
            </div>
            
            <div class="summary-cards">
                <div class="summary-card">
                    <div class="summary-number">{{ open_ports }}</div>
                    <div class="summary-label">Open Ports</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{{ subdomains }}</div>
                    <div class="summary-label">Subdomains</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{{ technologies }}</div>
                    <div class="summary-label">Technologies</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{{ vulnerabilities }}</div>
                    <div class="summary-label">Issues</div>
                </div>
            </div>
        </div>
        
        {% if passive %}
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🕵️</div>
                <div class="section-title">Passive Reconnaissance</div>
            </div>
            
            {% if passive.whois %}
            <div class="subsection">
                <div class="subsection-title">WHOIS Information</div>
                <div class="data-grid">
                    {% for key, value in passive.whois.items() %}
                    {% if value and key != 'raw_data' %}
                    <div class="data-item">
                        <div class="data-label">{{ key }}</div>
                        <div class="data-value">
                            {% if value is iterable and value is not string %}
                                {% for item in value %}
                                    {{ item }}<br>
                                {% endfor %}
                            {% else %}
                                {{ value }}
                            {% endif %}
                        </div>
                    </div>
                    {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            
            {% if passive.dns %}
            <div class="subsection">
                <div class="subsection-title">DNS Records</div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Records</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for record_type, records in passive.dns.records.items() %}
                            {% if records and record_type != 'error' %}
                            <tr>
                                <td>{{ record_type }}</td>
                                <td>
                                    {% for record in records %}
                                    {{ record }}<br>
                                    {% endfor %}
                                </td>
                            </tr>
                            {% endif %}
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if active %}
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚡</div>
                <div class="section-title">Active Reconnaissance</div>
            </div>
            
            {% if active.port_scan and active.port_scan.open_ports %}
            <div class="subsection">
                <div class="subsection-title">Open Ports</div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Product</th>
                                <th>Version</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for port in active.port_scan.open_ports %}
                            <tr class="port-open">
                                <td>{{ port.port }}/{{ port.protocol }}</td>
                                <td>{{ port.service }}</td>
                                <td>{{ port.product }}</td>
                                <td>{{ port.version }}</td>
                                <td>{{ port.state }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}
            
            {% if active.technologies %}
            <div class="subsection">
                <div class="subsection-title">Detected Technologies</div>
                <div class="data-grid">
                    {% for category, tech_list in active.technologies.items() %}
                    {% if tech_list and category != 'error' %}
                    <div class="data-item">
                        <div class="data-label">{{ category }}</div>
                        <div class="data-value">
                            {% for tech in tech_list %}
                            <span class="tech-tag">{{ tech }}</span>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if findings %}
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚠️</div>
                <div class="section-title">Findings & Recommendations</div>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in findings %}
                        <tr>
                            <td>
                                <span class="severity-badge severity-{{ finding.severity|lower }}">
                                    {{ finding.severity }}
                                </span>
                            </td>
                            <td>{{ finding.category }}</td>
                            <td>{{ finding.title }}<br><small>{{ finding.description }}</small></td>
                            <td>{{ finding.recommendation }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Generated by CYSILM Reconnaissance Tool v{{ tool_version }}</p>
            <p>CYSILM Security Team - Confidential</p>
            <p class="timestamp">Report generated: {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare data for template
        target = self.results['metadata']['target']
        scan_id = self.results['metadata']['scan_id']
        start_time = self.results['metadata']['start_time']
        tool_version = self.results['metadata']['tool_version']
        
        # Risk assessment
        risk = self.results.get('risk_assessment', {})
        risk_level = risk.get('risk_level', 'INFO')
        risk_class = f"risk-{risk_level.lower()}"
        
        # Statistics
        active = self.results.get('active', {})
        passive = self.results.get('passive', {})
        
        open_ports = len(active.get('port_scan', {}).get('open_ports', []))
        subdomains = passive.get('subdomains', {}).get('total_valid', 0)
        
        tech_data = active.get('technologies', {})
        technologies = sum(len(techs) for techs in tech_data.values())
        
        vuln_data = active.get('vulnerability_checks', {})
        vulnerabilities = len(vuln_data.get('issues', []))
        
        # Create template context
        context = {
            'target': target,
            'scan_id': scan_id,
            'start_time': start_time,
            'risk_level': risk_level,
            'risk_class': risk_class,
            'open_ports': open_ports,
            'subdomains': subdomains,
            'technologies': technologies,
            'vulnerabilities': vulnerabilities,
            'passive': passive,
            'active': active,
            'findings': self.results.get('findings', []),
            'tool_version': tool_version,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Render template
        template = Template(html_template)
        return template.render(**context)