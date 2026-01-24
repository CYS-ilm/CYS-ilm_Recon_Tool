"""
Enhanced Active Reconnaissance Module - OPTIMIZED VERSION
CYS-ILM Security Tool
"""

import nmap
import socket
import requests
import ssl
import json
import re
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple
import logging
import time
from urllib.parse import urlparse
import ipaddress
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logger = logging.getLogger(__name__)

class ActiveReconnaissance:
    """CYS-ILM active reconnaissance operations."""
    
    def __init__(self, verbose: bool = False):
        """Initialize active reconnaissance module.
        
        Args:
            verbose: Enable verbose logging
        """
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        
        # Initialize nmap scanner
        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            logger.error(f"Failed to initialize Nmap: {str(e)}")
            raise
        
        # Configuration
        self.timeout = 3  # Reduced timeout
        self.max_threads = 20
        
        # Common ports for various services
        self.common_ports = {
            'web': [80, 443, 8080, 8443],
            'database': [3306, 5432, 27017],
            'mail': [25, 110, 143, 465, 587, 993, 995],
            'file': [21, 22, 23, 139, 445, 2049],
            'remote': [3389, 5900],
            'dns': [53],
            'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080]
        }
    
    def comprehensive_port_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform optimized port scanning.
        
        Args:
            target: Target domain or IP
            **kwargs: Additional scan options
            
        Returns:
            Port scan results
        """
        ports = kwargs.get('ports', '1-1000')
        scan_type = kwargs.get('scan_type', 'quick')
        timing = kwargs.get('timing_template', 3)
        
        logger.info(f"Starting {scan_type} port scan on {target} (ports: {ports})")
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'ports_scanned': ports,
            'open_ports': [],
            'scan_stats': {},
            'start_time': time.time()
        }
        
        try:
            # Build optimized nmap arguments
            nmap_args = self._build_nmap_arguments(scan_type, timing)
            
            logger.debug(f"Nmap arguments: {nmap_args}")
            
            # Perform the scan with timeout protection
            try:
                self.nm.scan(target, ports, arguments=nmap_args, timeout=300)  # 5 min timeout
            except Exception as scan_error:
                error_msg = str(scan_error)
                if "requires root" in error_msg.lower() or "privileges" in error_msg.lower():
                    logger.warning("Root privileges required, falling back to TCP connect scan")
                    # Fallback to non-privileged scan
                    nmap_args = self._build_nmap_arguments('tcp_connect', timing)
                    self.nm.scan(target, ports, arguments=nap_args, timeout=300)
                else:
                    raise
            
            # Process results
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                # Extract port information
                for proto in host_info.all_protocols():
                    port_list = host_info[proto].keys()
                    
                    for port in port_list:
                        port_info = host_info[proto][port]
                        state = port_info['state']
                        
                        if state == 'open':
                            port_data = {
                                'port': port,
                                'protocol': proto,
                                'state': state,
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'cpe': port_info.get('cpe', '')
                            }
                            results['open_ports'].append(port_data)
                            
                            # Log found ports immediately
                            logger.info(f"Found open port: {port}/{proto} - {port_info.get('name', 'unknown')}")
            
            # Calculate statistics
            end_time = time.time()
            duration = end_time - results['start_time']
            
            results['scan_stats'] = {
                'total_scanned': len(results['open_ports']),
                'open_count': len(results['open_ports']),
                'duration_seconds': round(duration, 2),
                'scan_speed': f"{len(results['open_ports'])/max(duration, 0.1):.1f} ports/sec",
                'status': 'completed'
            }
            
            logger.info(f"Port scan completed: {len(results['open_ports'])} open ports found in {duration:.1f}s")
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            results['error'] = str(e)
            results['scan_stats']['status'] = 'failed'
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            results['error'] = str(e)
            results['scan_stats']['status'] = 'failed'
        
        results['end_time'] = time.time()
        return results
    
    def _build_nmap_arguments(self, scan_type: str, timing: int) -> str:
        """Build optimized Nmap arguments.
        
        Args:
            scan_type: Type of scan
            timing: Timing template (1-5)
            
        Returns:
            Nmap arguments string
        """
        args_map = {
            'quick': f'-T{timing} -F --max-retries 1 --min-rate=100',
            'standard': f'-T{timing} -sS --max-retries 2 --min-rate=50',
            'comprehensive': f'-T{timing} -sS -sV -sC --max-retries 2 --min-rate=20',
            'tcp_connect': f'-T{timing} -sT --max-retries 1 --min-rate=50',
            'stealth': f'-T{timing} -sS -f --mtu 24 --max-retries 1'
        }
        
        # Default to quick scan if type not found
        nmap_args = args_map.get(scan_type, args_map['quick'])
        
        # Add common options
        nmap_args += ' -Pn'  # Skip host discovery
        nmap_args += ' --open'  # Only show open ports
        
        return nmap_args
    
    def banner_grabbing(self, target: str, ports: List[int] = None) -> Dict[int, Dict[str, Any]]:
        """Grab service banners from ports.
        
        Args:
            target: Target domain or IP
            ports: List of ports to check
            
        Returns:
            Banner information
        """
        logger.info(f"Starting banner grabbing on {target}")
        
        # Use common ports if none specified
        if ports is None:
            ports = self.common_ports['common']
            logger.info(f"No ports specified, using {len(ports)} common ports")
        
        results = {}
        found_count = 0
        
        try:
            # Use thread pool for faster banner grabbing
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), self.max_threads)) as executor:
                future_to_port = {
                    executor.submit(self._grab_single_banner, target, port): port 
                    for port in ports
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        banner_info = future.result(timeout=5)
                        if banner_info and banner_info.get('banner'):
                            results[port] = banner_info
                            found_count += 1
                            logger.debug(f"Got banner from port {port}: {banner_info['banner'][:50]}...")
                    except concurrent.futures.TimeoutError:
                        logger.debug(f"Banner grab timeout on port {port}")
                    except Exception as e:
                        logger.debug(f"Banner grab failed on port {port}: {str(e)[:50]}")
        
        except Exception as e:
            logger.error(f"Banner grabbing failed: {str(e)}")
        
        logger.info(f"Banner grabbing completed: {found_count} banners found")
        return results
    
    def _grab_single_banner(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Grab banner from a single port.
        
        Args:
            target: Target domain or IP
            port: Port number
            
        Returns:
            Banner information or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect to port
            sock.connect((target, port))
            
            # Try to receive initial banner
            banner = b''
            try:
                sock.settimeout(1)
                banner = sock.recv(1024)
            except socket.timeout:
                pass
            
            # Service-specific probes
            extra_info = {}
            
            if port in [80, 443, 8080, 8443]:
                # HTTP/HTTPS
                try:
                    probe = f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
                    sock.send(probe)
                    response = sock.recv(2048)
                    extra_info['http_response'] = response.decode('utf-8', errors='ignore')[:500]
                except:
                    pass
            
            elif port == 21:
                # FTP
                try:
                    sock.send(b"SYST\r\n")
                    response = sock.recv(1024)
                    extra_info['ftp_response'] = response.decode('utf-8', errors='ignore')
                except:
                    pass
            
            elif port == 22:
                # SSH - just get the banner
                pass
            
            sock.close()
            
            if banner:
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                return {
                    'port': port,
                    'banner': banner_text,
                    'extra_info': extra_info
                }
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None
        
        return None
    
    def technology_detection(self, target: str, ports: List[int] = None) -> Dict[str, List[str]]:
        """Detect web technologies.
        
        Args:
            target: Target domain
            ports: List of ports to check
            
        Returns:
            Detected technologies by category
        """
        logger.info(f"Starting technology detection on {target}")
        
        if ports is None:
            ports = [80, 443, 8080, 8443]
        
        results = {
            'web_server': [],
            'programming_language': [],
            'framework': [],
            'javascript': [],
            'database': [],
            'cms': [],
            'analytics': [],
            'cdn': [],
            'security': [],
            'miscellaneous': []
        }
        
        try:
            for port in ports:
                # Try HTTP and HTTPS
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{target}:{port}"
                    
                    try:
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                        
                        response = requests.get(
                            url, 
                            headers=headers, 
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=True
                        )
                        
                        # Analyze headers
                        self._analyze_headers(response.headers, results)
                        
                        # Analyze HTML content
                        if 'text/html' in response.headers.get('Content-Type', '').lower():
                            self._analyze_html_content(response.text, results)
                        
                        # Found a working service, break
                        break
                        
                    except requests.RequestException:
                        continue
                    except Exception as e:
                        logger.debug(f"Tech detection error on {url}: {str(e)[:50]}")
                        continue
            
            # Clean up results (remove empty categories)
            cleaned_results = {k: v for k, v in results.items() if v}
            
            tech_count = sum(len(v) for v in cleaned_results.values())
            logger.info(f"Technology detection completed: {tech_count} technologies found")
            
            return cleaned_results
            
        except Exception as e:
            logger.error(f"Technology detection failed: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_headers(self, headers: Dict, results: Dict[str, List[str]]):
        """Analyze HTTP headers for technology indicators."""
        # Server header
        server = headers.get('Server', '')
        if server:
            results['web_server'].append(server)
        
        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            if 'php' in powered_by.lower():
                results['programming_language'].append('PHP')
            elif 'asp.net' in powered_by.lower():
                results['programming_language'].append('ASP.NET')
                results['framework'].append('ASP.NET')
            else:
                results['framework'].append(powered_by)
        
        # X-Generator header (CMS)
        generator = headers.get('X-Generator', '')
        if generator:
            if 'wordpress' in generator.lower():
                results['cms'].append('WordPress')
            elif 'joomla' in generator.lower():
                results['cms'].append('Joomla')
            elif 'drupal' in generator.lower():
                results['cms'].append('Drupal')
        
        # Security headers
        security_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 
                          'X-Frame-Options', 'X-Content-Type-Options']
        for header in security_headers:
            if header in headers:
                results['security'].append(header)
    
    def _analyze_html_content(self, html: str, results: Dict[str, List[str]]):
        """Analyze HTML content for technology indicators."""
        html_lower = html.lower()
        
        # Framework detection
        framework_patterns = {
            'jquery': [r'jquery(?:\.min)?\.js'],
            'react': [r'react', r'react-dom'],
            'angular': [r'angular', r'ng-'],
            'vue': [r'vue', r'v-bind'],
            'bootstrap': [r'bootstrap', r'btn-']
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower):
                    if framework not in results['framework']:
                        results['framework'].append(framework)
                    break
        
        # CMS detection
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
            'Joomla': [r'joomla', r'templates/joomla'],
            'Drupal': [r'drupal', r'sites/all']
        }
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if pattern in html_lower:
                    if cms not in results['cms']:
                        results['cms'].append(cms)
                    break
        
        # Analytics detection
        analytics_patterns = [
            r'google-analytics\.com',
            r'gtm\.js',
            r'googletagmanager\.com',
            r'facebook\.com/tr'
        ]
        
        for pattern in analytics_patterns:
            if re.search(pattern, html_lower):
                provider = pattern.split('.')[0] if '.' in pattern else pattern.split('/')[0]
                if provider not in results['analytics']:
                    results['analytics'].append(provider)
        
        # CDN detection
        cdn_patterns = [
            r'cloudflare',
            r'cloudfront',
            r'akamai',
            r'fastly'
        ]
        
        for pattern in cdn_patterns:
            if re.search(pattern, html_lower):
                if pattern not in results['cdn']:
                    results['cdn'].append(pattern)
    
    def http_header_analysis(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP security headers.
        
        Args:
            target: Target domain
            
        Returns:
            Header analysis results
        """
        logger.info(f"Starting HTTP header analysis on {target}")
        
        results = {
            'security_headers': {},
            'missing_headers': [],
            'issues': [],
            'grade': 'F',
            'tested_urls': []
        }
        
        security_headers = {
            'Content-Security-Policy': 'Prevents XSS attacks',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Referrer-Policy': 'Controls referrer information'
        }
        
        try:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{target}"
                results['tested_urls'].append(url)
                
                try:
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    
                    # Check each security header
                    for header, description in security_headers.items():
                        if header in response.headers:
                            results['security_headers'][header] = {
                                'value': response.headers[header],
                                'description': description,
                                'present': True
                            }
                        else:
                            results['security_headers'][header] = {
                                'value': None,
                                'description': description,
                                'present': False
                            }
                            results['missing_headers'].append(header)
                    
                    # Check for common issues
                    self._check_header_issues(response.headers, results)
                    
                    # Calculate security grade
                    results['grade'] = self._calculate_security_grade(
                        len(results['security_headers']),
                        len(results['missing_headers']),
                        len(results['issues'])
                    )
                    
                    logger.info(f"HTTP header analysis completed: Grade {results['grade']}")
                    return results
                    
                except requests.RequestException:
                    continue
            
            # If we get here, no URL worked
            results['error'] = 'Could not connect to target'
            return results
            
        except Exception as e:
            logger.error(f"HTTP header analysis failed: {str(e)}")
            return {'error': str(e)}
    
    def _check_header_issues(self, headers: Dict, results: Dict[str, Any]):
        """Check for common HTTP header issues."""
        # Server version disclosure
        server = headers.get('Server', '')
        if server and any(x in server.lower() for x in ['apache', 'nginx', 'iis']):
            if any(str(i) in server for i in range(10)):  # Contains version number
                results['issues'].append(f"Server version disclosure: {server}")
        
        # CORS misconfiguration
        cors = headers.get('Access-Control-Allow-Origin', '')
        if cors == '*':
            results['issues'].append("CORS policy allows all origins (*)")
    
    def _calculate_security_grade(self, present_headers: int, missing_headers: int, 
                                issues: int) -> str:
        """Calculate security grade based on headers and issues."""
        score = 100
        
        # Deduct for missing headers
        score -= missing_headers * 10
        
        # Deduct for issues
        score -= issues * 15
        
        # Determine grade
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def basic_vulnerability_checks(self, target: str) -> Dict[str, Any]:
        """Perform basic vulnerability checks.
        
        Args:
            target: Target domain
            
        Returns:
            Vulnerability check results
        """
        logger.info(f"Starting basic vulnerability checks on {target}")
        
        results = {
            'checks_performed': [],
            'issues': [],
            'warnings': [],
            'info': []
        }
        
        try:
            # SSL/TLS check
            results['checks_performed'].append('ssl_tls')
            ssl_results = self._check_ssl_tls(target)
            if ssl_results.get('issues'):
                results['issues'].extend(ssl_results['issues'])
            if ssl_results.get('warnings'):
                results['warnings'].extend(ssl_results['warnings'])
            if ssl_results.get('info'):
                results['info'].extend(ssl_results['info'])
            
            # Exposed files check
            results['checks_performed'].append('exposed_files')
            exposed_files = self._check_exposed_files(target)
            if exposed_files:
                results['warnings'].extend([
                    f"Exposed file found: {file}" for file in exposed_files[:5]
                ])
            
            logger.info(f"Vulnerability checks completed: {len(results['issues'])} issues found")
            return results
            
        except Exception as e:
            logger.error(f"Vulnerability checks failed: {str(e)}")
            return {'error': str(e)}
    
    def _check_ssl_tls(self, target: str) -> Dict[str, List[str]]:
        """Check SSL/TLS configuration."""
        results = {
            'issues': [],
            'warnings': [],
            'info': []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        try:
                            expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_remaining = (expire_date - datetime.now()).days
                            
                            if days_remaining < 0:
                                results['issues'].append(f"SSL certificate expired {abs(days_remaining)} days ago")
                            elif days_remaining < 30:
                                results['warnings'].append(f"SSL certificate expires in {days_remaining} days")
                            else:
                                results['info'].append(f"SSL certificate valid for {days_remaining} days")
                        except:
                            pass
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version == 'TLSv1':
                        results['issues'].append("Using deprecated TLSv1.0")
                    elif tls_version == 'TLSv1.1':
                        results['warnings'].append("Using outdated TLSv1.1")
                    elif tls_version in ['TLSv1.2', 'TLSv1.3']:
                        results['info'].append(f"Using secure {tls_version}")
        
        except Exception as e:
            results['warnings'].append(f"SSL check failed: {str(e)[:100]}")
        
        return results
    
    def _check_exposed_files(self, target: str) -> List[str]:
        """Check for exposed common files."""
        exposed_files = []
        
        common_files = [
            '/.git/HEAD',
            '/.env',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml'
        ]
        
        for scheme in ['https', 'http']:
            for file_path in common_files:
                url = f"{scheme}://{target}{file_path}"
                try:
                    response = requests.get(url, timeout=2, verify=False)
                    if response.status_code == 200:
                        exposed_files.append(url)
                        break  # Found via one scheme, skip other
                except:
                    continue
        
        return exposed_files
    
    def quick_health_check(self, target: str) -> Dict[str, Any]:
        """Perform quick health check on target.
        
        Args:
            target: Target domain or IP
            
        Returns:
            Health check results
        """
        logger.info(f"Performing quick health check on {target}")
        
        results = {
            'target': target,
            'is_alive': False,
            'services': [],
            'response_times': {},
            'timestamp': time.time()
        }
        
        # Common ports to check
        check_ports = [80, 443, 22, 21, 25]
        
        for port in check_ports:
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                elapsed = time.time() - start_time
                sock.close()
                
                if result == 0:
                    results['services'].append({
                        'port': port,
                        'status': 'open',
                        'response_time': round(elapsed, 3)
                    })
                    results['is_alive'] = True
                else:
                    results['services'].append({
                        'port': port,
                        'status': 'closed',
                        'response_time': round(elapsed, 3)
                    })
                    
            except Exception as e:
                results['services'].append({
                    'port': port,
                    'status': 'error',
                    'error': str(e)[:50]
                })
        
        logger.info(f"Health check completed: {'Alive' if results['is_alive'] else 'Not responding'}")
        return results