"""
Enhanced Passive Reconnaissance Module - OPTIMIZED VERSION
CYS-ILM Security Tool
"""

import whois
import dns.resolver
import dns.reversename
import requests
import socket
import json
import time
import re
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse, urlunparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class PassiveReconnaissance:
    """CYS-ILM passive reconnaissance operations."""
    
    def __init__(self, verbose: bool = False):
        """Initialize passive reconnaissance module.
        
        Args:
            verbose: Enable verbose logging
        """
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        
        # Configure DNS resolver with timeouts
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3  # Reduced timeout
        self.resolver.lifetime = 5
        
        # External API endpoints (with fallbacks)
        self.apis = {
            'crtsh': 'https://crt.sh/',
            'otx': 'https://otx.alienvault.com/api/v1/',
            'hackertarget': 'https://api.hackertarget.com/',
        }
        
        # Rate limiting
        self.request_delay = 2.0
        self.last_request = {}
        
        # Common subdomains for checking
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'admin', 'blog',
            'webmail', 'portal', 'cpanel', 'whm', 'webdisk', 'ns1', 'ns2',
            'test', 'dev', 'staging', 'api', 'secure', 'vpn', 'm', 'mobile',
            'static', 'cdn', 'assets', 'support', 'help', 'status'
        ]
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup on domain.
        
        Args:
            domain: Target domain
            
        Returns:
            WHOIS information dictionary
        """
        logger.info(f"Starting WHOIS lookup for {domain}")
        
        try:
            # Clean domain
            domain_clean = self._clean_domain(domain)
            
            # Perform WHOIS lookup with timeout
            whois_info = whois.whois(domain_clean)
            
            # Extract and format information
            result = {
                'domain_name': self._safe_extract(whois_info.domain_name),
                'registrar': whois_info.registrar,
                'whois_server': whois_info.whois_server,
                'creation_date': self._safe_extract(whois_info.creation_date),
                'expiration_date': self._safe_extract(whois_info.expiration_date),
                'updated_date': self._safe_extract(whois_info.updated_date),
                'name_servers': self._safe_extract(whois_info.name_servers),
                'status': self._safe_extract(whois_info.status),
                'emails': self._safe_extract(whois_info.emails),
                'dnssec': whois_info.dnssec if hasattr(whois_info, 'dnssec') else None,
            }
            
            # Calculate domain age if possible
            if result['creation_date']:
                try:
                    if isinstance(result['creation_date'], list):
                        creation = result['creation_date'][0]
                    else:
                        creation = result['creation_date']
                    
                    if hasattr(creation, 'year'):
                        age = datetime.now().year - creation.year
                        result['domain_age_years'] = age
                except:
                    pass
            
            logger.info(f"WHOIS lookup completed for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'note': 'WHOIS lookup failed'
            }
    
    def dns_enumeration(self, domain: str, record_types: List[str] = None) -> Dict[str, Any]:
        """Comprehensive DNS record enumeration.
        
        Args:
            domain: Target domain
            record_types: List of DNS record types to query
            
        Returns:
            DNS records dictionary
        """
        logger.info(f"Starting DNS enumeration for {domain}")
        
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        
        results = {
            'domain': domain,
            'records': {},
            'summary': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Query each record type
            for record_type in record_types:
                try:
                    answers = self.resolver.resolve(domain, record_type, lifetime=3)
                    records = []
                    
                    for rdata in answers:
                        if record_type == 'MX':
                            record_str = f"{rdata.preference} {rdata.exchange}"
                        else:
                            record_str = str(rdata)
                        records.append(record_str)
                    
                    if records:
                        results['records'][record_type] = records
                    else:
                        results['records'][record_type] = []
                        
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    results['records'][record_type] = []
                except dns.resolver.Timeout:
                    results['records'][record_type] = ['TIMEOUT']
                except Exception as e:
                    logger.debug(f"Failed to resolve {record_type} for {domain}: {str(e)}")
                    results['records'][record_type] = [f'ERROR: {str(e)[:50]}']
            
            # Generate summary
            total_records = sum(len(records) for records in results['records'].values())
            ip_addresses = results['records'].get('A', []) + results['records'].get('AAAA', [])
            
            results['summary'] = {
                'total_records': total_records,
                'record_types_found': [rt for rt in results['records'] if results['records'][rt]],
                'has_mx': bool(results['records'].get('MX')),
                'has_txt': bool(results['records'].get('TXT')),
                'nameservers': results['records'].get('NS', []),
                'ip_addresses': ip_addresses
            }
            
            logger.info(f"DNS enumeration completed for {domain}: {total_records} records found")
            return results
            
        except Exception as e:
            logger.error(f"DNS enumeration failed: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'note': 'DNS enumeration failed'
            }
    
    def subdomain_discovery(self, domain: str, **kwargs) -> Dict[str, Any]:
        """Discover subdomains using multiple techniques.
        
        Args:
            domain: Target domain
            **kwargs: Additional options
            
        Returns:
            Subdomain discovery results
        """
        logger.info(f"Starting subdomain discovery for {domain}")
        
        use_crtsh = kwargs.get('use_crtsh', True)
        use_otx = kwargs.get('use_otx', False)  # Disabled by default due to rate limits
        brute_force = kwargs.get('brute_force', False)
        
        all_subdomains = set()
        sources = {}
        
        try:
            # Method 1: Certificate Transparency (crt.sh)
            if use_crtsh:
                logger.debug(f"Searching crt.sh for {domain} subdomains...")
                crt_subdomains = self._query_crtsh_api(domain)
                sources['crt_sh'] = sorted(crt_subdomains)
                all_subdomains.update(crt_subdomains)
                logger.debug(f"crt.sh found {len(crt_subdomains)} subdomains")
            
            # Method 2: Check common subdomains
            logger.debug(f"Checking common subdomains for {domain}...")
            common_subdomains = self._check_common_subdomains(domain)
            sources['common_patterns'] = sorted(common_subdomains)
            all_subdomains.update(common_subdomains)
            logger.debug(f"Common patterns found {len(common_subdomains)} subdomains")
            
            # Method 3: AlienVault OTX (optional)
            if use_otx:
                logger.debug(f"Searching AlienVault OTX for {domain} subdomains...")
                otx_subdomains = self._query_otx_api(domain)
                sources['alienvault_otx'] = sorted(otx_subdomains)
                all_subdomains.update(otx_subdomains)
                logger.debug(f"OTX found {len(otx_subdomains)} subdomains")
            
            # Validate discovered subdomains
            validated_subdomains = []
            unique_subdomains = sorted(list(all_subdomains))
            
            logger.info(f"Validating {len(unique_subdomains)} discovered subdomains...")
            
            # Use thread pool for faster validation
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_subdomain = {
                    executor.submit(self._validate_subdomain, subdomain): subdomain 
                    for subdomain in unique_subdomains[:50]  # Limit to first 50 for speed
                }
                
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        is_valid, ip_address = future.result(timeout=3)
                        if is_valid:
                            validated_subdomains.append({
                                'subdomain': subdomain,
                                'ip_address': ip_address,
                                'source': self._identify_source(subdomain, sources)
                            })
                    except Exception as e:
                        logger.debug(f"Validation failed for {subdomain}: {str(e)}")
            
            # Organize results
            results = {
                'domain': domain,
                'total_discovered': len(unique_subdomains),
                'total_valid': len(validated_subdomains),
                'sources': {k: len(v) for k, v in sources.items()},
                'validated_subdomains': validated_subdomains,
                'by_ip': self._group_by_ip(validated_subdomains),
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"Subdomain discovery completed: {len(validated_subdomains)} valid subdomains found")
            return results
            
        except Exception as e:
            logger.error(f"Subdomain discovery failed: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'note': 'Subdomain discovery failed'
            }
    
    def reverse_ip_lookup(self, target: str) -> Dict[str, Any]:
        """Perform reverse IP lookup to find domains sharing IP.
        
        Args:
            target: Domain or IP address
            
        Returns:
            Reverse lookup results
        """
        logger.info(f"Starting reverse IP lookup for {target}")
        
        try:
            # Get IP if domain is provided
            if not self._is_ip(target):
                ip_address = socket.gethostbyname(target)
            else:
                ip_address = target
            
            # Skip API call for now (due to timeouts)
            # Could implement local DNS PTR lookup instead
            
            results = {
                'ip_address': ip_address,
                'shared_domains': [],
                'total_domains': 0,
                'note': 'Reverse IP lookup skipped (API timeouts)'
            }
            
            logger.info(f"Reverse IP lookup completed for {ip_address}")
            return results
            
        except Exception as e:
            logger.error(f"Reverse IP lookup failed: {str(e)}")
            return {
                'error': str(e),
                'target': target,
                'note': 'Reverse IP lookup failed'
            }
    
    def find_related_domains(self, domain: str) -> Dict[str, Any]:
        """Find domains related to target.
        
        Args:
            domain: Target domain
            
        Returns:
            Related domains information
        """
        logger.info(f"Finding related domains for {domain}")
        
        results = {
            'primary_domain': domain,
            'similar_names': [],
            'same_ip_range': [],
            'same_registrar': [],
            'same_nameservers': [],
            'note': 'Basic related domain check'
        }
        
        try:
            # Get base name and TLD
            parts = domain.split('.')
            if len(parts) >= 2:
                base_name = parts[-2]
                tld = parts[-1]
                
                # Quick check for common variations (limited to avoid timeouts)
                common_variations = [
                    f"{base_name}-test.{tld}",
                    f"test-{base_name}.{tld}",
                    f"{base_name}1.{tld}",
                ]
                
                # Check with timeout
                for variation in common_variations:
                    try:
                        # Set socket timeout
                        socket.setdefaulttimeout(2)
                        socket.gethostbyname(variation)
                        results['similar_names'].append(variation)
                    except:
                        pass
            
            logger.info(f"Related domains check completed for {domain}")
            return results
            
        except Exception as e:
            logger.error(f"Finding related domains failed: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'note': 'Related domains check failed'
            }
    
    # ========== HELPER METHODS ==========
    
    def _clean_domain(self, domain: str) -> str:
        """Remove protocol and path from domain."""
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        return domain.strip().lower()
    
    def _safe_extract(self, value) -> Any:
        """Extract and format WHOIS values safely."""
        if value is None:
            return None
        elif isinstance(value, list):
            return [str(v) for v in value if v is not None]
        else:
            return str(value)
    
    def _rate_limit(self, api_name: str):
        """Implement rate limiting."""
        current_time = time.time()
        
        if api_name in self.last_request:
            time_since = current_time - self.last_request[api_name]
            if time_since < self.request_delay:
                time.sleep(self.request_delay - time_since)
        
        self.last_request[api_name] = time.time()
    
    def _is_ip(self, address: str) -> bool:
        """Check if string is an IP address."""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def _query_crtsh_api(self, domain: str) -> Set[str]:
        """Query crt.sh API for subdomains."""
        try:
            self._rate_limit('crtsh')
            
            params = {
                'q': f'%.{domain}',
                'output': 'json'
            }
            
            response = requests.get(self.apis['crtsh'], params=params, timeout=5)
            
            if response.status_code != 200:
                logger.warning(f"crt.sh API returned status {response.status_code}")
                return set()
            
            data = response.json()
            domains = set()
            
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    # Split by newlines and clean up
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if domain in name:
                            # Remove wildcards and clean
                            name = name.replace('*.', '').strip()
                            if name and domain in name:
                                domains.add(name)
            
            return domains
            
        except requests.Timeout:
            logger.warning("crt.sh API timeout")
            return set()
        except Exception as e:
            logger.warning(f"crt.sh API query failed: {str(e)[:100]}")
            return set()
    
    def _query_otx_api(self, domain: str) -> Set[str]:
        """Query AlienVault OTX API."""
        try:
            self._rate_limit('otx')
            
            url = f"{self.apis['otx']}indicators/domain/{domain}/passive_dns"
            headers = {
                'User-Agent': 'CYS-ILM-Recon-Tool/2.0',
                'Accept': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 429:  # Rate limited
                logger.warning("OTX API rate limited")
                return set()
            elif response.status_code != 200:
                logger.warning(f"OTX API returned status {response.status_code}")
                return set()
            
            data = response.json()
            domains = set()
            
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname', '')
                if hostname and domain in hostname:
                    domains.add(hostname.lower())
            
            return domains
            
        except requests.Timeout:
            logger.warning("OTX API timeout")
            return set()
        except Exception as e:
            logger.warning(f"OTX API query failed: {str(e)[:100]}")
            return set()
    
    def _check_common_subdomains(self, domain: str) -> Set[str]:
        """Check for commonly used subdomains."""
        domains = set()
        
        # Check only a subset for speed
        for sub in self.common_subdomains[:20]:  # Limit to first 20
            full_domain = f"{sub}.{domain}"
            try:
                # Set timeout
                socket.setdefaulttimeout(2)
                socket.gethostbyname(full_domain)
                domains.add(full_domain)
            except:
                pass
        
        return domains
    
    def _validate_subdomain(self, subdomain: str) -> Tuple[bool, Optional[str]]:
        """Validate if subdomain exists and get its IP."""
        try:
            # Set timeout
            socket.setdefaulttimeout(3)
            ip_address = socket.gethostbyname(subdomain)
            return True, ip_address
        except socket.gaierror:
            return False, None
        except:
            return False, None
    
    def _identify_source(self, subdomain: str, sources: Dict[str, List[str]]) -> List[str]:
        """Identify which source discovered the subdomain."""
        identified_sources = []
        
        for source_name, source_subs in sources.items():
            if subdomain in source_subs:
                identified_sources.append(source_name)
        
        return identified_sources if identified_sources else ['unknown']
    
    def _group_by_ip(self, subdomains: List[Dict]) -> Dict[str, List[str]]:
        """Group subdomains by IP address."""
        groups = {}
        
        for sub in subdomains:
            ip = sub.get('ip_address')
            if ip:
                if ip not in groups:
                    groups[ip] = []
                groups[ip].append(sub['subdomain'])
        
        return groups
    
    def _query_hackertarget_api(self, domain: str) -> Set[str]:
        """Query HackerTarget API (disabled due to timeouts)."""
        # This API often times out, so we'll skip it
        logger.debug("Skipping HackerTarget API (known timeout issues)")
        return set()
    
    def _check_spf_record(self, txt_records: List[str]) -> Optional[str]:
        """Check for SPF record in TXT records."""
        for record in txt_records:
            if record and 'v=spf1' in record:
                return record
        return None
    
    def _check_dmarc_record(self, domain: str) -> Optional[str]:
        """Check for DMARC record."""
        try:
            answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=2)
            for rdata in answers:
                record = str(rdata)
                if 'v=DMARC1' in record:
                    return record
        except:
            pass
        return None
    
    def _check_dnssec(self, domain: str) -> Optional[bool]:
        """Check if DNSSEC is enabled for domain."""
        try:
            self.resolver.resolve(domain, 'DNSKEY', lifetime=2)
            return True
        except:
            return False