import dns.resolver
import dns.zone
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List, Dict
import requests
import re

class SubdomainEnumerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1
        self.resolver.lifetime = 1
        
        # Common subdomain prefixes
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'dns1', 'dns2',
            'webmail', 'admin', 'secure', 'vpn', 'remote', 'test', 'dev', 'host',
            'support', 'api', 'dev', 'staging', 'app', 'portal', 'beta'
        ]

# File: reconnaissance/subdomain_enumerator.py
# Updates needed in enumerate_subdomains method

    def enumerate_subdomains(self, target: str) -> List[Dict]:
        """Main subdomain enumeration method combining multiple techniques"""
        # Clean target - remove protocol and path to get just the domain
        domain = self._extract_domain(target)
        if not domain:
            self.logger.error(f"Invalid domain provided: {target}")
            return []
            
        self.logger.info(f"Starting subdomain enumeration for domain: {domain}")
        
        # Add a basic check to ensure the domain is valid
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            # Add the domain itself as a subdomain if we can't resolve it
            # This allows the workflow to continue
            self.logger.warning(f"Domain {domain} could not be resolved, but continuing enumeration")
        
        discovered_subdomains = set()
        results = []

        # Always add the domain itself to results
        try:
            main_domain_ip = socket.gethostbyname(domain)
            discovered_subdomains.add(domain)
            results.append({
                'subdomain': domain,
                'ip_address': main_domain_ip,
                'is_http': True,  # Assume main domain has HTTP
                'http_status': None,
                'status': 'active'
            })
        except Exception as e:
            self.logger.warning(f"Couldn't resolve main domain {domain}: {str(e)}")
        
        # 1. DNS enumeration
        dns_results = self._dns_enumeration(domain)
        for subdomain in dns_results:
            discovered_subdomains.add(subdomain)

        # 2. Brute force common subdomains
        brute_results = self._brute_force_subdomains(domain)
        for subdomain in brute_results:
            discovered_subdomains.add(subdomain)

        # Process and validate all discovered subdomains
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {
                executor.submit(self._validate_subdomain, subdomain): subdomain 
                for subdomain in discovered_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error validating {subdomain}: {str(e)}")

        # Ensure we have at least the main domain in results
        if not results and domain:
            results.append({
                'subdomain': domain,
                'ip_address': None,
                'is_http': None,
                'http_status': None,
                'status': 'unknown'
            })

        return results

    def _extract_domain(self, url: str) -> str:
        """Extract root domain from a URL or domain string"""
        # Remove protocol if present
        if '://' in url:
            url = url.split('://', 1)[1]
            
        # Remove path, query params, and fragment
        url = url.split('/', 1)[0]
        url = url.split('?', 1)[0]
        url = url.split('#', 1)[0]
        
        # Remove port if present
        url = url.split(':', 1)[0]
        
        # Validate domain format
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, url):
            return url
        
        return None

    def _dns_enumeration(self, domain: str) -> set:
        """Enumerate subdomains using DNS queries"""
        discovered = set()
        
        try:
            # Try zone transfer first
            try:
                ns_records = self.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                        for name, _ in zone.nodes.items():
                            subdomain = str(name) + '.' + domain
                            discovered.add(subdomain)
                    except Exception as zone_error:
                        # Zone transfers often fail due to security restrictions, this is expected
                        continue
            except dns.resolver.NoAnswer:
                self.logger.info(f"No NS records found for {domain} - this is normal for many domains")
            except dns.resolver.NXDOMAIN:
                self.logger.info(f"Domain {domain} does not exist in DNS")
            except Exception as e:
                self.logger.info(f"NS record query failed for {domain}: {str(e)}")

            # Try to get common DNS records
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if record_type == 'MX':
                            discovered.add(str(rdata.exchange).rstrip('.'))
                        elif record_type == 'NS':
                            discovered.add(str(rdata).rstrip('.'))
                        elif record_type == 'CNAME':
                            discovered.add(str(rdata.target).rstrip('.'))
                except dns.resolver.NoAnswer:
                    # This is normal - not all record types exist for all domains
                    continue
                except Exception:
                    # Other DNS errors are also common and shouldn't stop enumeration
                    continue

        except Exception as e:
            # Only log as warning since this is one of multiple enumeration techniques
            self.logger.warning(f"DNS enumeration had issues for {domain}: {str(e)}")

        return discovered

    def _brute_force_subdomains(self, domain: str) -> set:
        """Brute force subdomains using common prefixes"""
        discovered = set()
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(self._check_subdomain, f"{prefix}.{domain}"): prefix 
                for prefix in self.common_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                try:
                    result = future.result()
                    if result:
                        discovered.add(result)
                except Exception as e:
                    continue

        return discovered

    def _check_subdomain(self, subdomain: str) -> str:
        """Check if a subdomain exists"""
        try:
            self.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None

    def _validate_subdomain(self, subdomain: str) -> Dict:
        """Validate and get information about a subdomain"""
        try:
            ip_address = socket.gethostbyname(subdomain)
            
            # Basic HTTP check
            is_http = False
            http_status = None
            try:
                response = requests.get(f"http://{subdomain}", timeout=3)
                is_http = True
                http_status = response.status_code
            except:
                try:
                    response = requests.get(f"https://{subdomain}", timeout=3)
                    is_http = True
                    http_status = response.status_code
                except:
                    pass

            return {
                'subdomain': subdomain,
                'ip_address': ip_address,
                'is_http': is_http,
                'http_status': http_status,
                'status': 'active'
            }
        except Exception as e:
            return None