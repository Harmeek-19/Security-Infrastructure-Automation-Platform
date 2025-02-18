import dns.resolver
import dns.zone
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List, Dict
import requests

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

    def enumerate_subdomains(self, domain: str) -> List[Dict]:
        """Main subdomain enumeration method combining multiple techniques"""
        discovered_subdomains = set()
        results = []

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

        return results

    def _dns_enumeration(self, domain: str) -> set:
        """Enumerate subdomains using DNS queries"""
        discovered = set()
        
        try:
            # Try zone transfer first
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name, _ in zone.nodes.items():
                        subdomain = str(name) + '.' + domain
                        discovered.add(subdomain)
                except:
                    continue

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
                except:
                    continue

        except Exception as e:
            self.logger.error(f"Error in DNS enumeration for {domain}: {str(e)}")

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