import nmap
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
import socket

class SubdomainEnumerator:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1
        self.resolver.lifetime = 1

    def enumerate_subdomains(self, domain: str) -> List[Dict]:
        discovered_subdomains = []
        
        # Common subdomain prefixes
        common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server',
                           'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api']

        def check_subdomain(subdomain):
            try:
                hostname = f"{subdomain}.{domain}"
                ip_address = socket.gethostbyname(hostname)
                return {
                    'subdomain': hostname,
                    'ip_address': ip_address,
                    'status': 'active'
                }
            except:
                return None

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_subdomain, common_subdomains)
            
        for result in results:
            if result:
                discovered_subdomains.append(result)

        return discovered_subdomains

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_ports(self, target: str, ports: str = '21-23,25,53,80,443,3306,8080') -> Dict:
        try:
            # Perform the scan
            self.nm.scan(target, ports, arguments='-sS -sV -T4')
            
            scan_results = []
            
            # Process results for each host
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        scan_results.append({
                            'port': port,
                            'state': service['state'],
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', 'unknown')
                        })
            
            return {
                'target': target,
                'total_ports': len(scan_results),
                'open_ports': len([p for p in scan_results if p['state'] == 'open']),
                'results': scan_results
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'target': target,
                'status': 'failed'
            }