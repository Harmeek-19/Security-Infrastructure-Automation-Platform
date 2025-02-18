import nmap
from typing import Dict, List, Optional
import logging
from datetime import datetime
import socket
import requests
from urllib.parse import urlparse
import concurrent.futures
import threading
from django.conf import settings

class ServiceIdentifier:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.logger = logging.getLogger(__name__)
        self.timeout = getattr(settings, 'SERVICE_SCAN_TIMEOUT', 180)  # 3 minutes default
        self._stop_event = threading.Event()

    def identify_services(self, target: str, scan_type: str = 'standard') -> Dict:
        """Comprehensive service identification with timeout handling"""
        try:
            # Parse target
            parsed_target = urlparse(target)
            target_host = parsed_target.netloc or parsed_target.path
            target_host = target_host.split(':')[0]

            scan_config = self._get_scan_config(scan_type)
            self.logger.info(f"Starting {scan_type} service scan for {target_host}")

            # Use ThreadPoolExecutor for timeout handling
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._run_service_scan, target_host, scan_config)
                try:
                    result = future.result(timeout=self.timeout)
                    return result
                except concurrent.futures.TimeoutError:
                    self._stop_event.set()
                    return {
                        'status': 'error',
                        'error': 'Scan timeout',
                        'details': f'Service scan exceeded {self.timeout} seconds'
                    }

        except Exception as e:
            self.logger.error(f"Service scan failed for {target}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'details': 'Service scan failed'
            }
            
    def _get_scan_config(self, scan_type: str) -> Dict:
        """Get scan configuration based on scan type"""
        configs = {
            'quick': {
                'ports': '21-23,25,80,443,3306,8080',
                'arguments': '-sV -sT -Pn -T4 --version-light'  # Fast scan
            },
            'standard': {
                'ports': '1-1000',
                'arguments': '-sV -sT -Pn -T4 --version-all'  # Standard scan
            },
            'full': {
                'ports': '1-65535',
                'arguments': '-sV -sT -Pn -T4 -A --version-all'  # Full scan
            },
            'stealth': {
                'ports': '1-1000',
                'arguments': '-sV -sS -Pn -T2 --version-all'  # Stealth scan
            }
        }
        return configs.get(scan_type, configs['standard'])

    def _run_service_scan(self, target: str, config: Dict) -> Dict:
        """Execute the actual service scan with interrupt handling"""
        try:
            # Initial port discovery
            self.logger.info(f"Starting port discovery for {target}")
            open_ports = self._discover_ports(target, config)
            
            if not open_ports:
                return {
                    'status': 'success',
                    'services': [],
                    'total_services': 0,
                    'scan_stats': {'open_ports': 0}
                }

            # Detailed service scanning
            self.logger.info(f"Starting service detection on {len(open_ports)} ports")
            scan_result = self.scanner.scan(
                target,
                ports=','.join(map(str, open_ports)),
                arguments=config['arguments']
            )

            # Debug logging
            self.logger.info(f"Raw scan result structure: {list(scan_result.keys())}")
            self.logger.info(f"Scan hosts: {self.scanner.all_hosts()}")
            if target in self.scanner.all_hosts():
                self.logger.info(f"Protocols for {target}: {self.scanner[target].all_protocols()}")
                for proto in self.scanner[target].all_protocols():
                    self.logger.info(f"Ports for {proto}: {list(self.scanner[target][proto].keys())}")

            if self._stop_event.is_set():
                return {
                    'status': 'error',
                    'error': 'Scan interrupted',
                    'details': 'Service scan was interrupted'
                }

            # Process scan results
            services = []
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    for port in self.scanner[host][proto].keys():
                        service_info = self.scanner[host][proto][port]
                        if service_info['state'] == 'open':
                            service_detail = {
                                'port': port,
                                'protocol': proto,
                                'state': service_info['state'],
                                'service': {
                                    'name': service_info.get('name', 'unknown'),
                                    'product': service_info.get('product', ''),
                                    'version': service_info.get('version', ''),
                                    'extrainfo': service_info.get('extrainfo', ''),
                                    'cpe': service_info.get('cpe', [])
                                },
                                'category': self._categorize_service(service_info),
                                'risk_level': self._assess_risk_level(service_info)
                            }
                            services.append(service_detail)

            # Enhance service information
            enhanced_services = []
            for service in services:
                try:
                    enhanced_service = self._enhance_service_info(target, service.copy())
                    if enhanced_service:
                        enhanced_services.append(enhanced_service)
                    else:
                        enhanced_services.append(service)
                except Exception as e:
                    self.logger.error(f"Error enhancing service {service.get('port')}: {str(e)}")
                    enhanced_services.append(service)

            scan_time = scan_result.get('nmap', {}).get('scanstats', {}).get('elapsed', 'unknown')
            self.logger.info(f"Scan completed in {scan_time} seconds")
            
            # Log found services
            for service in enhanced_services:
                self.logger.info(f"Found service: Port {service['port']} - {service['service']['name']} ({service['category']})")

            return {
                'status': 'success',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'services': enhanced_services,
                'total_services': len(enhanced_services),
                'scan_stats': {
                    'open_ports': len(open_ports),
                    'scan_time': scan_time
                }
            }

        except Exception as e:
            self.logger.error(f"Error in service scan: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'details': 'Error during service scan execution'
            }

    def _discover_ports(self, target: str, config: Dict) -> List[int]:
        """Initial port discovery with timeout"""
        open_ports = set()
        ports_to_scan = self._parse_ports(config['ports'])
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self._check_port, target, port): port 
                for port in ports_to_scan
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                if not self._stop_event.is_set():
                    try:
                        is_open = future.result()
                        if is_open:
                            open_ports.add(future_to_port[future])
                    except:
                        continue
                else:
                    break

        return list(sorted(open_ports))

    def _check_port(self, target: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                return result == 0
        except:
            return False

    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parse ports string into list of port numbers"""
        ports = set()
        for part in ports_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return list(ports)

    def _enhance_service_info(self, target: str, service: Dict) -> Dict:
        """Enhance service information with additional checks"""
        try:
            if service['service']['name'] == 'http':
                self._enhance_web_service(target, service)
            elif service['service']['name'] in ['ssh', 'ftp', 'smtp']:
                self._enhance_common_service(target, service)
            return service
        except:
            return service

    def _enhance_web_service(self, target: str, service: Dict) -> None:
        """Enhance web service information"""
        try:
            port = service['port']
            url = f"http{'s' if port == 443 else ''}://{target}:{port}"
            response = requests.get(url, timeout=3, verify=False)
            
            service['service']['headers'] = dict(response.headers)
            service['service']['status_code'] = response.status_code
            service['service']['technologies'] = self._detect_technologies(response)
        except:
            pass

    def _enhance_common_service(self, target: str, service: Dict) -> None:
        """Enhance common service information with banner grabbing"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target, service['port']))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                service['service']['banner'] = banner
        except:
            pass

    def _detect_technologies(self, response) -> List[str]:
        """Detect web technologies from response headers"""
        technologies = []
        headers = response.headers
        
        tech_headers = {
            'X-Powered-By': None,
            'Server': None,
            'X-AspNet-Version': 'ASP.NET',
            'X-Runtime': 'Ruby'
        }
        
        for header, tech in tech_headers.items():
            if header in headers:
                technologies.append(tech or headers[header])
                
        return technologies

    def _process_scan_results(self, target: str) -> List[Dict]:
        """Process scan results and categorize services"""
        services = []
        
        if target not in self.scanner.all_hosts():
            return services

        for proto in self.scanner[target].all_protocols():
            ports = self.scanner[target][proto].keys()
            
            for port in ports:
                service_info = self.scanner[target][proto][port]
                service_detail = {
                    'port': port,
                    'protocol': proto,
                    'state': service_info['state'],
                    'service': {
                        'name': service_info.get('name', 'unknown'),
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'extrainfo': service_info.get('extrainfo', ''),
                        'cpe': service_info.get('cpe', [])
                    },
                    'category': self._categorize_service(service_info),
                    'risk_level': self._assess_risk_level(service_info)
                }
                services.append(service_detail)
        
        return services

    def _categorize_service(self, service_info: Dict) -> str:
        """Categorize service based on name and product"""
        service_categories = {
            'web': ['http', 'https', 'nginx', 'apache'],
            'database': ['mysql', 'postgresql', 'mongodb'],
            'mail': ['smtp', 'pop3', 'imap'],
            'file_transfer': ['ftp', 'sftp'],
            'remote_access': ['ssh', 'telnet', 'rdp'],
            'dns': ['dns', 'domain']
        }

        service_name = service_info.get('name', '').lower()
        
        for category, services in service_categories.items():
            if any(s in service_name for s in services):
                return category
        return 'other'

    def _assess_risk_level(self, service_info: Dict) -> str:
        """Basic risk assessment of services"""
        high_risk = ['telnet', 'ftp']
        medium_risk = ['smtp', 'pop3']
        
        service_name = service_info.get('name', '').lower()
        
        if any(service in service_name for service in high_risk):
            return 'HIGH'
        elif any(service in service_name for service in medium_risk):
            return 'MEDIUM'
        return 'LOW'

    def _log_service_details(self, target: str, services: List[Dict]) -> None:
        """Log detailed information about identified services"""
        self.logger.info(f"Service identification completed for {target}")
        self.logger.info(f"Total services identified: {len(services)}")
        
        for service in services:
            log_message = (
                f"Port {service['port']}/{service['protocol']}: "
                f"{service['service']['name']} "
                f"({service['category']}, Risk: {service['risk_level']})"
            )
            if service['service']['version']:
                log_message += f" Version: {service['service']['version']}"
            
            self.logger.info(log_message)