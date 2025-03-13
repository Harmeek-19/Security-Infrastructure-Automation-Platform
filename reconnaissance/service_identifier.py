import nmap
from typing import Dict, List, Optional
import logging
from datetime import datetime
import socket
import requests
from urllib.parse import urlparse
import concurrent.futures
import threading
import time
from django.conf import settings
import os

class ServiceIdentifier:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.logger = logging.getLogger(__name__)
        self.timeout = getattr(settings, 'SERVICE_SCAN_TIMEOUT', 180)  # 3 minutes default
        self._stop_event = threading.Event()
        # Use shorter timeouts for various operations
        self.discovery_timeout = 60  # 1 minute for port discovery
        self.connection_timeout = 2  # 2 seconds for individual connections

    def identify_services(self, target: str, scan_type: str = 'standard') -> Dict:
        """Comprehensive service identification with improved timeout handling"""
        try:
            # Parse target
            parsed_target = urlparse(target)
            target_host = parsed_target.netloc or parsed_target.path
            target_host = target_host.split(':')[0]

            scan_config = self._get_scan_config(scan_type)
            self.logger.info(f"Starting {scan_type} service scan for {target_host}")

            # Use a simpler approach with manual timeout handling
            self._stop_event.clear()
            
            # Start a timer to enforce overall timeout
            start_time = time.time()
            
            # Set timeout based on scan type
            effective_timeout = self.timeout
            if scan_type == 'quick':
                effective_timeout = min(self.timeout, 120)  # 2 minutes max for quick
            elif scan_type == 'full':
                effective_timeout = self.timeout  # Full timeout for full scan
            
            self.logger.info(f"Using timeout of {effective_timeout} seconds for {scan_type} scan")
            
            # Discover open ports with a shorter timeout
            open_ports = self._discover_ports_with_timeout(target_host, scan_config, 
                                                          timeout=self.discovery_timeout)
            
            # Check if we should stop
            elapsed = time.time() - start_time
            if elapsed > effective_timeout * 0.8:  # 80% of timeout used
                self.logger.warning(f"Port discovery took {elapsed:.1f}s, approaching timeout")
                return {
                    'status': 'success',
                    'services': [],
                    'total_services': 0,
                    'scan_stats': {'open_ports': len(open_ports)}
                }
            
            if not open_ports:
                return {
                    'status': 'success',
                    'services': [],
                    'total_services': 0,
                    'scan_stats': {'open_ports': 0}
                }

            # Perform limited service detection directly without nmap
            self.logger.info(f"Starting basic service detection on {len(open_ports)} ports")
            services = self._perform_basic_service_detection(target_host, open_ports)
            
            # Only do nmap service detection if we have time and found less than 10 ports
            time_left = effective_timeout - (time.time() - start_time)
            if time_left > 60 and len(open_ports) < 10 and not self._stop_event.is_set():
                try:
                    # Try nmap service detection with a short timeout
                    self.logger.info(f"Starting nmap service detection (time left: {time_left:.1f}s)")
                    nmap_services = self._run_nmap_service_detection(
                        target_host, open_ports, scan_config, timeout=min(60, time_left)
                    )
                    
                    # Add any services found by nmap
                    if nmap_services:
                        services.extend(nmap_services)
                except Exception as e:
                    self.logger.error(f"Nmap service detection failed: {str(e)}")
                    # Continue with basic services
            
            # Remove duplicates by port
            service_dict = {}
            for service in services:
                port = service['port']
                # Keep the one with more information
                if port not in service_dict or len(str(service)) > len(str(service_dict[port])):
                    service_dict[port] = service
            
            unique_services = list(service_dict.values())
            
            return {
                'status': 'success',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'services': unique_services,
                'total_services': len(unique_services),
                'scan_stats': {
                    'open_ports': len(open_ports),
                    'scan_time': f"{time.time() - start_time:.1f}s"
                }
            }

        except Exception as e:
            self.logger.error(f"Service scan failed for {target}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'details': 'Service scan failed'
            }
    
    def _discover_ports_with_timeout(self, target: str, config: Dict, timeout: int = 60) -> List[int]:
        """Discover open ports with a strict timeout"""
        self.logger.info(f"Starting port discovery with {timeout}s timeout")
        open_ports = set()
        
        # Parse ports to scan
        ports_to_scan = self._parse_ports(config['ports'])
        
        # Use a smaller subset of ports for quicker scanning
        if len(ports_to_scan) > 100:
            # If many ports, prioritize common ones
            common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
            subset = [p for p in ports_to_scan if p in common_ports]
            subset.extend(sorted(list(set(ports_to_scan) - set(subset)))[:100-len(subset)])
            self.logger.info(f"Scanning subset of {len(subset)} ports out of {len(ports_to_scan)}")
            ports_to_scan = subset
        
        start_time = time.time()
        
        # Check ports in parallel with a maximum time limit
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self._check_port, target, port, 1): port 
                for port in ports_to_scan
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                if time.time() - start_time > timeout:
                    self.logger.warning(f"Port discovery reached timeout of {timeout}s")
                    break
                    
                if self._stop_event.is_set():
                    break
                    
                try:
                    is_open = future.result()
                    if is_open:
                        port = future_to_port[future]
                        open_ports.add(port)
                        self.logger.info(f"Found open port {port} on {target}")
                except Exception as e:
                    self.logger.debug(f"Error checking port: {str(e)}")
                    continue

        self.logger.info(f"Port discovery completed in {time.time() - start_time:.1f}s, found {len(open_ports)} open ports")
        return sorted(list(open_ports))
    
    def _perform_basic_service_detection(self, target: str, open_ports: List[int]) -> List[Dict]:
        """Perform basic service detection without nmap"""
        services = []
        
        # Common service port mappings
        common_services = {
            21: {'name': 'ftp', 'category': 'file_transfer', 'risk_level': 'HIGH'},
            22: {'name': 'ssh', 'category': 'remote_access', 'risk_level': 'LOW'},
            23: {'name': 'telnet', 'category': 'remote_access', 'risk_level': 'HIGH'},
            25: {'name': 'smtp', 'category': 'mail', 'risk_level': 'MEDIUM'},
            53: {'name': 'domain', 'category': 'dns', 'risk_level': 'LOW'},
            80: {'name': 'http', 'category': 'web', 'risk_level': 'MEDIUM'},
            110: {'name': 'pop3', 'category': 'mail', 'risk_level': 'MEDIUM'},
            139: {'name': 'netbios-ssn', 'category': 'file_transfer', 'risk_level': 'HIGH'},
            143: {'name': 'imap', 'category': 'mail', 'risk_level': 'MEDIUM'},
            443: {'name': 'https', 'category': 'web', 'risk_level': 'LOW'},
            445: {'name': 'microsoft-ds', 'category': 'file_transfer', 'risk_level': 'HIGH'},
            993: {'name': 'imaps', 'category': 'mail', 'risk_level': 'LOW'},
            995: {'name': 'pop3s', 'category': 'mail', 'risk_level': 'LOW'},
            1723: {'name': 'pptp', 'category': 'vpn', 'risk_level': 'MEDIUM'},
            3306: {'name': 'mysql', 'category': 'database', 'risk_level': 'HIGH'},
            3389: {'name': 'ms-wbt-server', 'category': 'remote_access', 'risk_level': 'HIGH'},
            5900: {'name': 'vnc', 'category': 'remote_access', 'risk_level': 'HIGH'},
            8080: {'name': 'http-proxy', 'category': 'web', 'risk_level': 'MEDIUM'},
            8443: {'name': 'https-alt', 'category': 'web', 'risk_level': 'LOW'}
        }
        
        for port in open_ports:
            # Start with defaults
            service_info = common_services.get(port, {
                'name': 'unknown',
                'category': 'other',
                'risk_level': 'MEDIUM'
            })
            
            # Try basic banner grabbing with short timeout
            banner = self._grab_banner(target, port)
            
            # For HTTP ports, try to get more info
            if port in [80, 443, 8080, 8443] or banner and ('HTTP' in banner or 'html' in banner.lower()):
                http_info = self._get_http_info(target, port)
                if http_info:
                    service_detail = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': {
                            'name': 'http' if port != 443 and port != 8443 else 'https',
                            'product': http_info.get('server', ''),
                            'version': '',
                            'extrainfo': '',
                            'banner': banner
                        },
                        'category': 'web',
                        'risk_level': 'MEDIUM',
                        'http_info': http_info
                    }
                    services.append(service_detail)
                    continue
            
            # For other ports, use the basic info
            service_detail = {
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': {
                    'name': service_info.get('name', 'unknown'),
                    'product': '',
                    'version': '',
                    'extrainfo': '',
                    'banner': banner
                },
                'category': service_info.get('category', 'other'),
                'risk_level': service_info.get('risk_level', 'MEDIUM')
            }
            services.append(service_detail)
        
        return services
    
    def _grab_banner(self, target: str, port: int) -> str:
        """Grab service banner with timeout"""
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.connection_timeout)
                sock.connect((target, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
        except:
            # Try one more time with no data sent (for non-HTTP services)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.connection_timeout)
                    sock.connect((target, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
            except:
                pass
        return banner
    
    def _get_http_info(self, target: str, port: int) -> Dict:
        """Get HTTP service information"""
        protocol = 'https' if port == 443 or port == 8443 else 'http'
        url = f"{protocol}://{target}:{port}"
        try:
            response = requests.get(
                url, 
                timeout=self.connection_timeout,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 SecurityScan'}
            )
            return {
                'status': response.status_code,
                'server': response.headers.get('Server', ''),
                'title': self._extract_title(response.text),
                'headers': dict(response.headers)
            }
        except:
            return None
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        import re
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return ""
    
    def _run_nmap_service_detection(self, target: str, open_ports: List[int], config: Dict, timeout: int = 60) -> List[Dict]:
        """Run nmap service detection with timeout"""
        if not open_ports:
            return []
        
        # Create a minimal scan config
        args = "-sV -T4 --version-all"
        ports_str = ','.join(map(str, open_ports))
        
        try:
            # Check if nmap is available and working
            try:
                self.scanner.scan('127.0.0.1', '22', "-sV -T5")
            except:
                self.logger.warning("Nmap test scan failed, skipping nmap service detection")
                return []
            
            # Run the scan with manual timeout using threading
            result_holder = []
            
            def run_scan():
                try:
                    scan_result = self.scanner.scan(target, ports_str, args)
                    result_holder.append(scan_result)
                except Exception as e:
                    self.logger.error(f"Nmap scan error in thread: {str(e)}")
            
            # Start thread
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.daemon = True
            scan_thread.start()
            
            # Wait with timeout
            scan_thread.join(timeout)
            
            if not result_holder:
                self.logger.warning(f"Nmap scan timed out or failed after {timeout}s")
                return []
            
            # Process results
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
            
            return services
        except Exception as e:
            self.logger.error(f"Error in nmap service detection: {str(e)}")
            return []
            
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
                'arguments': '-sV -sT -Pn -T4 --version-all'  # Full scan
            },
            'stealth': {
                'ports': '1-1000',
                'arguments': '-sV -sS -Pn -T2 --version-all'  # Stealth scan
            }
        }
        return configs.get(scan_type, configs['standard'])

    def _check_port(self, target: str, port: int, timeout: int = 1) -> bool:
        """Check if a port is open with timeout"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
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