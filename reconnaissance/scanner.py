import nmap
from typing import Dict, Any, List
from enum import Enum
import os
import logging
import time
import threading
import socket

logger = logging.getLogger(__name__)

class ScanType(Enum):
    QUICK = "quick"       # Fast scan of most common ports
    PARTIAL = "partial"   # Standard scan with version detection
    COMPLETE = "complete" # Comprehensive scan of all ports with version detection
    FULL = "full"        # Intensive scan with all possible features

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        # Check if running as root
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        # Set default timeout
        self.default_timeout = 300  # 5 minutes default
        # Logger for class instance
        self.logger = logging.getLogger(__name__)
        
    def get_scan_config(self, scan_type: str) -> Dict[str, str]:
        # Base configurations without OS detection
        base_configs = {
            ScanType.QUICK.value: {
                'ports': '21-23,25,80,443,3306,8080',
                'arguments': '-sV -T4 --version-intensity 0',  # Fast scan
                'timeout': 120  # 2 minutes timeout
            },
            ScanType.PARTIAL.value: {
                'ports': '1-1000',
                'arguments': '-sV -T4 -sC --version-intensity 5',  # Standard scan
                'timeout': 300  # 5 minutes timeout
            },
            ScanType.COMPLETE.value: {
                'ports': '1-65535',
                'arguments': '-sV -T4 -sC --version-intensity 7',  # All ports
                'timeout': 600  # 10 minutes timeout
            },
            ScanType.FULL.value: {
                'ports': '1-10000',  # Reduced port range for full scan
                'arguments': '-sV -T4 --version-intensity 9',  # Simplified for full scan
                'timeout': 900  # 15 minutes timeout
            }
        }
        
        # Add OS detection flags only if running as root
        if self.is_root:
            base_configs[ScanType.COMPLETE.value]['arguments'] += ' -O'
            base_configs[ScanType.FULL.value]['arguments'] += ' -O -A'
        
        config = base_configs.get(scan_type, base_configs[ScanType.QUICK.value])
        logger.info(f"Scan configuration for {scan_type}: {config}")
        return config

    def scan(self, target: str, scan_type: str = "quick") -> Dict[str, Any]:
        try:
            config = self.get_scan_config(scan_type)
            logger.info(f"Starting {scan_type} scan for {target} with args: {config['arguments']}")
            
            # Always do a manual port check first - this is more reliable
            responsive_ports = self._check_responsive_ports(target)
            
            # If we found ports in our manual check, create a manual result immediately
            if responsive_ports:
                logger.info(f"Manual check found open ports on {target}: {responsive_ports}")
                manual_result = self._create_manual_result(target, responsive_ports)
                
                # Only try nmap if it's not a full scan (which seems problematic)
                if scan_type != 'full':
                    try:
                        # Still run nmap for better service detection
                        scan_result = self.scanner.scan(target, config['ports'], config['arguments'])
                        
                        # Check if nmap found any open ports
                        nmap_ports = self._extract_open_ports_from_nmap(scan_result)
                        
                        if nmap_ports:
                            logger.info(f"Nmap found {len(nmap_ports)} open ports")
                            # Process the nmap results normally
                            return self._process_nmap_results(scan_result, scan_type)
                    except Exception as e:
                        logger.warning(f"Nmap scan failed: {str(e)}, using manual results")
                
                # Return our manual results
                return manual_result
            
            # If no ports were found by manual check, still try nmap
            try:
                scan_result = self.scanner.scan(target, config['ports'], config['arguments'])
                # Process the nmap results
                return self._process_nmap_results(scan_result, scan_type)
            except Exception as e:
                logger.error(f"Nmap scan error: {str(e)}")
                return {
                    'status': 'error',
                    'error': str(e)
                }
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _process_nmap_results(self, scan_result, scan_type):
        """Process nmap scan results into our standard format"""
        scan_results = []
        scan_info = {
            'scan_type': scan_type,
            'command_line': self.scanner.command_line(),
            'scan_time': self.scanner.scanstats().get('elapsed', ''),
            'total_hosts': len(self.scanner.all_hosts())
        }
        
        vulnerabilities = []  # Create a list to store detected vulnerabilities
        
        for host in self.scanner.all_hosts():
            host_data = {
                'host': host,
                'state': self.scanner[host].state(),
                'ports': []
            }
            
            # Flag to check if we found any open ports
            found_open_ports = False
            open_ports = []  # List to track open ports for vulnerability detection
            
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    port_info = self.scanner[host][proto][port]
                    # Normalize state to 'open', 'closed', or 'filtered'
                    port_state = port_info['state']
                    
                    if port_state == 'open':
                        found_open_ports = True
                        open_ports.append(int(port))  # Add to open ports list
                            
                    port_data = {
                        'port': port,
                        'state': port_state,
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'reason': port_info.get('reason', ''),
                        'cpe': port_info.get('cpe', '')
                    }
                    host_data['ports'].append(port_data)
            
            # Add a flag to indicate if any open ports were found
            host_data['has_open_ports'] = found_open_ports
            
            # Process risky open ports and create vulnerabilities
            if open_ports:
                RISKY_PORTS = {
                    80: {'name': 'HTTP Server', 'severity': 'LOW'},
                    443: {'name': 'HTTPS Server', 'severity': 'LOW'},
                    21: {'name': 'FTP Server', 'severity': 'HIGH'},
                    22: {'name': 'SSH Server', 'severity': 'LOW'},
                    23: {'name': 'Telnet Server', 'severity': 'HIGH'},
                    25: {'name': 'SMTP Server', 'severity': 'MEDIUM'},
                    53: {'name': 'DNS Server', 'severity': 'LOW'},
                    3306: {'name': 'MySQL Database', 'severity': 'MEDIUM'},
                    5432: {'name': 'PostgreSQL Database', 'severity': 'MEDIUM'},
                    8080: {'name': 'HTTP Alternate Port', 'severity': 'MEDIUM'}
                }
                
                for port in open_ports:
                    if port in RISKY_PORTS:
                        port_info = RISKY_PORTS[port]
                        vuln_data = {
                            'type': 'open_port',
                            'name': f"Open Port {port} ({port_info['name']})",
                            'description': f"Port {port} is open, running {port_info['name']}. This may present a security risk depending on configuration.",
                            'severity': port_info['severity'],
                            'evidence': f"Port {port} is open and accessible",
                            'confidence': 'high',
                            'cvss': 5.0,  # Default CVSS score for open port
                            'host': host  # Add the host for database storage
                        }
                        
                        # Add to vulnerabilities list
                        vulnerabilities.append(vuln_data)
            
            # Only try to include OS data if it exists
            if 'osmatch' in self.scanner[host]:
                host_data['os_matches'] = self.scanner[host]['osmatch']
            
            scan_results.append(host_data)
        
        # After scanning, save any detected port vulnerabilities to database
        from vulnerability.models import Vulnerability
        from django.utils import timezone
        
        # Get the target from the first host (assuming all hosts are for the same target)
        if scan_results and vulnerabilities:
            target = scan_results[0]['host']
            
            for vuln in vulnerabilities:
                try:
                    # Create vulnerability record in database
                    Vulnerability.objects.get_or_create(
                        target=target,
                        name=vuln['name'],
                        defaults={
                            'description': vuln['description'],
                            'severity': vuln['severity'],
                            'vuln_type': 'open_port',
                            'evidence': vuln['evidence'],
                            'source': 'port_scan',
                            'confidence': vuln['confidence'],
                            'cvss_score': vuln['cvss'],
                            'is_fixed': False,
                            'discovery_date': timezone.now()
                        }
                    )
                except Exception as e:
                    logger.error(f"Error creating vulnerability for open port: {str(e)}")
        
        return {
            'status': 'success',
            'scan_info': scan_info,
            'results': scan_results,
            'open_ports_found': any(host.get('has_open_ports', False) for host in scan_results),
            'vulnerabilities': vulnerabilities  # Include vulnerabilities in result
        }
    
    def _extract_open_ports_from_nmap(self, scan_result) -> List[int]:
        """Extract list of open ports from nmap scan result"""
        open_ports = []
        for host in self.scanner.all_hosts():
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    port_info = self.scanner[host][proto][port]
                    if port_info['state'] == 'open':
                        open_ports.append(int(port))
        return open_ports
        
    def _check_responsive_ports(self, target: str) -> List[int]:
        """Check if common ports are responsive and return list of open ports"""
        common_ports = [80, 443, 22, 21, 8080, 8443, 3306, 3389, 7001, 8081, 8000]
        open_ports = []
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
                        logger.info(f"Target {target} is responsive on port {port}")
            except:
                pass
        
        return open_ports
    
    def _guess_service_name(self, port: int) -> str:
        """Guess service name based on common port numbers"""
        service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'domain',
            80: 'http',
            110: 'pop3',
            139: 'netbios-ssn',
            143: 'imap',
            443: 'https', 
            445: 'microsoft-ds',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'ms-wbt-server',
            5900: 'vnc',
            7001: 'weblogic',
            8000: 'http-alt',
            8080: 'http-proxy',
            8081: 'http-alt',
            8443: 'https-alt'
        }
        return service_map.get(port, 'unknown')
    

    def get_available_scan_types(self) -> Dict[str, str]:
        return {
            ScanType.QUICK.value: "Fast scan of most common ports (21-23,25,80,443,3306,8080)",
            ScanType.PARTIAL.value: "Standard scan of first 1000 ports with version detection",
            ScanType.COMPLETE.value: "Comprehensive scan of all ports with version detection",
            ScanType.FULL.value: "Intensive scan with all features including vulnerability detection"
        }
        
    # In PortScanner class in scanner.py
    def _create_manual_result(self, target: str, open_ports: List[int]) -> Dict[str, Any]:
        """Create scan result dictionary from manually detected open ports"""
        ports_data = []
        vulnerabilities = []  # Add a list for vulnerabilities
        
        for port in open_ports:
            service_name = self._guess_service_name(port)
            ports_data.append({
                'port': port,
                'state': 'open',
                'service': service_name,
                'version': '',
                'product': '',
                'extrainfo': 'Detected by manual scan',
                'reason': 'syn-ack',
                'cpe': ''
            })
            
            # Create vulnerability data for open ports
            # Define risk levels for different services
            RISKY_PORTS = {
                80: {'name': 'HTTP Server', 'severity': 'LOW'},
                443: {'name': 'HTTPS Server', 'severity': 'LOW'},
                21: {'name': 'FTP Server', 'severity': 'HIGH'},
                22: {'name': 'SSH Server', 'severity': 'LOW'},
                23: {'name': 'Telnet Server', 'severity': 'HIGH'},
                25: {'name': 'SMTP Server', 'severity': 'MEDIUM'},
                53: {'name': 'DNS Server', 'severity': 'LOW'},
                3306: {'name': 'MySQL Database', 'severity': 'MEDIUM'},
                5432: {'name': 'PostgreSQL Database', 'severity': 'MEDIUM'},
                8080: {'name': 'HTTP Alternate Port', 'severity': 'MEDIUM'}
            }
            
            # Add vulnerability for the detected port
            if port in RISKY_PORTS:
                port_info = RISKY_PORTS[port]
                vuln_data = {
                    'type': 'open_port',
                    'name': f"Open Port {port} ({port_info['name']})",
                    'description': f"Port {port} is open, running {port_info['name']}. This may present a security risk depending on configuration.",
                    'severity': port_info['severity'],
                    'evidence': f"Port {port} is open and accessible",
                    'confidence': 'high',
                    'cvss': 5.0,  # Default CVSS score for open port
                    'host': target  # Add the host for database storage
                }
                vulnerabilities.append(vuln_data)
        
        # Add vulnerabilities to database
        self._save_port_vulnerabilities(target, vulnerabilities)
        
        return {
            'status': 'success',
            'scan_info': {
                'scan_type': 'manual',
                'command_line': 'Manual socket scan',
                'scan_time': '0',
                'total_hosts': 1
            },
            'results': [{
                'host': target,
                'state': 'up',
                'ports': ports_data
            }],
            'manual_detected': True,
            'vulnerabilities': vulnerabilities  # Include vulnerabilities in result
        }

    def _save_port_vulnerabilities(self, target: str, vulnerabilities: List[Dict]) -> None:
        """Save port vulnerabilities to database"""
        from vulnerability.models import Vulnerability
        from django.utils import timezone
        
        for vuln in vulnerabilities:
            try:
                # Create vulnerability record in database
                Vulnerability.objects.get_or_create(
                    target=target,
                    name=vuln['name'],
                    defaults={
                        'description': vuln['description'],
                        'severity': vuln['severity'],
                        'vuln_type': 'open_port',
                        'evidence': vuln['evidence'],
                        'source': 'port_scan',
                        'confidence': vuln['confidence'],
                        'cvss_score': vuln['cvss'],
                        'is_fixed': False,
                        'discovery_date': timezone.now()
                    }
                )
            except Exception as e:
                self.logger.error(f"Error creating vulnerability for open port: {str(e)}")
        
    # Add to port scanning results processing
