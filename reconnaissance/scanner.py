import nmap
from typing import Dict, Any
from enum import Enum

class ScanType(Enum):
    QUICK = "quick"       # Fast scan of most common ports
    PARTIAL = "partial"   # Standard scan with version detection
    COMPLETE = "complete" # Comprehensive scan of all ports with version detection
    FULL = "full"        # Intensive scan with all possible features

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        
    def get_scan_config(self, scan_type: str) -> Dict[str, str]:
        scan_configs = {
            ScanType.QUICK.value: {
                'ports': '21-23,25,80,443,3306,8080',
                'arguments': '-sV -T4 --version-intensity 0'  # Fast scan
            },
            ScanType.PARTIAL.value: {
                'ports': '1-1000',
                'arguments': '-sV -T4 -sC --version-intensity 5'  # Standard scan
            },
            ScanType.COMPLETE.value: {
                'ports': '1-65535',
                'arguments': '-sV -T4 -sC -O --version-intensity 7'  # All ports
            },
            ScanType.FULL.value: {
                'ports': '1-65535',
                'arguments': '-sV -T4 -sC -O -A --version-intensity 9 --script=vuln'  # Everything
            }
        }
        return scan_configs.get(scan_type, scan_configs[ScanType.QUICK.value])

    def scan(self, target: str, scan_type: str = "quick") -> Dict[str, Any]:
        try:
            config = self.get_scan_config(scan_type)
            self.scanner.scan(target, config['ports'], config['arguments'])
            
            scan_results = []
            scan_info = {
                'scan_type': scan_type,
                'command_line': self.scanner.command_line(),
                'scan_time': self.scanner.scanstats().get('elapsed', ''),
                'total_hosts': len(self.scanner.all_hosts())
            }
            
            for host in self.scanner.all_hosts():
                host_data = {
                    'host': host,
                    'state': self.scanner[host].state(),
                    'ports': []
                }
                
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        port_info = self.scanner[host][proto][port]
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'reason': port_info.get('reason', ''),
                            'cpe': port_info.get('cpe', '')
                        }
                        host_data['ports'].append(port_data)
                
                if 'osmatch' in self.scanner[host]:
                    host_data['os_matches'] = self.scanner[host]['osmatch']
                
                scan_results.append(host_data)
            
            return {
                'status': 'success',
                'scan_info': scan_info,
                'results': scan_results
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def get_available_scan_types(self) -> Dict[str, str]:
        return {
            ScanType.QUICK.value: "Fast scan of most common ports (21-23,25,80,443,3306,8080)",
            ScanType.PARTIAL.value: "Standard scan of first 1000 ports with version detection",
            ScanType.COMPLETE.value: "Comprehensive scan of all ports with version and OS detection",
            ScanType.FULL.value: "Intensive scan with all features including vulnerability detection"
        }