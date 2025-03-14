from datetime import datetime
import json
from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
from .models import Report
from reconnaissance.models import Subdomain, PortScan
from vulnerability.models import Vulnerability

class ReportGenerator:
    def generate_report(self, report_type: str, target: str, output_format: str = 'json', scan_results: dict = None) -> Report:
        """
        Generate a security report
        
        Args:
            report_type: Type of report ('basic', 'detailed', 'executive')
            target: Target hostname/domain
            output_format: Format to generate (currently only 'json' is supported)
            scan_results: Optional dictionary containing scan results to include
            
        Returns:
            Report: The generated report object
        """
        # Clean target string
        target = target.strip()
        
        if report_type not in ['basic', 'detailed', 'executive']:
            report_type = 'basic'
        
        # Generate report content based on type
        if report_type == 'detailed':
            content = self.generate_detailed_report(target, scan_results)
        elif report_type == 'executive':
            content = self.generate_executive_report(target, scan_results)
        else:
            content = self.generate_basic_report(target, scan_results)
        
        # Properly serialize content to JSON string (all formats are currently JSON)
        json_content = json.dumps(content, cls=DjangoJSONEncoder)
        
        # Create and save the report
        report = Report.objects.create(
            title=f"{report_type.capitalize()} Security Report - {target}",
            content=json_content,
            report_type=f"{report_type}_{output_format}"
        )
        
        return report

    def _serialize_port_scan(self, port_scan):
        """Serialize port scan data"""
        return {
            'port': port_scan.port,
            'service': port_scan.service,
            'state': port_scan.state,
            'protocol': port_scan.protocol,
            'banner': port_scan.banner if port_scan.banner else '',
            'scan_date': port_scan.scan_date.isoformat()
        }

    def _get_open_ports(self, target: str) -> list:
        """Get all open ports with details"""
        open_ports = PortScan.objects.filter(
            host=target,
            state='open'
        ).order_by('port')
        return [self._serialize_port_scan(port) for port in open_ports]

    def _serialize_vulnerability(self, vuln):
        """Properly serialize a vulnerability instance"""
        return {
            'id': vuln.id,
            'target': vuln.target,
            'name': vuln.name,
            'description': vuln.description,
            'severity': vuln.severity,
            'vuln_type': vuln.vuln_type,
            'evidence': vuln.evidence,
            'discovery_date': vuln.discovery_date.isoformat(),
            'is_fixed': vuln.is_fixed,
            'fix_date': vuln.fix_date.isoformat() if vuln.fix_date else None,
            'source': vuln.source,
            'confidence': vuln.confidence,
            'cvss_score': vuln.cvss_score,
            'solution': vuln.solution if vuln.solution else '',
            'references': list(vuln.references) if vuln.references else [],
            'cwe': vuln.cwe if vuln.cwe else '',
            'metadata': dict(vuln.metadata) if vuln.metadata else {}
        }
    
    def generate_basic_report(self, target: str, scan_results: dict = None) -> dict:
        """Generate a basic security report"""
        subdomains = Subdomain.objects.filter(domain=target)
        port_scans = PortScan.objects.filter(host=target)
        vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
        open_ports = self._get_open_ports(target)

        # Use provided scan_results if available
        if scan_results:
            # You can integrate the scan_results into your report here
            # Example: Extract vulnerabilities from the scan_results
            if 'vulnerabilities' in scan_results:
                # Process the vulnerabilities from scan_results
                pass

        return {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'summary': {
                'total_subdomains': subdomains.count(),
                'total_ports_scanned': port_scans.count(),
                'total_vulnerabilities': vulnerabilities.count(),
                'open_ports_count': len(open_ports)
            },
            'subdomains': [model_to_dict(sub, exclude=['id']) for sub in subdomains],
            'open_ports': open_ports,
            'port_scan_summary': {
                'total_scanned': port_scans.count(),
                'open': port_scans.filter(state='open').count(),
                'closed': port_scans.filter(state='closed').count(),
                'filtered': port_scans.filter(state='filtered').count()
            },
            'vulnerabilities': [self._serialize_vulnerability(vuln) for vuln in vulnerabilities]
        }

    def generate_detailed_report(self, target: str, scan_results: dict = None) -> dict:
        """Generate a detailed security report"""
        basic_report = self.generate_basic_report(target, scan_results)
        vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
        
        # Enhanced port analysis
        open_ports = self._get_open_ports(target)
        port_risks = self._analyze_port_risks(open_ports)
        
        detailed_info = {
            'port_analysis': {
                'high_risk_ports': port_risks['high_risk'],
                'medium_risk_ports': port_risks['medium_risk'],
                'low_risk_ports': port_risks['low_risk']
            },
            'vulnerability_severity': {
                'critical': vulnerabilities.filter(severity='CRITICAL').count(),
                'high': vulnerabilities.filter(severity='HIGH').count(),
                'medium': vulnerabilities.filter(severity='MEDIUM').count(),
                'low': vulnerabilities.filter(severity='LOW').count()
            },
            'vulnerability_sources': {
                'internal': vulnerabilities.filter(source='internal').count(),
                'zap': vulnerabilities.filter(source='zap').count(),
                'nuclei': vulnerabilities.filter(source='nuclei').count(),
                'multiple': vulnerabilities.exclude(source__in=['internal', 'zap', 'nuclei']).count()
            }
        }
        
        return {**basic_report, 'detailed_info': detailed_info}

    def _analyze_port_risks(self, open_ports: list) -> dict:
        """Analyze risks associated with open ports"""
        high_risk_ports = [21, 23, 445, 3389]  # FTP, Telnet, SMB, RDP
        medium_risk_ports = [22, 25, 110, 143]  # SSH, SMTP, POP3, IMAP
        
        port_risks = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': []
        }
        
        for port_data in open_ports:
            port = port_data['port']
            if port in high_risk_ports:
                port_risks['high_risk'].append(port_data)
            elif port in medium_risk_ports:
                port_risks['medium_risk'].append(port_data)
            else:
                port_risks['low_risk'].append(port_data)
                
        return port_risks

    def generate_executive_report(self, target: str, scan_results: dict = None) -> dict:
        """Generate an executive summary report"""
        basic_report = self.generate_basic_report(target, scan_results)
        vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
        high_vulns = vulnerabilities.filter(severity='HIGH')
        critical_vulns = vulnerabilities.filter(severity='CRITICAL')
        
        # Enhanced metrics
        risk_metrics = {
            'critical_severity_vulns': critical_vulns.count(),
            'high_severity_vulns': high_vulns.count(),
            'open_ports': len(basic_report['open_ports']),
            'total_vulnerabilities': vulnerabilities.count(),
            'high_risk_ports': len(self._analyze_port_risks(basic_report['open_ports'])['high_risk'])
        }
        
        # Combine critical and high vulnerabilities in findings
        top_findings = []
        for vuln in critical_vulns:
            top_findings.append(self._serialize_vulnerability(vuln))
        if len(top_findings) < 5:  # Limit to 5 findings total
            for vuln in high_vulns[:5-len(top_findings)]:
                top_findings.append(self._serialize_vulnerability(vuln))
        
        executive_summary = {
            'risk_level': self._calculate_risk_level(risk_metrics),
            'critical_findings': top_findings,
            'risk_metrics': risk_metrics,
            'recommendations': self._generate_recommendations(risk_metrics, basic_report)
        }
        
        return {**basic_report, 'executive_summary': executive_summary}
    
    def _calculate_risk_level(self, metrics):
        """Calculate overall risk level based on metrics"""
        if metrics['critical_severity_vulns'] > 0:
            return 'CRITICAL'
        elif metrics['high_severity_vulns'] > 2:
            return 'HIGH'
        elif metrics['high_severity_vulns'] > 0 or metrics['high_risk_ports'] > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, metrics, basic_report):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Add recommendations based on findings
        if metrics['critical_severity_vulns'] > 0 or metrics['high_severity_vulns'] > 0:
            recommendations.append({
                'title': 'Address High and Critical Vulnerabilities',
                'description': 'Fix identified critical and high vulnerabilities as a priority.'
            })
            
        if metrics['high_risk_ports'] > 0:
            recommendations.append({
                'title': 'Secure High Risk Ports',
                'description': 'Restrict access to high risk services or replace with more secure alternatives.'
            })
            
        # Always add general recommendations
        recommendations.append({
            'title': 'Regular Security Testing',
            'description': 'Perform regular security assessments to identify new vulnerabilities.'
        })
        
        return recommendations
    
    