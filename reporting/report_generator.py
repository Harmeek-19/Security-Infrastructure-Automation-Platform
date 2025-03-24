import logging
from datetime import datetime
import json
from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
from .models import Report
from reconnaissance.models import Subdomain, PortScan
from vulnerability.models import Vulnerability

class ReportGenerator:
    def __init__(self):
        # Add logger initialization
        self.logger = logging.getLogger(__name__)
        
# File: reporting/report_generator.py
    def generate_report(self, report_type: str, target: str, output_format: str = 'json', scan_results: dict = None) -> Report:
        """
        Generate a security report
        
        Args:
            report_type: Type of report ('basic', 'detailed', 'executive')
            target: Target hostname/domain
            output_format: Format to generate ('json', 'html', 'pdf')
            scan_results: Optional dictionary containing scan results to include
            
        Returns:
            Report: The generated report object
        """
        # Clean target string
        target = target.strip()
        
        if report_type not in ['basic', 'detailed', 'executive']:
            report_type = 'basic'
        
        # Generate report content based on type
        try:
            if report_type == 'detailed':
                content = self.generate_detailed_report(target, scan_results)
            elif report_type == 'executive':
                content = self.generate_executive_report(target, scan_results)
            else:
                content = self.generate_basic_report(target, scan_results)
            
            # Make sure severity counts are properly calculated
            self._update_severity_counts(content)
            
            # Add workflow_id to content if provided in scan_results
            if scan_results and 'workflow_id' in scan_results:
                content['workflow_id'] = scan_results['workflow_id']
            
            # If output format is PDF, ensure proper formatting
            if output_format == 'pdf':
                content = self._format_for_pdf(content)
            
            # Properly serialize content to JSON string
            json_content = json.dumps(content, cls=DjangoJSONEncoder)
            
            # Create and save the report
            report = Report.objects.create(
                title=f"{report_type.capitalize()} Security Report - {target}",
                content=json_content,
                report_type=f"{report_type}_{output_format}"
            )
            
            self.logger.info(f"Generated {report_type} report for {target} with ID {report.id}")
            return report
                
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            raise
    
    
    def _update_severity_counts(self, content: dict) -> None:
        """
        Ensure vulnerability severity counts are accurate
        """
        if 'vulnerabilities' not in content:
            return
        
        # Reset counters
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Count each vulnerability by severity
        for vuln in content['vulnerabilities']:
            severity = vuln.get('severity', '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Update summary with accurate counts
        if 'summary' in content:
            for severity, count in severity_counts.items():
                content['summary'][severity] = count
        
        return

    def _format_for_pdf(self, content: dict) -> dict:
        """
        Format report content specifically for PDF output
        """
        # Create a copy to avoid modifying the original
        pdf_content = content.copy()
        
        # Ensure proper table formatting for vulnerabilities
        if 'vulnerabilities' in pdf_content:
            for vuln in pdf_content['vulnerabilities']:
                # Ensure descriptions are properly formatted
                if 'description' in vuln:
                    vuln['description'] = self._clean_description(vuln['description'])
                
                # Ensure evidence is properly formatted
                if 'evidence' in vuln:
                    vuln['evidence'] = self._clean_evidence(vuln['evidence'])
        
        # Ensure network visualization data is properly formatted
        if 'network_data' in pdf_content:
            pdf_content['network_data'] = self._format_network_data_for_pdf(pdf_content['network_data'])
        
        return pdf_content

    def _format_network_data_for_pdf(self, network_data: dict) -> dict:
        """Format network visualization data for PDF output"""
        # Simplify network data to avoid rendering issues
        if not network_data:
            return {}
            
        # Limit number of nodes and links to avoid overcrowding
        if 'nodes' in network_data and len(network_data['nodes']) > 20:
            # Keep only the most important 20 nodes
            network_data['nodes'] = sorted(
                network_data['nodes'], 
                key=lambda x: self._get_node_importance(x)
            )[:20]
            
            # Keep only links between these nodes
            node_ids = {node['id'] for node in network_data['nodes']}
            network_data['links'] = [
                link for link in network_data.get('links', [])
                if link['source'] in node_ids and link['target'] in node_ids
            ]
        
        return network_data

    def _get_node_importance(self, node: dict) -> int:
        """Calculate node importance for filtering"""
        # Host nodes are most important
        if node.get('type') == 'host':
            return 100
            
        # Next subdomains
        if node.get('type') == 'subdomain':
            return 90
            
        # Important service nodes
        if node.get('type') == 'service':
            # Web services are more important
            if 'http' in node.get('name', '').lower():
                return 80
            return 70
            
        # High and critical vulnerabilities
        if node.get('type') == 'vulnerability':
            if 'critical' in node.get('name', '').lower():
                return 85
            if 'high' in node.get('name', '').lower():
                return 75
                
        # Default importance
        return 0

    # Existing methods below
    
    def generate_basic_report(self, target: str, scan_results: dict = None) -> dict:
        """Generate a basic security report"""
        subdomains = Subdomain.objects.filter(domain=target)
        port_scans = PortScan.objects.filter(host=target)
        vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
        open_ports = self._get_open_ports(target)

        # Use provided scan_results if available
        if scan_results and 'vulnerabilities' in scan_results:
            # Combine DB findings with scan results if available
            vuln_count = len(scan_results['vulnerabilities'])
            self.logger.info(f"Incorporating {vuln_count} vulnerabilities from scan results")
            
            # Process each vulnerability to ensure it's in the database
            for vuln_data in scan_results['vulnerabilities']:
                try:
                    # Create or update vulnerability in the database
                    vuln_name = vuln_data.get('name', 'Unknown Vulnerability')
                    vuln_severity = vuln_data.get('severity', 'LOW')
                    
                    # Normalize severity
                    if isinstance(vuln_severity, str):
                        vuln_severity = vuln_severity.upper()
                    
                    Vulnerability.objects.update_or_create(
                        target=target,
                        name=vuln_name,
                        defaults={
                            'description': vuln_data.get('description', ''),
                            'severity': vuln_severity,
                            'vuln_type': vuln_data.get('type', 'unknown'),
                            'evidence': vuln_data.get('evidence', ''),
                            'source': vuln_data.get('source', 'scan'),
                            'confidence': vuln_data.get('confidence', 'medium'),
                            'cvss_score': vuln_data.get('cvss_score', 0.0),
                            'is_fixed': False
                        }
                    )
                except Exception as e:
                    self.logger.error(f"Error saving vulnerability from scan results: {str(e)}")
            
            # Refresh vulnerabilities from database to include the ones we just added
            vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)

        # Create the report structure
        report = {
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
        
        # Log key metrics
        self.logger.info(f"Generated basic report for {target} with {vulnerabilities.count()} vulnerabilities")
        
        return report

    def generate_detailed_report(self, target: str, scan_results: dict = None) -> dict:
        """Generate a detailed security report"""
        basic_report = self.generate_basic_report(target, scan_results)
        vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
        
        # Enhanced port analysis
        open_ports = self._get_open_ports(target)
        port_risks = self._analyze_port_risks(open_ports)
        
        # Calculate vulnerability severity counts
        vulnerability_severity = {
            'critical': vulnerabilities.filter(severity='CRITICAL').count(),
            'high': vulnerabilities.filter(severity='HIGH').count(),
            'medium': vulnerabilities.filter(severity='MEDIUM').count(),
            'low': vulnerabilities.filter(severity='LOW').count()
        }
        
        # Calculate source counts
        vulnerability_sources = {
            'internal': vulnerabilities.filter(source='internal').count(),
            'zap': vulnerabilities.filter(source='zap').count(),
            'nuclei': vulnerabilities.filter(source='nuclei').count(),
            'multiple': vulnerabilities.exclude(source__in=['internal', 'zap', 'nuclei']).count()
        }
        
        detailed_info = {
            'port_analysis': {
                'high_risk_ports': port_risks['high_risk'],
                'medium_risk_ports': port_risks['medium_risk'],
                'low_risk_ports': port_risks['low_risk']
            },
            'vulnerability_severity': vulnerability_severity,
            'vulnerability_sources': vulnerability_sources
        }
        
        # Log key metrics
        self.logger.info(f"Vulnerability severity counts: {vulnerability_severity}")
        
        return {**basic_report, 'detailed_info': detailed_info}

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
        
        # Log key metrics
        self.logger.info(f"Executive report metrics: Critical={critical_vulns.count()}, High={high_vulns.count()}, Total={vulnerabilities.count()}")
        
        return {**basic_report, 'executive_summary': executive_summary}

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
    
    def _serialize_vulnerability(self, vuln):
        """Properly serialize a vulnerability instance with improved formatting"""
        
        # Clean up description to remove repetition
        description = self._clean_description(vuln.description)
        
        # Clean up evidence to remove repetition
        evidence = self._clean_evidence(vuln.evidence)
        
        return {
            'id': vuln.id,
            'target': vuln.target,
            'name': vuln.name,
            'description': description,
            'severity': vuln.severity,
            'vuln_type': vuln.vuln_type,
            'type': vuln.vuln_type,  # Add duplicate field for template compatibility
            'evidence': evidence,
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

# File: reporting/report_generator.py

    def _clean_description(self, description):
        """Clean up repetitive content in descriptions"""
        if not description:
            return ""
        
        # Remove prefixes like "zap:" that appear at the beginning
        if description.startswith("zap:"):
            description = description[4:].strip()
        
        # Split by paragraphs first (handles cases like the CSP text)
        paragraphs = description.split('\n\n')
        
        # Store unique paragraphs preserving order
        unique_paragraphs = []
        seen_paragraphs = set()
        
        for paragraph in paragraphs:
            paragraph = paragraph.strip()
            if not paragraph:
                continue
            
            # Use the first 100 chars as a fingerprint to identify similar paragraphs
            fingerprint = paragraph[:100].lower()
            
            if fingerprint not in seen_paragraphs:
                unique_paragraphs.append(paragraph)
                seen_paragraphs.add(fingerprint)
        
        # For each paragraph, clean duplicate sentences
        cleaned_paragraphs = []
        for paragraph in unique_paragraphs:
            # Split by sentences
            sentences = paragraph.split('. ')
            
            # Remove duplicate sentences
            unique_sentences = []
            seen_sentences = set()
            
            for sentence in sentences:
                sentence = sentence.strip()
                if not sentence:
                    continue
                
                # Create a fingerprint for the sentence
                fingerprint = sentence.lower()
                
                # Only add if not already seen
                if fingerprint not in seen_sentences:
                    unique_sentences.append(sentence)
                    seen_sentences.add(fingerprint)
            
            # Rejoin sentences
            cleaned_paragraph = '. '.join(unique_sentences)
            if not cleaned_paragraph.endswith('.'):
                cleaned_paragraph += '.'
            
            cleaned_paragraphs.append(cleaned_paragraph)
        
        # Join the cleaned paragraphs, limit to a reasonable length
        result = '\n\n'.join(cleaned_paragraphs)
        
        # If still too long, truncate with an indicator
        if len(result) > 2000:
            result = result[:1997] + '...'
            
        return result

    def _clean_evidence(self, evidence):
        """Clean up repetitive content in evidence"""
        if not evidence:
            return ""
        
        # Split by newlines
        lines = evidence.split('\n')
        
        # Store unique evidence items with counts
        unique_lines = []
        seen_patterns = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract the pattern (e.g., "nginx/1.19.0" from "zap: nginx/1.19.0")
            if ': ' in line:
                prefix, pattern = line.split(': ', 1)
                processed_line = f"{prefix}: {pattern}"
            else:
                prefix, pattern = "", line
                processed_line = line
            
            # Use lowercase for matching but preserve original case for display
            pattern_key = pattern.lower()
            
            # Track this pattern
            if pattern_key in seen_patterns:
                seen_patterns[pattern_key]['count'] += 1
                
                # Only keep a maximum of 2 examples per pattern
                if seen_patterns[pattern_key]['count'] <= 2:
                    unique_lines.append(processed_line)
            else:
                seen_patterns[pattern_key] = {
                    'count': 1,
                    'line': processed_line
                }
                unique_lines.append(processed_line)
        
        # Add counts for patterns with more than 2 occurrences
        result_lines = []
        
        # First add all the unique lines we want to keep
        for line in unique_lines:
            result_lines.append(line)
        
        # Then add summary counts for patterns with more occurrences
        for pattern, info in seen_patterns.items():
            if info['count'] > 2:
                extra_count = info['count'] - 2
                if extra_count > 0:
                    # Extract prefix from the line to maintain consistency
                    if ': ' in info['line']:
                        prefix = info['line'].split(': ', 1)[0]
                        result_lines.append(f"{prefix}: ... and {extra_count} more similar items")
                    else:
                        result_lines.append(f"... and {extra_count} more similar items")
        
        # Rejoin lines, limit overall size
        result = '\n'.join(result_lines)
        
        # If still too long, truncate
        if len(result) > 500:
            result = result[:497] + '...'
            
        return result
        
    def _similarity(self, str1, str2):
        """Calculate similarity between two strings"""
        # Simple similarity check based on word overlap
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())
        
        if not words1 or not words2:
            return 0.0
            
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)