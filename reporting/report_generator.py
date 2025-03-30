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
        Generate a security report with improved vulnerability handling
        
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
            self.logger.info(f"Starting report generation for {target}, type: {report_type}, format: {output_format}")
            
            # First, ensure vulnerabilities from scan_results are saved to the database
            if scan_results and 'vulnerabilities' in scan_results:
                vuln_list = scan_results['vulnerabilities']
                vuln_count = len(vuln_list)
                self.logger.info(f"Processing {vuln_count} vulnerabilities from scan results")
                
                from vulnerability.models import Vulnerability
                saved_count = 0
                
                # Save each vulnerability to database
                for vuln_data in vuln_list:
                    try:
                        # Ensure we have basic required fields
                        name = vuln_data.get('name', 'Unknown Vulnerability')
                        
                        # Normalize severity
                        severity = vuln_data.get('severity', 'LOW')
                        if isinstance(severity, str):
                            severity = severity.upper()
                        
                        # Get vuln_type from either 'type' or 'vuln_type' field
                        vuln_type = vuln_data.get('type', vuln_data.get('vuln_type', 'unknown'))
                        
                        # Create or update vulnerability in database
                        vuln, created = Vulnerability.objects.update_or_create(
                            target=target,
                            name=name,
                            defaults={
                                'description': vuln_data.get('description', ''),
                                'severity': severity,
                                'vuln_type': vuln_type,
                                'evidence': vuln_data.get('evidence', ''),
                                'source': vuln_data.get('source', 'scan'),
                                'confidence': vuln_data.get('confidence', 'medium'),
                                'cvss_score': vuln_data.get('cvss_score', 0.0),
                                'is_fixed': False
                            }
                        )
                        
                        status = "Created" if created else "Updated"
                        self.logger.debug(f"{status} vulnerability in database: {name}")
                        saved_count += 1
                        
                    except Exception as e:
                        self.logger.error(f"Error saving vulnerability '{vuln_data.get('name', 'unknown')}': {str(e)}")
                
                self.logger.info(f"Saved {saved_count} vulnerabilities to database")
                
                # Get fresh data from database to ensure report accuracy
                from vulnerability.models import Vulnerability
                db_vulns = Vulnerability.objects.filter(target=target, is_fixed=False)
                db_vuln_count = db_vulns.count()
                self.logger.info(f"Found {db_vuln_count} vulnerabilities in database for report")
            
            # Generate the appropriate report type
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
            
            # Verify vulnerability data is present
            if 'vulnerabilities' in content:
                vuln_count = len(content['vulnerabilities'])
                self.logger.info(f"Report contains {vuln_count} vulnerabilities")
            else:
                self.logger.warning("No vulnerabilities included in the report")
            
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
        Ensure vulnerability severity counts are accurate with detailed logging
        """
        if 'vulnerabilities' not in content:
            self.logger.warning("No 'vulnerabilities' key found in content - cannot update severity counts")
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
        self.logger.info(f"Counting {len(content['vulnerabilities'])} vulnerabilities by severity")
        
        for vuln in content['vulnerabilities']:
            severity = vuln.get('severity', '').lower()
            self.logger.debug(f"Vulnerability: {vuln.get('name')}, Severity: {severity}")
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                self.logger.warning(f"Unknown severity level: {severity} for vulnerability {vuln.get('name')}")
        
        # Update summary with accurate counts
        if 'summary' in content:
            for severity, count in severity_counts.items():
                content['summary'][severity] = count
                
            self.logger.info(f"Updated severity counts: {severity_counts}")
        else:
            self.logger.warning("No 'summary' key found in content - cannot update severity counts")
        
        return

    def _format_for_pdf(self, content: dict) -> dict:
        """
        Format report content specifically for PDF output
        
        Args:
            content: The raw report content
            
        Returns:
            dict: Report content formatted for PDF output
        """
        # Create a copy to avoid modifying the original
        pdf_content = content.copy()
        
        # Ensure summary data is accessible at both top level and within report_data
        # This addresses the template variable lookup issue
        if 'summary' in pdf_content:
            # Add a copy at the top level for direct template access
            summary = pdf_content['summary'].copy()
            
            # Ensure exploit matching data is included in the report
            if 'executive_summary' in pdf_content and 'exploit_matches' in pdf_content['executive_summary']:
                summary['exploit_matches'] = pdf_content['executive_summary']['exploit_matches']
            
            # Make severity counts accessible at top level if available
            if 'detailed_info' in pdf_content and 'vulnerability_severity' in pdf_content['detailed_info']:
                for key, value in pdf_content['detailed_info']['vulnerability_severity'].items():
                    summary[key] = value
        
        return pdf_content

    def _calculate_risk_level_from_summary(self, summary):
        """Calculate risk level based on summary data"""
        if summary.get('critical', 0) > 0:
            return 'CRITICAL'
        elif summary.get('high', 0) > 2:
            return 'HIGH'
        elif summary.get('high', 0) > 0 or summary.get('open_ports_count', 0) > 5:
            return 'MEDIUM'
        else:
            return 'LOW'

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
        """Generate a basic security report with more robust handling of scan results"""
        # Fetch existing data from the database
        subdomains = Subdomain.objects.filter(domain=target)
        port_scans = PortScan.objects.filter(host=target)
        vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
        open_ports = self._get_open_ports(target)

        # Use provided scan_results if available
        processed_vulns = []
        if scan_results and 'vulnerabilities' in scan_results:
            # Process incoming vulnerabilities from scan results
            vuln_count = len(scan_results['vulnerabilities'])
            self.logger.info(f"Processing {vuln_count} vulnerabilities from scan results")
            
            # Save vulnerabilities to database for reporting
            for vuln_data in scan_results['vulnerabilities']:
                try:
                    # Extract core vulnerability data
                    vuln_name = vuln_data.get('name', 'Unknown Vulnerability')
                    vuln_severity = vuln_data.get('severity', 'LOW')
                    
                    # Normalize severity
                    if isinstance(vuln_severity, str):
                        vuln_severity = vuln_severity.upper()
                    
                    # Create/update vulnerability record
                    vuln, created = Vulnerability.objects.update_or_create(
                        target=target,
                        name=vuln_name,
                        defaults={
                            'description': vuln_data.get('description', ''),
                            'severity': vuln_severity,
                            'vuln_type': vuln_data.get('type', vuln_data.get('vuln_type', 'unknown')),
                            'evidence': vuln_data.get('evidence', ''),
                            'source': vuln_data.get('source', 'scan'),
                            'confidence': vuln_data.get('confidence', 'medium'),
                            'cvss_score': vuln_data.get('cvss_score', 0.0),
                            'is_fixed': False
                        }
                    )
                    
                    # Add to processed list
                    processed_vulns.append(vuln)
                    self.logger.info(f"Processed vulnerability: {vuln_name} ({vuln_severity})")
                    
                except Exception as e:
                    self.logger.error(f"Error saving vulnerability from scan results: {str(e)}")
            
            # Refresh vulnerabilities from database to include the ones we just added
            if processed_vulns:
                self.logger.info(f"Successfully processed {len(processed_vulns)} vulnerabilities")
                # Use a combination of existing and newly added vulnerabilities
                vulnerabilities = Vulnerability.objects.filter(target=target, is_fixed=False)
                self.logger.info(f"Total vulnerabilities in database: {vulnerabilities.count()}")

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
        """Generate a detailed security report with exploit matches"""
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
        
        # Add exploit matching statistics
        exploit_matching = {}
        try:
            # Try to get exploit matching info from scan results first
            if scan_results and 'exploit_matching' in scan_results:
                exploit_matching = scan_results['exploit_matching']
            else:
                # Otherwise calculate it from the database
                from exploit_manager.models import ExploitMatch
                
                # Get total matches
                total_matches = ExploitMatch.objects.filter(
                    vulnerability__target=target,
                    vulnerability__is_fixed=False
                ).count()
                
                # Get vulnerabilities with matches
                vulns_with_matches = vulnerabilities.filter(
                    exploit_matches__isnull=False
                ).distinct().count()
                
                # Get top matches by confidence
                top_matches = ExploitMatch.objects.filter(
                    vulnerability__target=target,
                    vulnerability__is_fixed=False
                ).order_by('-confidence_score')[:5]
                
                match_details = []
                for match in top_matches:
                    match_details.append({
                        'vulnerability_id': match.vulnerability.id,
                        'vulnerability_name': match.vulnerability.name,
                        'exploit_title': match.exploit.title,
                        'exploit_id': match.exploit.exploit_id,
                        'confidence': match.confidence_score,
                        'source_url': match.exploit.source_url,
                        'cve_id': match.exploit.cve_id
                    })
                
                exploit_matching = {
                    'total_vulnerabilities': vulnerabilities.count(),
                    'vulnerabilities_with_matches': vulns_with_matches,
                    'total_matches': total_matches,
                    'match_details': match_details
                }
                
        except Exception as e:
            self.logger.error(f"Error getting exploit match data: {str(e)}")
        
        detailed_info = {
            'port_analysis': {
                'high_risk_ports': port_risks['high_risk'],
                'medium_risk_ports': port_risks['medium_risk'],
                'low_risk_ports': port_risks['low_risk']
            },
            'vulnerability_severity': vulnerability_severity,
            'vulnerability_sources': vulnerability_sources,
            'exploit_matching': exploit_matching
        }
        
        # Log key metrics
        self.logger.info(f"Vulnerability severity counts: {vulnerability_severity}")
        if exploit_matching:
            self.logger.info(f"Exploit matching: {exploit_matching.get('total_matches', 0)} matches for {exploit_matching.get('vulnerabilities_with_matches', 0)} vulnerabilities")
        
        return {**basic_report, 'detailed_info': detailed_info}

    def generate_executive_report(self, target: str, scan_results: dict = None) -> dict:
        """Generate an executive summary report with exploit matches"""
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
        
        # Get exploit matching information
        exploit_data = {}
        try:
            # Try to get exploit matching info from scan results first
            if scan_results and 'exploit_matching' in scan_results:
                exploit_data = scan_results['exploit_matching']
            else:
                # Otherwise calculate it from the database
                from exploit_manager.models import ExploitMatch
                
                # Count matches
                total_matches = ExploitMatch.objects.filter(
                    vulnerability__target=target,
                    vulnerability__is_fixed=False
                ).count()
                
                # Count vulnerabilities with matches
                vulns_with_matches = vulnerabilities.filter(
                    exploit_matches__isnull=False
                ).distinct().count()
                
                exploit_data = {
                    'total_matches': total_matches,
                    'vulnerabilities_with_matches': vulns_with_matches
                }
            
            # Add to risk metrics
            if exploit_data:
                risk_metrics['vulnerabilities_with_exploits'] = exploit_data.get('vulnerabilities_with_matches', 0)
                risk_metrics['total_exploit_matches'] = exploit_data.get('total_matches', 0)
        except Exception as e:
            self.logger.error(f"Error getting exploit match data for executive report: {str(e)}")
        
        # Combine critical and high vulnerabilities in findings
        top_findings = []
        for vuln in critical_vulns:
            top_findings.append(self._serialize_vulnerability(vuln))
        if len(top_findings) < 5:  # Limit to 5 findings total
            for vuln in high_vulns[:5-len(top_findings)]:
                top_findings.append(self._serialize_vulnerability(vuln))
        
        # Get top exploit matches
        top_exploit_matches = []
        try:
            if 'match_details' in exploit_data:
                top_exploit_matches = exploit_data['match_details']
            else:
                # Get from database if not in scan results
                from exploit_manager.models import ExploitMatch
                matches = ExploitMatch.objects.filter(
                    vulnerability__target=target,
                    vulnerability__is_fixed=False,
                    confidence_score__gte=0.4  # Only high confidence matches for executive report
                ).order_by('-confidence_score')[:3]
                
                for match in matches:
                    top_exploit_matches.append({
                        'vulnerability_name': match.vulnerability.name,
                        'exploit_title': match.exploit.title,
                        'confidence': match.confidence_score,
                        'cve_id': match.exploit.cve_id or "None",
                        'source_url': match.exploit.source_url
                    })
        except Exception as e:
            self.logger.error(f"Error getting top exploit matches: {str(e)}")
        
        executive_summary = {
            'risk_level': self._calculate_risk_level(risk_metrics),
            'critical_findings': top_findings,
            'risk_metrics': risk_metrics,
            'recommendations': self._generate_recommendations(risk_metrics, basic_report),
            'exploit_matches': top_exploit_matches
        }
        
        # Add extra recommendations for exploits if needed
        if risk_metrics.get('vulnerabilities_with_exploits', 0) > 0:
            executive_summary['recommendations'].insert(0, {
                'title': 'Address Vulnerabilities with Known Exploits',
                'description': f"Fix the {risk_metrics.get('vulnerabilities_with_exploits', 0)} vulnerabilities that have known public exploits as highest priority."
            })
        
        # Log key metrics
        self.logger.info(f"Executive report metrics: Critical={critical_vulns.count()}, High={high_vulns.count()}, Total={vulnerabilities.count()}")
        self.logger.info(f"Executive report exploit matches: {risk_metrics.get('total_exploit_matches', 0)}")
        
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
    
# File: reporting/report_generator.py
# In the _serialize_vulnerability method, add exploit match information

# File: reporting/report_generator.py
# In the _serialize_vulnerability method, add exploit match information

    def _serialize_vulnerability(self, vuln):
        """
        Properly serialize a vulnerability instance with correct ID handling for exploits
        
        Args:
            vuln: Vulnerability model instance
            
        Returns:
            dict: Serialized vulnerability data with exploit details
        """
        # Clean up description and evidence using helper methods
        description = self._clean_description(vuln.description)
        evidence = self._clean_evidence(vuln.evidence)
        
        # Get exploit matches with proper ID handling for links
        exploit_matches = []
        try:
            from exploit_manager.models import ExploitMatch
            matches = ExploitMatch.objects.filter(vulnerability=vuln)
            
            # Log the number of matches found for debugging
            match_count = matches.count()
            self.logger.info(f"Found {match_count} exploit matches for vulnerability {vuln.id}")
            
            if match_count > 0:
                for match in matches:
                    exploit = match.exploit
                    # Include both database ID and exploit_id to support proper linking
                    exploit_data = {
                        'id': exploit.id,  # Database ID for URL construction
                        'exploit_id': exploit.exploit_id,  # ExploitDB ID for reference
                        'title': exploit.title,
                        'description': exploit.description[:100] + '...' if len(exploit.description) > 100 else exploit.description,
                        'confidence': match.confidence_score,
                        'status': match.status,
                        'source_url': exploit.source_url,
                        'cve_id': exploit.cve_id or "None"
                    }
                    exploit_matches.append(exploit_data)
                    self.logger.debug(f"Added exploit match: Database ID={exploit.id}, ExploitDB ID={exploit.exploit_id}")
        except Exception as e:
            self.logger.error(f"Error retrieving exploit matches for vulnerability {vuln.id}: {str(e)}")
        
        # Build the complete vulnerability data object
        vuln_data = {
            'id': vuln.id,
            'target': vuln.target,
            'name': vuln.name,
            'description': description,
            'severity': vuln.severity,
            'vuln_type': vuln.vuln_type,
            'type': vuln.vuln_type,  # Duplicate field for template compatibility
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
            'metadata': dict(vuln.metadata) if vuln.metadata else {},
            'exploit_matches': exploit_matches  # Include properly formatted exploit matches
        }
        
        return vuln_data
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