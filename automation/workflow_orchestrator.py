# automation/workflow_orchestrator.py

import logging
import json
import socket
import time
from datetime import datetime, timedelta
from typing import Dict, List
from django.utils import timezone
from django.db import transaction
from django.conf import settings
from urllib.parse import urlparse

from reconnaissance.subdomain_enumerator import SubdomainEnumerator
from reconnaissance.scanner import PortScanner
from reconnaissance.service_identifier import ServiceIdentifier
from vulnerability.unified_scanner import UnifiedVulnerabilityScanner
from network_visualization.topology_mapper import TopologyMapper
from reporting.report_generator import ReportGenerator
from .models import ScanWorkflow, ScanTask, Notification
from .notification_manager import NotificationManager

logger = logging.getLogger(__name__)

class WorkflowOrchestrator:
    """
    Orchestrates the complete scanning workflow including reconnaissance,
    vulnerability scanning, network visualization, and report generation.
    
    Supports automatic scheduling, task dependencies, and failure handling.
    """
    
    # Workflow task types
    TASK_TYPES = {
        'subdomain_enumeration': 'Subdomain Enumeration',
        'port_scanning': 'Port Scanning',
        'service_identification': 'Service Identification',
        'vulnerability_scanning': 'Vulnerability Scanning',
        'network_mapping': 'Network Mapping',
        'report_generation': 'Report Generation'
    }
    
    # Task dependencies - keys depend on values
    TASK_DEPENDENCIES = {
        'port_scanning': ['subdomain_enumeration'],
        'service_identification': ['port_scanning'],
        'vulnerability_scanning': ['service_identification'],
        'network_mapping': ['service_identification'],
        'report_generation': ['vulnerability_scanning', 'network_mapping']
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.subdomain_enumerator = SubdomainEnumerator()
        self.port_scanner = PortScanner()
        self.service_identifier = ServiceIdentifier()
        self.vulnerability_scanner = UnifiedVulnerabilityScanner()
        self.topology_mapper = TopologyMapper()
        self.report_generator = ReportGenerator()
        self.notification_manager = NotificationManager()
    
    def parse_target_url(self, url: str) -> str:
        """
        Parse a target URL and extract just the hostname.
        Handles various URL formats including those with protocols, paths, query strings, etc.
        
        Args:
            url: The target URL to parse
            
        Returns:
            str: The clean hostname
        """
        # Handle empty values
        if not url:
            return ""
        
        try:
            # Remove protocol if present by using urlparse
            parsed = urlparse(url)
            
            # If netloc is empty, the URL might not have a protocol
            if not parsed.netloc:
                # Try adding a protocol and parsing again
                parsed = urlparse(f"http://{url}")
            
            # Extract just the hostname (netloc without port)
            hostname = parsed.netloc
            if ':' in hostname:
                hostname = hostname.split(':', 1)[0]
                
            # If still empty, return the original url as a last resort
            if not hostname:
                return url
                
            return hostname
        except Exception as e:
            self.logger.error(f"Error parsing URL {url}: {str(e)}")
            # Return the original URL if parsing fails
            return url
    
    def setup_workflow(self, workflow, target: str, scan_profile: str = 'standard'):
        """
        Set up tasks for an existing workflow
        
        Args:
            workflow: The existing ScanWorkflow object
            target: The domain or IP to scan
            scan_profile: Scan intensity level (quick, standard, full)
            
        Returns:
            Updated workflow
        """
        with transaction.atomic():
            # Create tasks with proper dependencies
            task_ids = {}
            
            # Create all tasks first
            for task_type, task_name in self.TASK_TYPES.items():
                task = ScanTask.objects.create(
                    workflow=workflow,
                    task_type=task_type,
                    name=f"{task_name} - {target}",
                    status='pending',
                    order=list(self.TASK_TYPES.keys()).index(task_type)
                )
                task_ids[task_type] = task.id
            
            # Set dependencies
            for task_type, dependencies in self.TASK_DEPENDENCIES.items():
                task = ScanTask.objects.get(id=task_ids[task_type])
                for dependency in dependencies:
                    dependency_task = ScanTask.objects.get(id=task_ids[dependency])
                    task.dependencies.add(dependency_task)
                task.save()
                
            # If scheduled for the future, create a notification 
            if workflow.scheduled_time and workflow.notification_email:
                Notification.objects.create(
                    workflow=workflow,
                    notification_type='workflow_scheduled',
                    recipient=workflow.notification_email,
                    subject=f"Scan scheduled: {workflow.name}",
                    message=f"A security scan for {target} has been scheduled to start at {workflow.scheduled_time}."
                )
                
            return workflow
        
    def _complete_workflow(self, workflow: ScanWorkflow) -> None:
        """Mark workflow as completed and send notifications"""
        workflow.status = 'completed'
        workflow.end_time = timezone.now()
        workflow.save()
        
        self.logger.info(f"Workflow {workflow.id} for {workflow.target} completed successfully")
        
        # Send completion notification
        if workflow.notification_email:
            self.notification_manager.send_workflow_completion_notification(workflow)
                
    def create_workflow(self, target: str, name: str = None, scan_profile: str = 'standard',
                      scheduled_time: datetime = None, notify_email: str = None) -> ScanWorkflow:
        """
        Create a new scanning workflow for a target
        
        Args:
            target: The domain or IP to scan
            name: Optional name for this workflow
            scan_profile: Scan intensity level (quick, standard, full)
            scheduled_time: When to start the scan (None = immediate)
            notify_email: Email to notify when scan completes
            
        Returns:
            ScanWorkflow object
        """
        if not name:
            name = f"Scan {target} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
        with transaction.atomic():
            # Create the workflow
            workflow = ScanWorkflow.objects.create(
                name=name,
                target=target,
                scan_profile=scan_profile,
                scheduled_time=scheduled_time,
                status='scheduled' if scheduled_time else 'pending',
                notification_email=notify_email
            )
            
            # Create tasks with proper dependencies
            task_ids = {}
            
            # Create all tasks first
            for task_type, task_name in self.TASK_TYPES.items():
                task = ScanTask.objects.create(
                    workflow=workflow,
                    task_type=task_type,
                    name=f"{task_name} - {target}",
                    status='pending',
                    order=list(self.TASK_TYPES.keys()).index(task_type)
                )
                task_ids[task_type] = task.id
            
            # Set dependencies
            for task_type, dependencies in self.TASK_DEPENDENCIES.items():
                task = ScanTask.objects.get(id=task_ids[task_type])
                for dependency in dependencies:
                    dependency_task = ScanTask.objects.get(id=task_ids[dependency])
                    task.dependencies.add(dependency_task)
                task.save()
                
            # If scheduled for the future, create a notification 
            if scheduled_time and notify_email:
                Notification.objects.create(
                    workflow=workflow,
                    notification_type='workflow_scheduled',
                    recipient=notify_email,
                    subject=f"Scan scheduled: {name}",
                    message=f"A security scan for {target} has been scheduled to start at {scheduled_time}."
                )
                
            return workflow
    
    def start_workflow(self, workflow_id: int) -> bool:
        """
        Start a workflow by ID
        
        Args:
            workflow_id: ID of the workflow to start
            
        Returns:
            bool: True if successfully started
        """
        try:
            workflow = ScanWorkflow.objects.get(id=workflow_id)
            
            # Check if it's time to start a scheduled workflow
            if workflow.status == 'scheduled' and workflow.scheduled_time:
                now = timezone.now()
                if now < workflow.scheduled_time:
                    self.logger.info(f"Workflow {workflow_id} is scheduled for {workflow.scheduled_time}, not starting yet")
                    return False
            
            # Update workflow status
            workflow.status = 'in_progress'
            workflow.start_time = timezone.now()
            workflow.save()
            
            self.logger.info(f"Starting workflow {workflow_id} for target {workflow.target}")
            
            # Get tasks with no dependencies (entry points)
            entry_tasks = ScanTask.objects.filter(
                workflow=workflow, 
                dependencies__isnull=True
            ).order_by('order')
            
            # Start entry tasks
            for task in entry_tasks:
                self._execute_task(task)
                
            return True
            
        except ScanWorkflow.DoesNotExist:
            self.logger.error(f"Workflow {workflow_id} not found")
            return False
        except Exception as e:
            self.logger.error(f"Error starting workflow {workflow_id}: {str(e)}")
            return False
    
    def check_pending_workflows(self) -> int:
        """
        Check for scheduled workflows that should be started
        
        Returns:
            int: Number of workflows started
        """
        now = timezone.now()
        
        # Find scheduled workflows that should start now
        scheduled_workflows = ScanWorkflow.objects.filter(
            status='scheduled',
            scheduled_time__lte=now
        )
        
        count = 0
        for workflow in scheduled_workflows:
            if self.start_workflow(workflow.id):
                count += 1
                
        return count
    
    def process_workflow_queue(self) -> int:
        """
        Process the workflow queue - check for tasks that can be started
        
        Returns:
            int: Number of tasks started
        """
        # Find in-progress workflows
        active_workflows = ScanWorkflow.objects.filter(
            status='in_progress'
        )
        
        tasks_started = 0
        
        for workflow in active_workflows:
            # Get pending tasks for this workflow
            pending_tasks = ScanTask.objects.filter(
                workflow=workflow,
                status='pending'
            )
            
            for task in pending_tasks:
                # Check if all dependencies are completed
                dependencies = task.dependencies.all()
                all_completed = all(dep.status == 'completed' for dep in dependencies)
                
                if all_completed:
                    self._execute_task(task)
                    tasks_started += 1
            
            # Check if workflow is complete
            if not ScanTask.objects.filter(workflow=workflow).exclude(status='completed').exists():
                self._complete_workflow(workflow)
                
        return tasks_started
    
    def _execute_task(self, task: ScanTask) -> None:
        """
        Execute a specific workflow task
        
        Args:
            task: The task to execute
        """
        try:
            # Update task status
            task.status = 'in_progress'
            task.start_time = timezone.now()
            task.save()
            
            self.logger.info(f"Executing task {task.id} ({task.task_type}) for workflow {task.workflow.id}")
            
            # Execute appropriate task type
            if task.task_type == 'subdomain_enumeration':
                result = self._run_subdomain_enumeration(task)
            elif task.task_type == 'port_scanning':
                result = self._run_port_scanning(task)
            elif task.task_type == 'service_identification':
                result = self._run_service_identification(task)
            elif task.task_type == 'vulnerability_scanning':
                result = self._run_vulnerability_scanning(task)
            elif task.task_type == 'network_mapping':
                result = self._run_network_mapping(task)
            elif task.task_type == 'report_generation':
                result = self._run_report_generation(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")
            
            # Update task status based on result
            if result.get('status') == 'success':
                task.status = 'completed'
                task.result = json.dumps(result)
            else:
                task.status = 'failed'
                task.result = json.dumps({'error': result.get('error', 'Unknown error')})
                
                # Create error notification
                if task.workflow.notification_email:
                    self.notification_manager.send_task_failure_notification(
                        task, result.get('error', 'Unknown error')
                    )
            
            task.end_time = timezone.now()
            task.save()
            
            # Check for critical failures that should stop the workflow
            if task.status == 'failed' and task.task_type in ['subdomain_enumeration', 'port_scanning']:
                self._fail_workflow(task.workflow, f"Critical task {task.task_type} failed")
                
        except Exception as e:
            self.logger.error(f"Error executing task {task.id}: {str(e)}")
            task.status = 'failed'
            task.result = json.dumps({'error': str(e)})
            task.end_time = timezone.now()
            task.save()
            
            # Create error notification
            if task.workflow.notification_email:
                self.notification_manager.send_task_failure_notification(task, str(e))
    
# File: automation/workflow_orchestrator.py
# Update the _run_subdomain_enumeration method to handle subdomain enumeration issues

    def _run_subdomain_enumeration(self, task: ScanTask) -> dict:
        """Run subdomain enumeration task with improved URL handling and reliability"""
        # Get the original target from the task
        original_target = task.workflow.target
        
        # Clean the target URL to get just the domain
        target_url = self.parse_target_url(original_target)
        
        # Remove 'www.' prefix if present for better subdomain enumeration
        if target_url.startswith('www.'):
            search_domain = target_url[4:]  # Remove www. prefix
            self.logger.info(f"Removing www prefix for enumeration, using: {search_domain}")
        else:
            search_domain = target_url
            
        try:
            self.logger.info(f"Starting subdomain enumeration for {search_domain} (original: {original_target})")
            results = self.subdomain_enumerator.enumerate_subdomains(search_domain)
            
            # If no results returned, add the main domain as a fallback
            if not results:
                self.logger.warning(f"No subdomains found for {search_domain}, adding main domain as fallback")
                try:
                    main_ip = socket.gethostbyname(search_domain)
                    results = [{
                        'subdomain': search_domain,
                        'ip_address': main_ip,
                        'is_http': True,
                        'http_status': None,
                        'status': 'active'
                    }]
                except Exception as e:
                    self.logger.error(f"Failed to resolve main domain as fallback: {str(e)}")
                    results = [{
                        'subdomain': search_domain,
                        'ip_address': None,
                        'is_http': None,
                        'http_status': None,
                        'status': 'unknown'
                    }]
            
            # Save results to database to ensure they're available for later steps
            saved_count = 0
            from reconnaissance.models import Subdomain  # Import the model explicitly
            
            for subdomain_data in results:
                # Skip entries without subdomain
                if not subdomain_data.get('subdomain'):
                    continue
                    
                try:
                    sub_obj, created = Subdomain.objects.update_or_create(
                        domain=search_domain,
                        subdomain=subdomain_data['subdomain'],
                        defaults={
                            'ip_address': subdomain_data.get('ip_address'),
                            'is_active': True
                        }
                    )
                    saved_count += 1
                except Exception as save_error:
                    self.logger.error(f"Error saving subdomain: {str(save_error)}")
            
            self.logger.info(f"Saved {saved_count} subdomains to database")
            
            return {
                'status': 'success',
                'target': original_target,  # Return original target for consistency
                'target_domain': search_domain,  # Use the domain without www for lookup
                'subdomains_found': len(results),
                'subdomains': results
            }
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {str(e)}")
            # Create a fallback result with just the main domain
            try:
                # Add the main domain as a subdomain in the database
                from reconnaissance.models import Subdomain  # Import the model explicitly
                
                sub_obj, created = Subdomain.objects.update_or_create(
                    domain=search_domain,
                    subdomain=search_domain,
                    defaults={
                        'ip_address': socket.gethostbyname(search_domain),
                        'is_active': True
                    }
                )
                
                return {
                    'status': 'success',  # Return success to continue workflow
                    'target': original_target,
                    'target_domain': search_domain,
                    'subdomains_found': 1, 
                    'subdomains': [{
                        'subdomain': search_domain,
                        'ip_address': sub_obj.ip_address,
                        'is_http': None,
                        'http_status': None,
                        'status': 'active'
                    }],
                    'warning': f"Error during subdomain scan: {str(e)}. Using main domain only."
                }
            except Exception as fallback_error:
                # Absolute last resort - return minimal data to allow workflow to continue
                return {
                    'status': 'success',  # Return success to continue workflow
                    'target': original_target,
                    'target_domain': search_domain,
                    'subdomains_found': 1,
                    'subdomains': [{
                        'subdomain': search_domain, 
                        'ip_address': None,
                        'is_http': None,
                        'http_status': None,
                        'status': 'unknown'
                    }],
                    'warning': f"Subdomain enumeration failed: {str(e)}. Using main domain as fallback."
                }
    
    def _run_port_scanning(self, task: ScanTask) -> dict:
        """Run port scanning task with improved URL handling and database storage"""
        # Get the original target from the task
        original_target = task.workflow.target
        scan_profile = task.workflow.scan_profile
        
        # Clean the target URL to get just the hostname
        target_url = self.parse_target_url(original_target)
        
        # Map scan profile to scan type
        scan_type = {
            'quick': 'quick',
            'standard': 'partial',
            'full': 'full'
        }.get(scan_profile, 'partial')
        
        self.logger.info(f"Starting port scan for {target_url} (original: {original_target}) with profile: {scan_profile}, type: {scan_type}")
        
        try:
            # Validate target before scanning
            import socket
            try:
                # Try to resolve hostname to ensure it's valid
                socket.gethostbyname(target_url)
            except socket.gaierror:
                self.logger.error(f"Unable to resolve target: {target_url}")
                return {
                    'status': 'error',
                    'error': f"Unable to resolve target: {target_url}. Please check the domain name."
                }
            
            # First run a quick check to see if common ports are open
            # This is more reliable than waiting for nmap
            common_ports = [80, 443, 8080, 8443, 22, 21]
            manual_check_ports = []
            
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((target_url, port))
                        if result == 0:
                            manual_check_ports.append(port)
                            self.logger.info(f"Manual port check found open port {port} on {target_url}")
                except Exception as e:
                    self.logger.debug(f"Socket error checking port {port}: {str(e)}")
            
            # Run the actual scan
            results = self.port_scanner.scan(target_url, scan_type)
            
            # Check for success
            if results.get('status') == 'success':
                # Check if the scan found any ports
                ports_found = False
                for host in results.get('results', []):
                    if host.get('ports') and len(host.get('ports', [])) > 0:
                        ports_found = True
                        break
                
                # If we have manual ports but no scan ports, add them to the results
                if not ports_found and manual_check_ports and 'manual_detected' not in results:
                    self.logger.info(f"Adding manually detected ports to scan results: {manual_check_ports}")
                    
                    # Create port data for each manual port
                    manual_ports = []
                    for port in manual_check_ports:
                        service_name = 'https' if port in [443, 8443] else 'http' if port in [80, 8080] else 'unknown'
                        manual_ports.append({
                            'port': port,
                            'state': 'open',
                            'service': service_name,
                            'reason': 'manual check'
                        })
                    
                    # Update the results with our manual ports
                    if len(results.get('results', [])) > 0:
                        results['results'][0]['ports'] = manual_ports
                    else:
                        results['results'] = [{
                            'host': target_url,
                            'state': 'up',
                            'ports': manual_ports
                        }]
                    
                    results['manual_added'] = True
                
                # Save scan results to the database
                from reconnaissance.models import PortScan
                
                # Track which ports we've saved to avoid duplicates
                saved_ports = set()
                saved_count = 0
                
                # Process and save all port results
                for host in results.get('results', []):
                    for port_data in host.get('ports', []):
                        port = port_data.get('port')
                        state = port_data.get('state')
                        service = port_data.get('service', '')
                        
                        # Skip if we already saved this port or if port is invalid
                        if not port or (target_url, port) in saved_ports:
                            continue
                        
                        try:
                            # Create or update port scan record
                            port_scan, created = PortScan.objects.update_or_create(
                                host=target_url,
                                port=port,
                                defaults={
                                    'service': service,
                                    'state': state,
                                    'protocol': 'tcp',
                                    'scan_status': 'completed',
                                    'scan_type': scan_type,
                                    'banner': port_data.get('extrainfo', ''),
                                    'notes': f"Version: {port_data.get('version', 'unknown')}"
                                }
                            )
                            
                            saved_ports.add((target_url, port))
                            saved_count += 1
                            
                            # Check if this port should be flagged as a vulnerability
                            if state == 'open' and service in ['ftp', 'telnet', 'rsh', 'rlogin']:
                                from vulnerability.models import Vulnerability
                                
                                # Create a vulnerability entry for high-risk open ports
                                Vulnerability.objects.get_or_create(
                                    target=target_url,
                                    name=f"Open {service.upper()} Port ({port})",
                                    defaults={
                                        'description': f"Port {port} is open and running {service}, which is potentially insecure.",
                                        'severity': 'HIGH',
                                        'vuln_type': 'open_port',
                                        'evidence': f"Port {port} is open and accessible.",
                                        'source': 'port_scan',
                                        'confidence': 'high',
                                        'cvss_score': 7.5,
                                        'is_fixed': False
                                    }
                                )
                            
                        except Exception as save_error:
                            self.logger.error(f"Error saving port scan result: {str(save_error)}")
                
                self.logger.info(f"Saved {saved_count} port scan results to database")
                
                # Add database save info to results
                results['database_saved'] = {
                    'saved_count': saved_count,
                    'target': target_url
                }
                
                return results
            else:
                error_msg = results.get('error', 'Port scanning failed without specific error')
                
                # If we have manually detected ports, return those instead
                if manual_check_ports:
                    self.logger.info(f"Using manually detected ports after scan error: {manual_check_ports}")
                    
                    # Create port data for each manual port
                    manual_ports = []
                    for port in manual_check_ports:
                        service_name = 'https' if port in [443, 8443] else 'http' if port in [80, 8080] else 'unknown'
                        manual_ports.append({
                            'port': port,
                            'state': 'open',
                            'service': service_name,
                            'reason': 'manual check'
                        })
                    
                    # Save manual results to database
                    from reconnaissance.models import PortScan
                    saved_count = 0
                    
                    for port_data in manual_ports:
                        try:
                            port_scan, created = PortScan.objects.update_or_create(
                                host=target_url,
                                port=port_data['port'],
                                defaults={
                                    'service': port_data['service'],
                                    'state': 'open',
                                    'protocol': 'tcp',
                                    'scan_status': 'completed',
                                    'scan_type': 'manual',
                                    'notes': 'Detected by manual scan'
                                }
                            )
                            saved_count += 1
                        except Exception as save_error:
                            self.logger.error(f"Error saving manual port result: {str(save_error)}")
                    
                    self.logger.info(f"Saved {saved_count} manual port results to database")
                    
                    return {
                        'status': 'success',
                        'scan_info': {
                            'scan_type': 'manual',
                            'command_line': 'Manual port check',
                        },
                        'results': [{
                            'host': target_url,
                            'state': 'up',
                            'ports': manual_ports
                        }],
                        'manual_only': True,
                        'database_saved': {
                            'saved_count': saved_count,
                            'target': target_url
                        }
                    }
                
                self.logger.error(f"Port scanning error: {error_msg}")
                return {
                    'status': 'error',
                    'error': error_msg
                }
        except Exception as e:
            self.logger.error(f"Port scanning failed: {str(e)}")
            return {
                'status': 'error',
                'error': f"Port scanning failed: {str(e)}"
            }
    
    def _run_service_identification(self, task: ScanTask) -> dict:
        """Run service identification task with improved URL handling and database storage"""
        # Get the original target from the task
        original_target = task.workflow.target
        scan_profile = task.workflow.scan_profile
        
        # Clean the target URL to get just the hostname
        target_url = self.parse_target_url(original_target)
        
        # Map scan profile to service ID scan type
        scan_type = {
            'quick': 'quick',
            'standard': 'standard',
            'full': 'standard'  # Use 'standard' for full profile for better reliability
        }.get(scan_profile, 'standard')
        
        # Set time limit based on profile
        time_limit = {
            'quick': 180,    # 3 minutes
            'standard': 300, # 5 minutes
            'full': 600      # 10 minutes 
        }.get(scan_profile, 300)
        
        self.logger.info(f"Starting service identification for {target_url} with type: {scan_type}, timeout: {time_limit}s")
        
        try:
            # First check if we have any port scan results to work with
            port_scan_task = ScanTask.objects.filter(
                workflow=task.workflow,
                task_type='port_scanning',
                status='completed'
            ).first()
            
            if not port_scan_task or not port_scan_task.result:
                self.logger.warning(f"No completed port scan found for service identification")
                
                # Do a quick manual check for common ports
                try:
                    common_ports = [80, 443, 8080, 8443, 22, 21]
                    found_ports = []
                    
                    for port in common_ports:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                                sock.settimeout(1)
                                result = sock.connect_ex((target_url, port))
                                if result == 0:
                                    found_ports.append(port)
                        except:
                            pass
                    
                    if found_ports:
                        self.logger.info(f"Manual check found {len(found_ports)} open ports for service identification")
                        # Create simple service details
                        services = []
                        for port in found_ports:
                            service_name = 'https' if port in [443, 8443] else 'http' if port in [80, 8080] else 'unknown'
                            category = 'web' if port in [80, 443, 8080, 8443] else 'other'
                            risk_level = 'LOW' if service_name == 'https' else 'MEDIUM'
                            
                            services.append({
                                'port': port,
                                'protocol': 'tcp',
                                'state': 'open',
                                'service': {
                                    'name': service_name,
                                    'product': '',
                                    'version': '',
                                    'extrainfo': 'Detected by manual scan',
                                },
                                'category': category,
                                'risk_level': risk_level
                            })
                        
                        # Save services to database
                        self._save_services_to_database(target_url, services)
                        
                        return {
                            'status': 'success',
                            'target': original_target,
                            'services': services,
                            'manual_detection': True,
                            'database_saved': True
                        }
                    else:
                        # Return empty results to continue workflow
                        return {
                            'status': 'success',
                            'target': original_target,
                            'services': [],
                            'warning': 'No port scan results available'
                        }
                except Exception as e:
                    self.logger.error(f"Manual port check failed: {str(e)}")
                    # Still return success with empty results to continue workflow
                    return {
                        'status': 'success',
                        'target': original_target,
                        'services': [],
                        'warning': 'No port scan results available'
                    }
            
            # Try to parse port scan results
            try:
                import json
                scan_results = json.loads(port_scan_task.result)
                
                # Check if manually detected ports exist
                if scan_results.get('manual_scan') or scan_results.get('manual_detected') or scan_results.get('manual_only') or scan_results.get('manual_added'):
                    self.logger.info("Using manually detected ports for service identification")
                    
                    services = []
                    for host in scan_results.get('results', []):
                        for port_data in host.get('ports', []):
                            port = port_data.get('port')
                            state = port_data.get('state')
                            service_name = port_data.get('service', 'unknown')
                            
                            if state == 'open':
                                category = 'web' if service_name in ['http', 'https'] else 'other'
                                risk_level = 'LOW' if service_name == 'https' else 'MEDIUM'
                                
                                services.append({
                                    'port': port,
                                    'protocol': 'tcp',
                                    'state': 'open',
                                    'service': {
                                        'name': service_name,
                                        'product': '',
                                        'version': '',
                                        'extrainfo': 'Detected by manual scan',
                                    },
                                    'category': category,
                                    'risk_level': risk_level
                                })
                    
                    # Save services to database
                    self._save_services_to_database(target_url, services)
                    
                    return {
                        'status': 'success',
                        'target': original_target,
                        'services': services,
                        'manual_identification': True,
                        'database_saved': True
                    }
                
                # Regular processing
                if not scan_results.get('results') or not any(host.get('ports') for host in scan_results.get('results', [])):
                    self.logger.warning(f"No open ports found in port scan results")
                    return {
                        'status': 'success',
                        'target': original_target,
                        'services': [],
                        'warning': 'No open ports found for service identification'
                    }
            except Exception as parse_error:
                self.logger.error(f"Error parsing port scan results: {str(parse_error)}")
            
            # Import needed for timeout handling
            import threading
            import time
            import queue
            
            # Create a queue to get results
            result_queue = queue.Queue()
            
            # Define a worker function
            def service_scan_worker():
                try:
                    scan_result = self.service_identifier.identify_services(target_url, scan_type)
                    result_queue.put(scan_result)
                except Exception as e:
                    self.logger.error(f"Service scan worker error: {str(e)}")
                    result_queue.put({
                        'status': 'error',
                        'error': str(e)
                    })
            
            # Start the worker thread
            worker_thread = threading.Thread(target=service_scan_worker)
            worker_thread.daemon = True
            worker_thread.start()
            
            # Wait for result with timeout
            start_time = time.time()
            try:
                result = result_queue.get(timeout=time_limit)
                self.logger.info(f"Service identification completed in {time.time() - start_time:.1f} seconds")
            except queue.Empty:
                self.logger.error(f"Service identification timed out after {time_limit} seconds")
                # Return success with limited info to continue workflow
                return {
                    'status': 'success',
                    'target': original_target,
                    'services': [],
                    'warning': f'Service identification timed out after {time_limit}s'
                }
            
            if result.get('status') == 'success':
                # If target in result doesn't match our original, update it
                if 'target' in result:
                    result['target'] = original_target
                
                # Save services to database
                services = result.get('services', [])
                if services:
                    self._save_services_to_database(target_url, services)
                    result['database_saved'] = True
                
                return result
            else:
                self.logger.error(f"Service identification failed: {result.get('error')}")
                # Even if the scan fails, return success with empty results to continue workflow
                return {
                    'status': 'success',
                    'target': original_target,
                    'services': [],
                    'warning': f"Service identification error: {result.get('error', 'Unknown error')}"
                }
        except Exception as e:
            self.logger.error(f"Service identification failed: {str(e)}")
            # Return success with empty results to continue workflow
            return {
                'status': 'success',
                'target': original_target,
                'services': [],
                'warning': f"Service identification error: {str(e)}"
            }

    def _save_services_to_database(self, target: str, services: List[Dict]) -> int:
        """Save service identification results to database
        
        Args:
            target: The target domain/IP
            services: List of service dictionaries
            
        Returns:
            int: Number of services saved
        """
        if not services:
            return 0
            
        from reconnaissance.models import Service
        from vulnerability.models import Vulnerability
        
        saved_count = 0
        
        # High risk services that should be flagged as vulnerabilities
        high_risk_services = {
            'ftp': 'File Transfer Protocol (FTP)',
            'telnet': 'Telnet Remote Access',
            'rsh': 'Remote Shell (RSH)',
            'rlogin': 'Remote Login (Rlogin)',
            'smb': 'Windows File Sharing (SMB)'
        }
        
        # Medium risk services
        medium_risk_services = {
            'smtp': 'Mail Server (SMTP)',
            'pop3': 'Mail Server (POP3)',
            'vnc': 'VNC Remote Desktop',
            'mysql': 'MySQL Database',
            'mssql': 'Microsoft SQL Server'
        }
        
        for service_data in services:
            try:
                port = service_data.get('port')
                if not port:
                    continue
                    
                # Extract service details
                protocol = service_data.get('protocol', 'tcp')
                state = service_data.get('state', 'open')
                service_info = service_data.get('service', {})
                
                if not service_info:
                    continue
                    
                service_name = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                extra_info = service_info.get('extrainfo', '')
                category = service_data.get('category', 'other')
                risk_level = service_data.get('risk_level', 'MEDIUM')
                
                # Create or update service record
                service_obj, created = Service.objects.update_or_create(
                    host=target,
                    port=port,
                    protocol=protocol,
                    defaults={
                        'name': service_name,
                        'product': product,
                        'version': version,
                        'extra_info': extra_info,
                        'category': category,
                        'risk_level': risk_level,
                        'is_active': True
                    }
                )
                
                saved_count += 1
                
                # Check if this service should be flagged as a vulnerability
                if state == 'open':
                    # For high risk services
                    if service_name.lower() in high_risk_services:
                        service_title = high_risk_services[service_name.lower()]
                        
                        # Create vulnerability entry
                        Vulnerability.objects.get_or_create(
                            target=target,
                            name=f"{service_title} on port {port}",
                            defaults={
                                'description': f"Port {port} is running {service_name}, which is potentially insecure. {product} {version}".strip(),
                                'severity': 'HIGH',
                                'vuln_type': 'insecure_service',
                                'evidence': f"Service detected on port {port}. {extra_info}".strip(),
                                'source': 'service_identification',
                                'confidence': 'high',
                                'cvss_score': 7.5,
                                'is_fixed': False
                            }
                        )
                    
                    # For medium risk services
                    elif service_name.lower() in medium_risk_services:
                        service_title = medium_risk_services[service_name.lower()]
                        
                        # Create vulnerability entry
                        Vulnerability.objects.get_or_create(
                            target=target,
                            name=f"{service_title} on port {port}",
                            defaults={
                                'description': f"Port {port} is running {service_name}, which might pose security risks if not properly configured. {product} {version}".strip(),
                                'severity': 'MEDIUM',
                                'vuln_type': 'potentially_risky_service',
                                'evidence': f"Service detected on port {port}. {extra_info}".strip(),
                                'source': 'service_identification',
                                'confidence': 'medium',
                                'cvss_score': 5.0,
                                'is_fixed': False
                            }
                        )
                        
                    # Flag uncommon open ports    
                    elif port not in [80, 443, 8080, 8443, 22] and port < 1024:
                        # Create vulnerability entry for uncommon open ports
                        Vulnerability.objects.get_or_create(
                            target=target,
                            name=f"Uncommon service on port {port} ({service_name})",
                            defaults={
                                'description': f"Port {port} is open and running {service_name}, which is uncommon and might indicate unnecessary services.",
                                'severity': 'LOW',
                                'vuln_type': 'uncommon_port',
                                'evidence': f"Service {service_name} detected on port {port}.",
                                'source': 'service_identification',
                                'confidence': 'medium',
                                'cvss_score': 3.0,
                                'is_fixed': False
                            }
                        )
                    
            except Exception as e:
                self.logger.error(f"Error saving service to database: {str(e)}")
        
        return saved_count
    
    def _run_vulnerability_scanning(self, task: ScanTask) -> dict:
        """Run vulnerability scanning task with improved URL handling"""
        # Get the original target from the task
        original_target = task.workflow.target
        scan_profile = task.workflow.scan_profile
        
        # Clean the target URL to get just the hostname
        target_url = self.parse_target_url(original_target)
        
        # Determine scanners to use based on scan profile
        include_zap = scan_profile in ['standard', 'full']
        include_nuclei = True  # Always use Nuclei
        nuclei_scan_type = 'advanced' if scan_profile == 'full' else 'basic'
        
        try:
            self.logger.info(f"Starting vulnerability scan for {target_url} (original: {original_target})")
            
            results = self.vulnerability_scanner.scan_target(
                target=target_url,
                scan_type=scan_profile,
                include_zap=include_zap,
                include_nuclei=include_nuclei,
                nuclei_scan_type=nuclei_scan_type,
                use_advanced_correlation=True
            )
            
            if results.get('status') == 'success':
                # Check for critical vulnerabilities
                high_vulns = 0
                critical_vulns = 0
                
                for vuln in results.get('vulnerabilities', []):
                    if vuln.get('severity') == 'CRITICAL':
                        critical_vulns += 1
                    elif vuln.get('severity') == 'HIGH':
                        high_vulns += 1
                
                # Add notification for critical vulnerabilities
                if (critical_vulns > 0 or high_vulns > 2) and task.workflow.notification_email:
                    self.notification_manager.send_critical_vulnerability_notification(
                        task.workflow, critical_vulns, high_vulns
                    )
                
                return results
            else:
                return {
                    'status': 'error',
                    'error': results.get('error', 'Vulnerability scanning failed without specific error')
                }
        except Exception as e:
            self.logger.error(f"Vulnerability scanning failed: {str(e)}")
            return {
                'status': 'error', 
                'error': f"Vulnerability scanning failed: {str(e)}"
            }
    
    def _run_network_mapping(self, task: ScanTask) -> dict:
        """Run network mapping task with improved visualization data"""
        # Get the original target from the task
        original_target = task.workflow.target
        
        # Clean the target URL to get just the hostname
        target_url = self.parse_target_url(original_target)
        
        try:
            self.logger.info(f"Starting network mapping for {target_url} (original: {original_target})")
            
            # Get services from previous tasks to include in the network map
            services_data = []
            try:
                service_task = ScanTask.objects.filter(
                    workflow=task.workflow,
                    task_type='service_identification',
                    status='completed'
                ).first()
                
                if service_task and service_task.result:
                    service_result = json.loads(service_task.result)
                    services_data = service_result.get('services', [])
            except Exception as e:
                self.logger.warning(f"Error fetching service data for network mapping: {str(e)}")
            
            # Get subdomains from previous tasks
            subdomains_data = []
            try:
                subdomain_task = ScanTask.objects.filter(
                    workflow=task.workflow,
                    task_type='subdomain_enumeration',
                    status='completed'
                ).first()
                
                if subdomain_task and subdomain_task.result:
                    subdomain_result = json.loads(subdomain_task.result)
                    subdomains_data = subdomain_result.get('subdomains', [])
            except Exception as e:
                self.logger.warning(f"Error fetching subdomain data for network mapping: {str(e)}")
            
            # Create network map
            results = self.topology_mapper.create_network_map(
                target_url, 
                services=services_data,
                subdomains=subdomains_data
            )
            
            # Get the number of nodes and connections for proper report display
            nodes_count = 0
            connections_count = 0
            
            if results.get('status') == 'success':
                # Try to get network node counts from the database
                from network_visualization.models import NetworkNode, NetworkConnection
                
                try:
                    nodes_count = NetworkNode.objects.filter(domain=target_url, is_active=True).count()
                    connections_count = NetworkConnection.objects.filter(
                        source__domain=target_url,
                        is_active=True
                    ).count()
                    
                    self.logger.info(f"Network map created with {nodes_count} nodes and {connections_count} connections")
                except Exception as db_error:
                    self.logger.error(f"Error counting network nodes from database: {str(db_error)}")
                
                # Add the node and connection counts to the result
                results['nodes'] = nodes_count
                results['connections'] = connections_count
                
                return results
            else:
                return {
                    'status': 'error',
                    'error': results.get('error', 'Network mapping failed without specific error'),
                    'nodes': 0,
                    'connections': 0
                }
        except Exception as e:
            self.logger.error(f"Network mapping failed: {str(e)}")
            return {
                'status': 'error',
                'error': f"Network mapping failed: {str(e)}",
                'nodes': 0,
                'connections': 0
            }
    
# File: automation/workflow_orchestrator.py
    def _run_report_generation(self, task: ScanTask) -> dict:
        """Run report generation task with improved URL handling"""
        # Get the original target from the task
        original_target = task.workflow.target
        
        # Clean the target URL for DB lookups if needed
        target_url = self.parse_target_url(original_target)
        
        scan_profile = task.workflow.scan_profile
        
        # Map scan profile to report type
        report_type = {
            'quick': 'basic',
            'standard': 'detailed',
            'full': 'executive'
        }.get(scan_profile, 'detailed')
        
        try:
            # Get vulnerability scanning task result
            vuln_scan_task = ScanTask.objects.filter(
                workflow=task.workflow,
                task_type='vulnerability_scanning',
                status='completed'
            ).first()
            
            # Parse scan results if available
            scan_results = None
            if vuln_scan_task and vuln_scan_task.result:
                try:
                    scan_results = json.loads(vuln_scan_task.result)
                except:
                    logger.error("Failed to parse vulnerability scan results")
            
            # Add workflow ID to the scan results
            if scan_results is None:
                scan_results = {}
            scan_results['workflow_id'] = task.workflow.id
            
            # Use original target for report generation
            logger.info(f"Generating {report_type} report for {original_target}")
            report_html = self.report_generator.generate_report(report_type, original_target, 'html', scan_results)
            
            # Only send a single notification email
            if task.workflow.notification_email:
                self.notification_manager.send_workflow_completion_notification(
                    task.workflow, 
                    report_id=report_html.id
                )
            
            return {
                'status': 'success',
                'target': original_target,
                'workflow_id': task.workflow.id,  # Include workflow ID in the result
                'report_types': [report_type],
                'report_formats': ['html'],
                'report_ids': {
                    'html': report_html.id
                }
            }
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return {
                'status': 'error',
                'error': f"Report generation failed: {str(e)}"
            }
    
    def _fail_workflow(self, workflow: ScanWorkflow, reason: str) -> None:
        """Mark workflow as failed and send notifications"""
        workflow.status = 'failed'
        workflow.end_time = timezone.now()
        workflow.save()
        
        logger.error(f"Workflow {workflow.id} for {workflow.target} failed: {reason}")
        
        # Update pending tasks to skipped
        ScanTask.objects.filter(workflow=workflow, status='pending').update(
            status='skipped',
            result=json.dumps({'skipped_reason': reason})
        )
        
        # Send failure notification
        if workflow.notification_email:
            self.notification_manager.send_workflow_failure_notification(workflow, reason)
    
    def cancel_workflow(self, workflow_id: int) -> bool:
        """
        Cancel a running or scheduled workflow
        
        Args:
            workflow_id: ID of the workflow to cancel
            
        Returns:
            bool: True if successfully canceled
        """
        try:
            workflow = ScanWorkflow.objects.get(id=workflow_id)
            
            if workflow.status in ['completed', 'failed', 'canceled']:
                logger.warning(f"Workflow {workflow_id} already in terminal state: {workflow.status}")
                return False
            
            # Update workflow status
            original_status = workflow.status
            workflow.status = 'canceled'
            workflow.end_time = timezone.now()
            workflow.save()
            
            # Update in-progress tasks to canceled
            ScanTask.objects.filter(workflow=workflow, status='in_progress').update(
                status='canceled',
                end_time=timezone.now(),
                result=json.dumps({'canceled_reason': 'Workflow canceled by user'})
            )
            
            # Update pending tasks to skipped
            ScanTask.objects.filter(workflow=workflow, status='pending').update(
                status='skipped',
                result=json.dumps({'skipped_reason': 'Workflow canceled by user'})
            )
            
            logger.info(f"Workflow {workflow_id} canceled (was {original_status})")
            
            # Send cancellation notification
            if workflow.notification_email:
                self.notification_manager.send_workflow_cancellation_notification(workflow)
                
            return True
            
        except ScanWorkflow.DoesNotExist:
            logger.error(f"Workflow {workflow_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error canceling workflow {workflow_id}: {str(e)}")
            return False
    
    def get_workflow_status(self, workflow_id: int) -> dict:
        """
        Get detailed status of a workflow
        
        Args:
            workflow_id: ID of the workflow
            
        Returns:
            dict: Workflow status details
        """
        try:
            workflow = ScanWorkflow.objects.get(id=workflow_id)
            tasks = ScanTask.objects.filter(workflow=workflow).order_by('order')
            
            # Calculate progress percentage
            total_tasks = tasks.count()
            completed_tasks = tasks.filter(status__in=['completed', 'skipped', 'canceled']).count()
            progress = int(completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
            
            # Format task results
            task_results = []
            for task in tasks:
                result_data = {}
                if task.result:
                    try:
                        result_data = json.loads(task.result)
                    except:
                        result_data = {'error': 'Invalid JSON result'}
                
                task_results.append({
                    'id': task.id,
                    'name': task.name,
                    'type': task.task_type,
                    'status': task.status,
                    'start_time': task.start_time.isoformat() if task.start_time else None,
                    'end_time': task.end_time.isoformat() if task.end_time else None,
                    'duration': str(task.end_time - task.start_time) if task.start_time and task.end_time else None,
                    'result_summary': self._summarize_task_result(task.task_type, result_data)
                })
            
            return {
                'id': workflow.id,
                'name': workflow.name,
                'target': workflow.target,
                'status': workflow.status,
                'scan_profile': workflow.scan_profile,
                'scheduled_time': workflow.scheduled_time.isoformat() if workflow.scheduled_time else None,
                'start_time': workflow.start_time.isoformat() if workflow.start_time else None,
                'end_time': workflow.end_time.isoformat() if workflow.end_time else None,
                'duration': str(workflow.end_time - workflow.start_time) if workflow.start_time and workflow.end_time else None,
                'progress': progress,
                'tasks': task_results,
                'notification_email': workflow.notification_email
            }
            
        except ScanWorkflow.DoesNotExist:
            logger.error(f"Workflow {workflow_id} not found")
            return {'error': 'Workflow not found'}
        except Exception as e:
            logger.error(f"Error getting workflow status: {str(e)}")
            return {'error': str(e)}
    
    def _summarize_task_result(self, task_type: str, result: dict) -> dict:
        """Generate a summary of task results for display"""
        summary = {}
        
        if task_type == 'subdomain_enumeration':
            summary['subdomains_found'] = result.get('subdomains_found', 0)
        elif task_type == 'port_scanning':
            hosts = result.get('results', [])
            open_ports = 0
            for host in hosts:
                open_ports += len([p for p in host.get('ports', []) if p.get('state') == 'open'])
            summary['hosts_scanned'] = len(hosts)
            summary['open_ports'] = open_ports
        elif task_type == 'service_identification':
            summary['services_found'] = len(result.get('services', []))
        elif task_type == 'vulnerability_scanning':
            vulns = result.get('vulnerabilities', [])
            severity_counts = {
                'critical': len([v for v in vulns if v.get('severity') == 'CRITICAL']),
                'high': len([v for v in vulns if v.get('severity') == 'HIGH']),
                'medium': len([v for v in vulns if v.get('severity') == 'MEDIUM']),
                'low': len([v for v in vulns if v.get('severity') == 'LOW'])
            }
            summary['vulnerabilities_found'] = len(vulns)
            summary['severity_counts'] = severity_counts
        elif task_type == 'network_mapping':
            summary['nodes'] = result.get('nodes', 0)
            summary['connections'] = result.get('connections', 0)
        elif task_type == 'report_generation':
            summary['report_types'] = result.get('report_types', [])
            summary['report_formats'] = result.get('report_formats', [])
            summary['report_ids'] = result.get('report_ids', {})
            
        return summary