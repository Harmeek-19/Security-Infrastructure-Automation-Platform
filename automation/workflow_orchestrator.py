# automation/workflow_orchestrator.py

import logging
import json
import socket
import time
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from django.conf import settings

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
        self.subdomain_enumerator = SubdomainEnumerator()
        self.port_scanner = PortScanner()
        self.service_identifier = ServiceIdentifier()
        self.vulnerability_scanner = UnifiedVulnerabilityScanner()
        self.topology_mapper = TopologyMapper()
        self.report_generator = ReportGenerator()
        self.notification_manager = NotificationManager()
    
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
        
        logger.info(f"Workflow {workflow.id} for {workflow.target} completed successfully")
        
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
                    logger.info(f"Workflow {workflow_id} is scheduled for {workflow.scheduled_time}, not starting yet")
                    return False
            
            # Update workflow status
            workflow.status = 'in_progress'
            workflow.start_time = timezone.now()
            workflow.save()
            
            logger.info(f"Starting workflow {workflow_id} for target {workflow.target}")
            
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
            logger.error(f"Workflow {workflow_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error starting workflow {workflow_id}: {str(e)}")
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
            
            logger.info(f"Executing task {task.id} ({task.task_type}) for workflow {task.workflow.id}")
            
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
            logger.error(f"Error executing task {task.id}: {str(e)}")
            task.status = 'failed'
            task.result = json.dumps({'error': str(e)})
            task.end_time = timezone.now()
            task.save()
            
            # Create error notification
            if task.workflow.notification_email:
                self.notification_manager.send_task_failure_notification(task, str(e))
    
    def _run_subdomain_enumeration(self, task: ScanTask) -> dict:
        """Run subdomain enumeration task"""
        target = task.workflow.target
        try:
            results = self.subdomain_enumerator.enumerate_subdomains(target)
            return {
                'status': 'success',
                'target': target,
                'subdomains_found': len(results),
                'subdomains': results
            }
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {str(e)}")
            return {
                'status': 'error',
                'error': f"Subdomain enumeration failed: {str(e)}"
            }
    
    def _run_port_scanning(self, task: ScanTask) -> dict:
        """Run port scanning task with improved manual detection"""
        target = task.workflow.target
        scan_profile = task.workflow.scan_profile
        
        # Map scan profile to scan type
        scan_type = {
            'quick': 'quick',
            'standard': 'partial',
            'full': 'full'  # Use 'full' to get the correct scan type
        }.get(scan_profile, 'partial')
        
        logger.info(f"Starting port scan for {target} with profile: {scan_profile}, type: {scan_type}")
        
        try:
            # Validate target before scanning
            import socket
            try:
                # Try to resolve hostname to ensure it's valid
                socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Unable to resolve target: {target}")
                return {
                    'status': 'error',
                    'error': f"Unable to resolve target: {target}. Please check the domain name."
                }
            
            # First run a quick check to see if common ports are open
            # since this is more reliable than waiting for nmap
            common_ports = [80, 443, 8080, 8443, 22, 21]
            manual_check_ports = []
            
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            manual_check_ports.append(port)
                            logger.info(f"Manual port check found open port {port} on {target}")
                except Exception as e:
                    logger.debug(f"Socket error checking port {port}: {str(e)}")
            
            # Run the actual scan
            results = self.port_scanner.scan(target, scan_type)
            
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
                    logger.info(f"Adding manually detected ports to scan results: {manual_check_ports}")
                    
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
                            'host': target,
                            'state': 'up',
                            'ports': manual_ports
                        }]
                    
                    results['manual_added'] = True
                
                return results
            else:
                error_msg = results.get('error', 'Port scanning failed without specific error')
                
                # If we have manually detected ports, return those instead
                if manual_check_ports:
                    logger.info(f"Using manually detected ports after scan error: {manual_check_ports}")
                    
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
                    
                    return {
                        'status': 'success',
                        'scan_info': {
                            'scan_type': 'manual',
                            'command_line': 'Manual port check',
                        },
                        'results': [{
                            'host': target,
                            'state': 'up',
                            'ports': manual_ports
                        }],
                        'manual_only': True
                    }
                
                logger.error(f"Port scanning error: {error_msg}")
                return {
                    'status': 'error',
                    'error': error_msg
                }
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            return {
                'status': 'error',
                'error': f"Port scanning failed: {str(e)}"
            }
    
# Update in automation/workflow_orchestrator.py
    def _run_service_identification(self, task: ScanTask) -> dict:
        """Run service identification task with improved timeout handling"""
        target = task.workflow.target
        scan_profile = task.workflow.scan_profile
        
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
        
        logger.info(f"Starting service identification for {target} with type: {scan_type}, timeout: {time_limit}s")
        
        try:
            # First check if we have any port scan results to work with
            port_scan_task = ScanTask.objects.filter(
                workflow=task.workflow,
                task_type='port_scanning',
                status='completed'
            ).first()
            
            if not port_scan_task or not port_scan_task.result:
                logger.warning(f"No completed port scan found for service identification")
                
                # Do a quick manual check for common ports
                try:
                    common_ports = [80, 443, 8080, 8443, 22, 21]
                    found_ports = []
                    
                    for port in common_ports:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                                sock.settimeout(1)
                                result = sock.connect_ex((target, port))
                                if result == 0:
                                    found_ports.append(port)
                        except:
                            pass
                    
                    if found_ports:
                        logger.info(f"Manual check found {len(found_ports)} open ports for service identification")
                        # Create simple service details
                        services = []
                        for port in found_ports:
                            service_name = 'https' if port in [443, 8443] else 'http' if port in [80, 8080] else 'unknown'
                            category = 'web' if port in [80, 443, 8080, 8443] else 'other'
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
                                'risk_level': 'MEDIUM'
                            })
                        
                        return {
                            'status': 'success',
                            'target': target,
                            'services': services,
                            'manual_detection': True
                        }
                    else:
                        # Return empty results to continue workflow
                        return {
                            'status': 'success',
                            'target': target,
                            'services': [],
                            'warning': 'No port scan results available'
                        }
                except Exception as e:
                    logger.error(f"Manual port check failed: {str(e)}")
                    # Still return success with empty results to continue workflow
                    return {
                        'status': 'success',
                        'target': target,
                        'services': [],
                        'warning': 'No port scan results available'
                    }
            
            # Try to parse port scan results
            try:
                import json
                scan_results = json.loads(port_scan_task.result)
                
                # Check if manually detected ports exist
                if scan_results.get('manual_scan') or scan_results.get('manual_detected'):
                    logger.info("Using manually detected ports for service identification")
                    
                    services = []
                    for host in scan_results.get('results', []):
                        for port_data in host.get('ports', []):
                            port = port_data.get('port')
                            state = port_data.get('state')
                            service_name = port_data.get('service', 'unknown')
                            
                            if state == 'open':
                                category = 'web' if service_name in ['http', 'https'] else 'other'
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
                                    'risk_level': 'MEDIUM'
                                })
                    
                    return {
                        'status': 'success',
                        'target': target,
                        'services': services,
                        'manual_identification': True
                    }
                
                # Regular processing
                if not scan_results.get('results') or not any(host.get('ports') for host in scan_results.get('results', [])):
                    logger.warning(f"No open ports found in port scan results")
                    return {
                        'status': 'success',
                        'target': target,
                        'services': [],
                        'warning': 'No open ports found for service identification'
                    }
            except Exception as parse_error:
                logger.error(f"Error parsing port scan results: {str(parse_error)}")
            
            # Import needed for timeout handling
            import threading
            import time
            import queue
            
            # Create a queue to get results
            result_queue = queue.Queue()
            
            # Define a worker function
            def service_scan_worker():
                try:
                    scan_result = self.service_identifier.identify_services(target, scan_type)
                    result_queue.put(scan_result)
                except Exception as e:
                    logger.error(f"Service scan worker error: {str(e)}")
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
                logger.info(f"Service identification completed in {time.time() - start_time:.1f} seconds")
            except queue.Empty:
                logger.error(f"Service identification timed out after {time_limit} seconds")
                # Return success with limited info to continue workflow
                return {
                    'status': 'success',
                    'target': target,
                    'services': [],
                    'warning': f'Service identification timed out after {time_limit}s'
                }
            
            if result.get('status') == 'success':
                return result
            else:
                logger.error(f"Service identification failed: {result.get('error')}")
                # Even if the scan fails, return success with empty results to continue workflow
                return {
                    'status': 'success',
                    'target': target,
                    'services': [],
                    'warning': f"Service identification error: {result.get('error', 'Unknown error')}"
                }
                
        except Exception as e:
            logger.error(f"Service identification failed: {str(e)}")
            # Return success with empty results to continue workflow
            return {
                'status': 'success',
                'target': target,
                'services': [],
                'warning': f"Service identification error: {str(e)}"
            }
            
            # Define a worker function
            def service_scan_worker():
                try:
                    scan_result = self.service_identifier.identify_services(target, scan_type)
                    result_queue.put(scan_result)
                except Exception as e:
                    logger.error(f"Service scan worker error: {str(e)}")
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
                logger.info(f"Service identification completed in {time.time() - start_time:.1f} seconds")
            except queue.Empty:
                logger.error(f"Service identification timed out after {time_limit} seconds")
                # Return success with limited info to continue workflow
                return {
                    'status': 'success',
                    'target': target,
                    'services': [],
                    'warning': f'Service identification timed out after {time_limit}s'
                }
            
            if result.get('status') == 'success':
                return result
            else:
                logger.error(f"Service identification failed: {result.get('error')}")
                # Even if the scan fails, return success with empty results to continue workflow
                return {
                    'status': 'success',
                    'target': target,
                    'services': [],
                    'warning': f"Service identification error: {result.get('error', 'Unknown error')}"
                }
                
        except Exception as e:
            logger.error(f"Service identification failed: {str(e)}")
            # Return success with empty results to continue workflow
            return {
                'status': 'success',
                'target': target,
                'services': [],
                'warning': f"Service identification error: {str(e)}"
            }
    
    def _run_vulnerability_scanning(self, task: ScanTask) -> dict:
        """Run vulnerability scanning task"""
        target = task.workflow.target
        scan_profile = task.workflow.scan_profile
        
        # Determine scanners to use based on scan profile
        include_zap = scan_profile in ['standard', 'full']
        include_nuclei = True  # Always use Nuclei
        nuclei_scan_type = 'advanced' if scan_profile == 'full' else 'basic'
        
        try:
            results = self.vulnerability_scanner.scan_target(
                target=target,
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
            logger.error(f"Vulnerability scanning failed: {str(e)}")
            return {
                'status': 'error', 
                'error': f"Vulnerability scanning failed: {str(e)}"
            }
    
    def _run_network_mapping(self, task: ScanTask) -> dict:
        """Run network mapping task"""
        target = task.workflow.target
        
        try:
            results = self.topology_mapper.create_network_map(target)
            if results.get('status') == 'success':
                return results
            else:
                return {
                    'status': 'error',
                    'error': results.get('error', 'Network mapping failed without specific error')
                }
        except Exception as e:
            logger.error(f"Network mapping failed: {str(e)}")
            return {
                'status': 'error',
                'error': f"Network mapping failed: {str(e)}"
            }
    
    def _run_report_generation(self, task: ScanTask) -> dict:
        """Run report generation task"""
        target = task.workflow.target
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
            
            # Generate HTML report
            report_html = self.report_generator.generate_report(report_type, target, 'html', scan_results)
            
            # Only send a single notification email
            if task.workflow.notification_email:
                self.notification_manager.send_workflow_completion_notification(
                    task.workflow, 
                    report_id=report_html.id
                )
            
            return {
                'status': 'success',
                'target': target,
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
    
    