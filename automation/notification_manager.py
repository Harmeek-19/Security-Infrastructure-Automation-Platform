# automation/notification_manager.py

import logging
import json
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.template.loader import render_to_string

from .models import Notification, ScanWorkflow, ScanTask

logger = logging.getLogger(__name__)

class NotificationManager:
    """
    Manages notifications for scan workflows, including:
    - Email notifications
    - System notifications
    - Alerts for critical findings
    """
    
    def __init__(self):
        self.app_base_url = getattr(settings, 'APP_BASE_URL', 'http://localhost:8000')
    
    def send_workflow_completion_notification(self, workflow: ScanWorkflow, report_id: int = None) -> None:
        """
        Send notification when a workflow is completed
        
        Args:
            workflow: The completed workflow
            report_id: ID of the generated report
        """
        try:
            if not workflow.notification_email:
                return
                
            # Create notification record
            notification = Notification.objects.create(
                workflow=workflow,
                notification_type='workflow_completed',
                recipient=workflow.notification_email,
                subject=f"Scan completed: {workflow.name}",
                message=f"The security scan for {workflow.target} has been completed."
            )
            
            # Get tasks for this workflow
            tasks = workflow.tasks.all().order_by('order')
            
            # Get vulnerability counts
            from vulnerability.models import Vulnerability
            vulns = Vulnerability.objects.filter(target=workflow.target, is_fixed=False)
            summary = {
                'critical': vulns.filter(severity='CRITICAL').count(),
                'high': vulns.filter(severity='HIGH').count(),
                'medium': vulns.filter(severity='MEDIUM').count(),
                'low': vulns.filter(severity='LOW').count(),
                'total': vulns.count()
            }
            
            # Send email
            self._send_email_notification(notification, {
                'workflow': workflow,
                'tasks': tasks,
                'summary': summary,
                'app_url': self.app_base_url,
                'comprehensive_report_url': f"{self.app_base_url}/reporting/comprehensive/{report_id}/?workflow_id={workflow.id}" if report_id else None,
                'pdf_url': f"{self.app_base_url}/reporting/download/{report_id}/pdf/" if report_id else None
            })
            
            logger.info(f"Sent workflow completion notification for workflow {workflow.id}")
            
        except Exception as e:
            logger.error(f"Error sending workflow completion notification: {str(e)}")
    
    def send_workflow_failure_notification(self, workflow: ScanWorkflow, reason: str) -> None:
        """
        Send notification when a workflow fails
        
        Args:
            workflow: The failed workflow
            reason: Reason for failure
        """
        try:
            if not workflow.notification_email:
                return
                
            # Create notification record
            notification = Notification.objects.create(
                workflow=workflow,
                notification_type='workflow_failed',
                recipient=workflow.notification_email,
                subject=f"Scan failed: {workflow.name}",
                message=f"The security scan for {workflow.target} has failed: {reason}"
            )
            
            # Send email
            self._send_email_notification(notification, {
                'workflow': workflow,
                'failure_reason': reason,  # Changed from reason to failure_reason to match template
                'app_url': self.app_base_url,
                'workflow_url': f"{self.app_base_url}/automation/api/workflows/{workflow.id}/status/",  # Updated URL
                'dashboard_url': f"{self.app_base_url}/automation/dashboard/"
            })
            
            logger.info(f"Sent workflow failure notification for workflow {workflow.id}")
            
        except Exception as e:
            logger.error(f"Error sending workflow failure notification: {str(e)}")
    
    def send_workflow_cancellation_notification(self, workflow: ScanWorkflow) -> None:
        """
        Send notification when a workflow is canceled
        
        Args:
            workflow: The canceled workflow
        """
        try:
            if not workflow.notification_email:
                return
                
            # Create notification record
            notification = Notification.objects.create(
                workflow=workflow,
                notification_type='workflow_canceled',
                recipient=workflow.notification_email,
                subject=f"Scan canceled: {workflow.name}",
                message=f"The security scan for {workflow.target} has been canceled."
            )
            
            # Send email
            self._send_email_notification(notification, {
                'workflow': workflow,
                'app_url': self.app_base_url,
                'workflow_url': f"{self.app_base_url}/automation/workflow/{workflow.id}/",
                'dashboard_url': f"{self.app_base_url}/automation/dashboard/"
            })
            
            logger.info(f"Sent workflow cancellation notification for workflow {workflow.id}")
            
        except Exception as e:
            logger.error(f"Error sending workflow cancellation notification: {str(e)}")
    
    def send_task_failure_notification(self, task: ScanTask, error: str) -> None:
        """
        Send notification when a task fails
        
        Args:
            task: The failed task
            error: Error message
        """
        try:
            workflow = task.workflow
            if not workflow.notification_email:
                return
                
            # Create notification record
            notification = Notification.objects.create(
                workflow=workflow,
                notification_type='task_failed',
                recipient=workflow.notification_email,
                subject=f"Task failed in scan: {workflow.name}",
                message=f"The task '{task.name}' has failed: {error}"
            )
            
            # Send email
            self._send_email_notification(notification, {
                'workflow': workflow,
                'task': task,
                'error_message': error,  # Changed to match template variable name
                'app_url': self.app_base_url,
                'workflow_url': f"{self.app_base_url}/automation/api/workflows/{workflow.id}/status/",  # Updated URL
                'dashboard_url': f"{self.app_base_url}/automation/dashboard/"
            })
            
            logger.info(f"Sent task failure notification for task {task.id}")
            
        except Exception as e:
            logger.error(f"Error sending task failure notification: {str(e)}")
    
    def send_critical_vulnerability_notification(self, workflow: ScanWorkflow, critical_count: int, high_count: int) -> None:
        """
        Send notification when critical vulnerabilities are found
        
        Args:
            workflow: The workflow with critical findings
            critical_count: Number of critical vulnerabilities
            high_count: Number of high vulnerabilities
        """
        try:
            if not workflow.notification_email:
                return
                
            # Create notification record
            subject = f"CRITICAL: Security vulnerabilities found in {workflow.target}"
            message = (
                f"The security scan for {workflow.target} has discovered {critical_count} critical "
                f"and {high_count} high severity vulnerabilities that require immediate attention."
            )
            
            notification = Notification.objects.create(
                workflow=workflow,
                notification_type='critical_vulnerabilities',
                recipient=workflow.notification_email,
                subject=subject,
                message=message
            )
            
            # Send email
            self._send_email_notification(notification, {
                'workflow': workflow,
                'critical_count': critical_count,
                'high_count': high_count,
                'app_url': self.app_base_url,
                'workflow_url': f"{self.app_base_url}/automation/workflow/{workflow.id}/",
                'dashboard_url': f"{self.app_base_url}/automation/dashboard/"
            })
            
            logger.info(f"Sent critical vulnerability notification for workflow {workflow.id}")
            
        except Exception as e:
            logger.error(f"Error sending critical vulnerability notification: {str(e)}")
    
    def send_report_ready_notification(self, workflow: ScanWorkflow, html_report_id: int, pdf_report_id: int) -> None:
        """
        Send notification when reports are ready
        
        Args:
            workflow: The workflow with generated reports
            html_report_id: ID of the HTML report
            pdf_report_id: ID of the PDF report
        """
        try:
            if not workflow.notification_email:
                return
                
            # Create notification record
            notification = Notification.objects.create(
                workflow=workflow,
                notification_type='report_ready',
                recipient=workflow.notification_email,
                subject=f"Security reports ready: {workflow.name}",
                message=f"Security reports for {workflow.target} are now available for viewing and download."
            )
            
            # Send email
            self._send_email_notification(notification, {
                'workflow': workflow,
                'app_url': self.app_base_url,
                'workflow_url': f"{self.app_base_url}/automation/api/workflows/{workflow.id}/",
                'html_report_url': f"{self.app_base_url}/reporting/view/{html_report_id}/",
                'pdf_report_url': f"{self.app_base_url}/reporting/download/{pdf_report_id}/",
                'report_ids': {
                    'html': html_report_id,
                    'pdf': pdf_report_id
                },
                'dashboard_url': f"{self.app_base_url}/automation/dashboard/"
            })
            
            logger.info(f"Sent report ready notification for workflow {workflow.id}")
            
        except Exception as e:
            logger.error(f"Error sending report ready notification: {str(e)}")
    
    def _send_email_notification(self, notification: Notification, context: dict) -> bool:
        """
        Send an email notification
        
        Args:
            notification: The notification to send
            context: Template context data
            
        Returns:
            bool: True if successfully sent
        """
        try:
            # Get email template based on notification type
            template_name = f"automation/email/{notification.notification_type}.html"
            
            # Render email content
            email_html = render_to_string(template_name, context)
            
            # Try to send the email
            try:
                send_mail(
                    subject=notification.subject,
                    message=notification.message,  # Plain text version
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[notification.recipient],
                    html_message=email_html,
                    fail_silently=False
                )
            except Exception as smtp_error:
                logger.error(f"SMTP error: {str(smtp_error)}")
                
                # Fall back to console backend in debug mode
                if hasattr(settings, 'EMAIL_BACKEND_FALLBACK') and settings.DEBUG:
                    from django.core.mail.backends.console import EmailBackend
                    backend = EmailBackend()
                    from django.core.mail import EmailMultiAlternatives
                    
                    email = EmailMultiAlternatives(
                        subject=notification.subject,
                        body=notification.message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[notification.recipient],
                    )
                    email.attach_alternative(email_html, "text/html")
                    backend.send_messages([email])
                    logger.info(f"Email sent using fallback console backend")
                else:
                    raise  # Re-raise the original error
            
            # Mark notification as sent
            notification.sent = True
            notification.sent_time = datetime.now()
            notification.save()
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending email notification: {template_name}")
            logger.error(f"Error details: {str(e)}")
            return False