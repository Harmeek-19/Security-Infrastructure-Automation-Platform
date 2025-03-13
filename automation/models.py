# automation/models.py

from django.db import models
from django.utils import timezone

class ScanWorkflow(models.Model):
    """
    Represents a complete security scanning workflow
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('canceled', 'Canceled')
    ]
    
    PROFILE_CHOICES = [
        ('quick', 'Quick Scan'),
        ('standard', 'Standard Scan'),
        ('full', 'Full Scan')
    ]
    
    name = models.CharField(max_length=255)
    target = models.CharField(max_length=255)
    scan_profile = models.CharField(max_length=20, choices=PROFILE_CHOICES, default='standard')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Timing information
    created_at = models.DateTimeField(auto_now_add=True)
    scheduled_time = models.DateTimeField(null=True, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    
    # Notification settings
    notification_email = models.EmailField(null=True, blank=True)
    
    # Additional metadata
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['target']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.target} ({self.status})"
    
    @property
    def duration(self):
        """Calculate workflow duration in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def is_active(self):
        """Check if workflow is active (not in terminal state)"""
        return self.status in ['pending', 'scheduled', 'in_progress']
    
    @property
    def is_scheduled(self):
        """Check if workflow is scheduled for future execution"""
        return self.status == 'scheduled' and self.scheduled_time and self.scheduled_time > timezone.now()


class ScanTask(models.Model):
    """
    Represents an individual task within a scanning workflow
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),
        ('canceled', 'Canceled')
    ]
    
    TASK_TYPE_CHOICES = [
        ('subdomain_enumeration', 'Subdomain Enumeration'),
        ('port_scanning', 'Port Scanning'),
        ('service_identification', 'Service Identification'),
        ('vulnerability_scanning', 'Vulnerability Scanning'),
        ('network_mapping', 'Network Mapping'),
        ('report_generation', 'Report Generation')
    ]
    
    workflow = models.ForeignKey(ScanWorkflow, on_delete=models.CASCADE, related_name='tasks')
    task_type = models.CharField(max_length=50, choices=TASK_TYPE_CHOICES)
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Task dependencies
    dependencies = models.ManyToManyField('self', symmetrical=False, related_name='dependents', blank=True)
    order = models.IntegerField(default=0)
    
    # Timing information
    created_at = models.DateTimeField(auto_now_add=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    
    # Results
    result = models.TextField(null=True, blank=True)
    
    class Meta:
        ordering = ['workflow', 'order']
        indexes = [
            models.Index(fields=['workflow', 'status']),
            models.Index(fields=['task_type']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.status})"
    
    @property
    def duration(self):
        """Calculate task duration in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def has_dependencies(self):
        """Check if task has dependencies"""
        return self.dependencies.exists()
    
    @property
    def is_blocked(self):
        """Check if any dependencies are not completed"""
        return self.dependencies.exclude(status='completed').exists()


class Notification(models.Model):
    """
    Represents a notification sent to a user
    """
    NOTIFICATION_TYPE_CHOICES = [
        ('workflow_scheduled', 'Workflow Scheduled'),
        ('workflow_started', 'Workflow Started'),
        ('workflow_completed', 'Workflow Completed'),
        ('workflow_failed', 'Workflow Failed'),
        ('workflow_canceled', 'Workflow Canceled'),
        ('task_failed', 'Task Failed'),
        ('critical_vulnerabilities', 'Critical Vulnerabilities'),
        ('report_ready', 'Report Ready')
    ]
    
    workflow = models.ForeignKey(ScanWorkflow, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPE_CHOICES)
    recipient = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    sent = models.BooleanField(default=False)
    sent_time = models.DateTimeField(null=True, blank=True)
    
    # For tracking email opens, clicks, etc.
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['notification_type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['sent']),
        ]
    
    def __str__(self):
        return f"{self.notification_type} for {self.workflow.name}"


class ScheduledTask(models.Model):
    """
    Represents a recurring scheduled task/scan
    """
    FREQUENCY_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('custom', 'Custom')
    ]
    
    name = models.CharField(max_length=255)
    target = models.CharField(max_length=255)
    scan_profile = models.CharField(max_length=20, choices=ScanWorkflow.PROFILE_CHOICES, default='standard')
    
    # Schedule
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    cron_expression = models.CharField(max_length=100, null=True, blank=True)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    
    # Active flag
    is_active = models.BooleanField(default=True)
    
    # Notification settings
    notification_email = models.EmailField(null=True, blank=True)
    
    # Created by
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=100, null=True, blank=True)
    
    # Last execution
    last_execution = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=20, null=True, blank=True)
    last_workflow = models.ForeignKey(ScanWorkflow, on_delete=models.SET_NULL, null=True, blank=True, related_name='schedule')
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['frequency']),
            models.Index(fields=['target']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.target} ({self.frequency})"