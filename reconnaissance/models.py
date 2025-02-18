from django.db import models

from django.db import models

class Subdomain(models.Model):
    domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True)
    discovered_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-discovered_date']
        unique_together = ['domain', 'subdomain']
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['subdomain']),
        ]

    def __str__(self):
        return self.subdomain

    def save(self, *args, **kwargs):
        # Update instead of error on duplicate
        try:
            super().save(*args, **kwargs)
        except:
            existing = Subdomain.objects.get(domain=self.domain, subdomain=self.subdomain)
            existing.ip_address = self.ip_address
            existing.is_active = self.is_active
            existing.save()

class Service(models.Model):
    RISK_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
    ]

    CATEGORIES = [
        ('web', 'Web Services'),
        ('database', 'Database Services'),
        ('mail', 'Mail Services'),
        ('file_transfer', 'File Transfer'),
        ('remote_access', 'Remote Access'),
        ('domain_services', 'Domain Services'),
        ('monitoring', 'Monitoring'),
        ('security', 'Security Services'),
        ('other', 'Other'),
    ]

    PROTOCOLS = [
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('sctp', 'SCTP'),
    ]

    host = models.CharField(max_length=255)
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, choices=PROTOCOLS, default='tcp')
    name = models.CharField(max_length=100)
    product = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=100, blank=True)
    extra_info = models.TextField(blank=True)
    category = models.CharField(max_length=50, choices=CATEGORIES)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS)
    cpe = models.JSONField(default=list)
    scan_date = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('host', 'port', 'protocol')
        ordering = ['-scan_date']
        indexes = [
            models.Index(fields=['host', 'port']),
            models.Index(fields=['category']),
            models.Index(fields=['risk_level']),
        ]

    def __str__(self):
        return f"{self.host}:{self.port} - {self.name}"

class PortScan(models.Model):
    STATES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'), 
        ('open', 'Open'),
        ('closed', 'Closed'),
        ('filtered', 'Filtered'),
        ('unfiltered', 'Unfiltered'),
        ('error', 'Error'),
        ('completed', 'Completed')
    ]

    SCAN_STATUS = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('error', 'Error')
    ]

    host = models.CharField(max_length=255)
    port = models.IntegerField()
    service = models.CharField(max_length=100)
    state = models.CharField(max_length=50, choices=STATES)
    scan_status = models.CharField(max_length=50, choices=SCAN_STATUS, default='pending')
    scan_date = models.DateTimeField(auto_now_add=True)
    protocol = models.CharField(max_length=10, choices=Service.PROTOCOLS, default='tcp')
    banner = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    scan_type = models.CharField(max_length=50, default='quick')
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-scan_date']
        indexes = [
            models.Index(fields=['host', 'port']),
            models.Index(fields=['state']),
            models.Index(fields=['scan_date']),
            models.Index(fields=['scan_status'])
        ]

    def __str__(self):
        return f"{self.host}:{self.port} - {self.state}"
class SystemLogEntry(models.Model):
    """Model for system logs admin interface"""
    class Meta:
        managed = False
        verbose_name_plural = 'System Logs'
        default_permissions = ('view',)