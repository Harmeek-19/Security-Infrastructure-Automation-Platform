from django.db import models
from reconnaissance.models import Subdomain, Service

class NetworkNode(models.Model):
    """Represents a node in the network topology"""
    NODE_TYPES = [
        ('host', 'Host'),
        ('subdomain', 'Subdomain'),
        ('service', 'Service'),
        ('gateway', 'Gateway'),
    ]

    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255)  # Added this field
    node_type = models.CharField(max_length=20, choices=NODE_TYPES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['name']),
            models.Index(fields=['node_type']),
        ]

    def __str__(self):
        return f"{self.name} ({self.node_type})"

class NetworkConnection(models.Model):
    """Represents a connection between network nodes"""
    CONNECTION_TYPES = [
        ('direct', 'Direct Connection'),
        ('gateway', 'Gateway Connection'),
        ('service', 'Service Connection'),
    ]

    source = models.ForeignKey(NetworkNode, on_delete=models.CASCADE, related_name='outgoing_connections')
    target = models.ForeignKey(NetworkNode, on_delete=models.CASCADE, related_name='incoming_connections')
    connection_type = models.CharField(max_length=20, choices=CONNECTION_TYPES)
    metadata = models.JSONField(default=dict)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('source', 'target', 'connection_type')
        indexes = [
            models.Index(fields=['connection_type']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.source.name} -> {self.target.name} ({self.connection_type})"