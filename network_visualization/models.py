from django.db import models

class NetworkNode(models.Model):
    """Represents a node in the network topology"""
    
    NODE_TYPES = [
        ('host', 'Host'),
        ('subdomain', 'Subdomain'),
        ('service', 'Service'),
        ('gateway', 'Gateway')
    ]
    
    domain = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=255)
    node_type = models.CharField(max_length=50, choices=NODE_TYPES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['domain', 'name', 'node_type']
        indexes = [
            models.Index(fields=['domain', 'is_active']),
            models.Index(fields=['node_type']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.node_type})"

class NetworkConnection(models.Model):
    """Represents a connection between two nodes in the network topology"""
    
    CONNECTION_TYPES = [
        ('domain', 'Domain Link'),
        ('service', 'Service Connection'),
        ('subdomain', 'Subdomain Link'),
        ('external', 'External Connection')
    ]
    
    source = models.ForeignKey(NetworkNode, on_delete=models.CASCADE, related_name='outgoing_connections')
    target = models.ForeignKey(NetworkNode, on_delete=models.CASCADE, related_name='incoming_connections')
    connection_type = models.CharField(max_length=50, choices=CONNECTION_TYPES)
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['source', 'target', 'connection_type']
        indexes = [
            models.Index(fields=['source', 'is_active']),
            models.Index(fields=['target', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.source.name} → {self.target.name} ({self.connection_type})"