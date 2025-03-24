import math
from typing import Dict, List, Optional
import logging
from django.db import transaction
from reconnaissance.models import PortScan, Subdomain, Service
from .models import NetworkNode, NetworkConnection
import socket
from subprocess import Popen, PIPE
from datetime import datetime
import json
from django.core.serializers.json import DjangoJSONEncoder
from vulnerability.models import Vulnerability

class TopologyMapper:
    """
    Handles network topology mapping and visualization
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    @transaction.atomic
    def create_network_map(self, target_domain: str, services: list = None, subdomains: list = None) -> dict:
        """
        Create a network map for a target domain
        
        Args:
            target_domain: The domain to map
            services: Optional list of service data from service identification
            subdomains: Optional list of subdomain data from subdomain enumeration
            
        Returns:
            dict: Status and count information about created nodes/connections
        """
        try:
            self.logger.info(f"Creating network map for {target_domain}")
            
            # Create domain node if it doesn't exist
            domain_node, created = NetworkNode.objects.get_or_create(
                domain=target_domain,
                name=target_domain,
                node_type='host',
                defaults={
                    'ip_address': None,
                    'metadata': {'main_domain': True},
                    'is_active': True
                }
            )
            
            if created:
                self.logger.info(f"Created domain node for {target_domain}")
            
            # Process subdomain data if provided
            if subdomains:
                self.logger.info(f"Processing {len(subdomains)} subdomains for network mapping")
                self._process_subdomains(target_domain, domain_node, subdomains)
            else:
                # Otherwise use database subdomain records
                self._process_database_subdomains(target_domain, domain_node)
                
            # Process service data if provided
            if services:
                self.logger.info(f"Processing {len(services)} services for network mapping")
                self._process_services(target_domain, domain_node, services)
            else:
                # Otherwise use database service records
                self._process_database_services(target_domain, domain_node)
            
            # Add gateway nodes for key external connections
            self._add_gateway_nodes(target_domain, domain_node)
            
            # Add vulnerability nodes
            self._add_vulnerability_nodes(target_domain, domain_node)
            
            # Count nodes and connections for the target domain
            node_count = NetworkNode.objects.filter(
                domain=target_domain,
                is_active=True
            ).count()
            
            connection_count = NetworkConnection.objects.filter(
                source__domain=target_domain,
                is_active=True
            ).count()
            
            self.logger.info(f"Network map created with {node_count} nodes and {connection_count} connections")
            
            # Get the network data for visualization
            network_data = self.get_network_data(target_domain)
            
            return {
                'status': 'success',
                'target': target_domain,
                'nodes': node_count,
                'connections': connection_count,
                'network_data': network_data  # Include the network data in the result
            }
            
        except Exception as e:
            self.logger.error(f"Error creating network map: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def _process_subdomains(self, target_domain, domain_node, subdomains):
        """Process subdomain data from scan results"""
        for subdomain_data in subdomains:
            subdomain = subdomain_data.get('subdomain')
            if not subdomain:
                continue
                
            try:
                # Create subdomain node
                subdomain_node, created = NetworkNode.objects.get_or_create(
                    domain=target_domain,
                    name=subdomain,
                    node_type='subdomain',
                    defaults={
                        'ip_address': subdomain_data.get('ip_address'),
                        'metadata': {
                            'is_http': subdomain_data.get('is_http'),
                            'http_status': subdomain_data.get('http_status'),
                            'status': subdomain_data.get('status')
                        },
                        'is_active': True
                    }
                )
                
                # Create connection to main domain
                NetworkConnection.objects.get_or_create(
                    source=domain_node,
                    target=subdomain_node,
                    connection_type='domain',
                    defaults={
                        'metadata': {},
                        'is_active': True
                    }
                )
            except Exception as e:
                self.logger.error(f"Error processing subdomain {subdomain}: {str(e)}")

    def _process_services(self, target_domain, domain_node, services):
        """Process service data from scan results"""
        for service_data in services:
            port = service_data.get('port')
            if not port:
                continue
                
            service_info = service_data.get('service', {})
            if not service_info:
                continue
                
            service_name = service_info.get('name', 'unknown')
            node_name = f"{service_name}:{port}"
            
            try:
                # Create service node
                service_node, created = NetworkNode.objects.get_or_create(
                    domain=target_domain,
                    name=node_name,
                    node_type='service',
                    defaults={
                        'ip_address': None,
                        'metadata': {
                            'port': port,
                            'protocol': service_data.get('protocol', 'tcp'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'category': service_data.get('category', 'other'),
                            'risk_level': service_data.get('risk_level', 'MEDIUM')
                        },
                        'is_active': True
                    }
                )
                
                # Create connection to main domain
                NetworkConnection.objects.get_or_create(
                    source=domain_node,
                    target=service_node,
                    connection_type='service',
                    defaults={
                        'metadata': {'port': port},
                        'is_active': True
                    }
                )
            except Exception as e:
                self.logger.error(f"Error processing service {node_name}: {str(e)}")

    def _process_database_subdomains(self, target_domain, domain_node):
        """Use subdomain information from the database"""
        from reconnaissance.models import Subdomain
        
        subdomains = Subdomain.objects.filter(domain=target_domain, is_active=True)
        self.logger.info(f"Processing {subdomains.count()} subdomains from database")
        
        for subdomain in subdomains:
            try:
                # Create subdomain node
                subdomain_node, created = NetworkNode.objects.get_or_create(
                    domain=target_domain,
                    name=subdomain.subdomain,
                    node_type='subdomain',
                    defaults={
                        'ip_address': subdomain.ip_address,
                        'metadata': {},
                        'is_active': True
                    }
                )
                
                # Create connection to main domain
                NetworkConnection.objects.get_or_create(
                    source=domain_node,
                    target=subdomain_node,
                    connection_type='subdomain',
                    defaults={
                        'metadata': {},
                        'is_active': True
                    }
                )
            except Exception as e:
                self.logger.error(f"Error processing DB subdomain {subdomain.subdomain}: {str(e)}")

    def _process_database_services(self, target_domain, domain_node):
        """Use service information from the database"""
        from reconnaissance.models import Service
        
        services = Service.objects.filter(host=target_domain, is_active=True)
        self.logger.info(f"Processing {services.count()} services from database")
        
        for service in services:
            try:
                node_name = f"{service.name}:{service.port}"
                
                # Create service node
                service_node, created = NetworkNode.objects.get_or_create(
                    domain=target_domain,
                    name=node_name,
                    node_type='service',
                    defaults={
                        'ip_address': None,
                        'metadata': {
                            'port': service.port,
                            'protocol': service.protocol,
                            'product': service.product,
                            'version': service.version,
                            'category': service.category,
                            'risk_level': service.risk_level
                        },
                        'is_active': True
                    }
                )
                
                # Create connection to main domain
                NetworkConnection.objects.get_or_create(
                    source=domain_node,
                    target=service_node,
                    connection_type='service',
                    defaults={
                        'metadata': {'port': service.port},
                        'is_active': True
                    }
                )
            except Exception as e:
                self.logger.error(f"Error processing DB service {service.name}:{service.port}: {str(e)}")

    def _add_gateway_nodes(self, target_domain, domain_node):
        """Add gateway nodes for external connections"""
        from vulnerability.models import Vulnerability
        
        # Check if target has vulnerabilities related to external services
        external_vulns = Vulnerability.objects.filter(
            target=target_domain,
            vuln_type__in=['ssrf', 'open_redirect', 'external_service']
        )
        
        for vuln in external_vulns:
            try:
                # Create a gateway node for the vulnerability
                gateway_name = f"External: {vuln.name[:30]}"
                
                gateway_node, created = NetworkNode.objects.get_or_create(
                    domain=target_domain,
                    name=gateway_name,
                    node_type='gateway',
                    defaults={
                        'ip_address': None,
                        'metadata': {
                            'vulnerability_id': vuln.id,
                            'severity': vuln.severity
                        },
                        'is_active': True
                    }
                )
                
                # Create connection to main domain
                NetworkConnection.objects.get_or_create(
                    source=domain_node,
                    target=gateway_node,
                    connection_type='external',
                    defaults={
                        'metadata': {'severity': vuln.severity},
                        'is_active': True
                    }
                )
            except Exception as e:
                self.logger.error(f"Error adding gateway node for {vuln.name}: {str(e)}")

    def _add_vulnerability_nodes(self, target_domain, domain_node):
        """Add vulnerability nodes to network map"""
        from vulnerability.models import Vulnerability
        
        vulnerabilities = Vulnerability.objects.filter(
            target=target_domain,
            is_fixed=False
        )
        for vuln in vulnerabilities:
            try:
                # Skip some vulnerability types to avoid cluttering
                if vuln.vuln_type in ['info_disclosure', 'outdated_component']:
                    continue
                    
                # Create node name based on severity
                severity_prefix = {
                    'CRITICAL': 'Critical:',
                    'HIGH': 'High:',
                    'MEDIUM': 'Medium:',
                    'LOW': 'Low:'
                }.get(vuln.severity, '')
                
                node_name = f"{severity_prefix} {vuln.name[:40]}"
                
                # Check if vulnerability node type exists in model choices
                # If not, handle potential database integrity errors
                try:
                    vuln_node, created = NetworkNode.objects.get_or_create(
                        domain=target_domain,
                        name=node_name,
                        node_type='vulnerability',
                        defaults={
                            'ip_address': None,
                            'metadata': {
                                'vulnerability_id': vuln.id,
                                'severity': vuln.severity,
                                'type': vuln.vuln_type,
                                'cvss': vuln.cvss_score
                            },
                            'is_active': True
                        }
                    )
                except Exception as type_error:
                    # Fall back to a more generic node type if 'vulnerability' not in choices
                    self.logger.warning(f"Could not create vulnerability node with type 'vulnerability', using 'gateway' instead: {str(type_error)}")
                    vuln_node, created = NetworkNode.objects.get_or_create(
                        domain=target_domain,
                        name=node_name,
                        node_type='gateway',  # Fallback to gateway which should exist
                        defaults={
                            'ip_address': None,
                            'metadata': {
                                'vulnerability_id': vuln.id,
                                'severity': vuln.severity,
                                'type': vuln.vuln_type,
                                'cvss': vuln.cvss_score,
                                'is_vulnerability': True  # Mark it as actually a vulnerability
                            },
                            'is_active': True
                        }
                    )
                
                # Connect to domain node
                NetworkConnection.objects.get_or_create(
                    source=domain_node,
                    target=vuln_node,
                    connection_type='external',  # Using 'external' for vulnerabilities too
                    defaults={
                        'metadata': {'severity': vuln.severity},
                        'is_active': True
                    }
                )
            except Exception as e:
                self.logger.error(f"Error adding vulnerability node for {vuln.name}: {str(e)}")

    def _cleanup_old_data(self, target_domain: str):
        """Clean up old nodes and connections for the target domain"""
        # Deactivate old nodes
        NetworkNode.objects.filter(domain=target_domain).update(is_active=False)
        
        # Deactivate old connections
        NetworkConnection.objects.filter(
            source__domain=target_domain
        ).update(is_active=False)

    def _get_or_create_node(self, name: str, domain: str, node_type: str, 
                           ip_address: Optional[str] = None, 
                           metadata: Optional[Dict] = None) -> NetworkNode:
        """Gets existing node or creates a new one"""
        node, created = NetworkNode.objects.get_or_create(
            name=name,
            domain=domain,
            node_type=node_type,
            defaults={
                'ip_address': ip_address,
                'metadata': metadata or {},
                'is_active': True
            }
        )
        if not created:
            node.ip_address = ip_address
            node.is_active = True
            if metadata:
                node.metadata.update(metadata)
            node.save()
        return node

    def _create_connection(self, source: NetworkNode, target: NetworkNode, 
                          connection_type: str, metadata: Optional[Dict] = None) -> NetworkConnection:
        """Creates or updates a connection between nodes"""
        connection, created = NetworkConnection.objects.get_or_create(
            source=source,
            target=target,
            connection_type=connection_type,
            defaults={
                'metadata': metadata or {},
                'is_active': True
            }
        )
        if not created:
            connection.is_active = True
            if metadata:
                connection.metadata.update(metadata)
            connection.save()
        return connection
            
    def get_network_data(self, target_domain: str) -> Dict:
        """
        Get formatted network data suitable for D3.js visualization
        
        Args:
            target_domain: The domain to get network data for
            
        Returns:
            dict: Network data with nodes and links arrays
        """
        try:
            nodes = []
            links = []
            
            # Get all active nodes for the domain
            domain_nodes = NetworkNode.objects.filter(
                domain=target_domain,
                is_active=True
            )
            
            if not domain_nodes.exists():
                self.logger.warning(f"No active nodes found for domain {target_domain}")
                return {
                    'nodes': [],
                    'links': []
                }
            
            # Create node data for visualization
            for node in domain_nodes:
                node_data = {
                    'id': str(node.id),  # Convert to string to ensure compatibility with D3
                    'name': node.name,
                    'type': node.node_type,
                    'info': str(node.ip_address) if node.ip_address else ''
                }
                
                # Add some metadata if available
                if isinstance(node.metadata, dict):
                    for key in ['port', 'product', 'version', 'category', 'risk_level', 'severity']:
                        if key in node.metadata:
                            node_data[key] = node.metadata[key]
                
                nodes.append(node_data)
            
            # Get all active connections for the domain
            node_ids = domain_nodes.values_list('id', flat=True)
            connections = NetworkConnection.objects.filter(
                source_id__in=node_ids,
                is_active=True
            )
            
            # Create link data for visualization, ensuring source/target are strings
            for conn in connections:
                links.append({
                    'source': str(conn.source_id),  # Must match the node id format (string)
                    'target': str(conn.target_id),  # Must match the node id format (string)
                    'type': conn.connection_type
                })
            
            # Log the data being returned
            self.logger.info(f"Returning network data with {len(nodes)} nodes and {len(links)} links for {target_domain}")
            
            if nodes:
                # Position main domain node at center
                center_node = next((node for node in nodes if node.get('type') == 'host'), nodes[0])
                center_node['x'] = 0
                center_node['y'] = 0
                
                # Position other nodes in concentric circles
                types_order = ['subdomain', 'service', 'gateway', 'vulnerability']
                
                for i, node_type in enumerate(types_order):
                    type_nodes = [node for node in nodes if node.get('type') == node_type]
                    radius = 150 * (i + 1)  # Increasing radius for each type
                    angle_step = (2 * math.pi) / max(len(type_nodes), 1)
                    
                    for j, node in enumerate(type_nodes):
                        angle = angle_step * j
                        node['x'] = radius * math.cos(angle)
                        node['y'] = radius * math.sin(angle)
            
            return {
                'nodes': nodes,
                'links': links
            }


            
        except Exception as e:
            self.logger.error(f"Error getting network data: {str(e)}")
            # Return minimal valid data structure instead of raising error
            return {
                'nodes': [],
                'links': [],
                'error': str(e)
            }

# Example dummy data for testing
def generate_test_network_data(target: str = "example.com") -> Dict:
    """Generate test network data for visualization testing"""
    return {
        "nodes": [
            {"id": "host_1", "name": target, "type": "host", "info": "Main target"},
            {"id": "subdomain_1", "name": f"www.{target}", "type": "subdomain", "info": "Web server"},
            {"id": "subdomain_2", "name": f"api.{target}", "type": "subdomain", "info": "API server"},
            {"id": "port_1", "name": "Port 80", "type": "port", "info": "HTTP port"},
            {"id": "port_2", "name": "Port 443", "type": "port", "info": "HTTPS port"},
            {"id": "port_3", "name": "Port 22", "type": "port", "info": "SSH port"},
            {"id": "service_1", "name": "HTTP", "type": "service", "info": "Web service"},
            {"id": "service_2", "name": "HTTPS", "type": "service", "info": "Secure web service"},
            {"id": "service_3", "name": "SSH", "type": "service", "info": "Secure shell"},
            {"id": "vuln_1", "name": "SQL Injection", "type": "vulnerability", "info": "Severity: HIGH"}
        ],
        "links": [
            {"source": "host_1", "target": "subdomain_1", "type": "contains"},
            {"source": "host_1", "target": "subdomain_2", "type": "contains"},
            {"source": "subdomain_1", "target": "port_1", "type": "contains"},
            {"source": "subdomain_1", "target": "port_2", "type": "contains"},
            {"source": "subdomain_2", "target": "port_3", "type": "contains"},
            {"source": "port_1", "target": "service_1", "type": "communicates"},
            {"source": "port_2", "target": "service_2", "type": "communicates"},
            {"source": "port_3", "target": "service_3", "type": "communicates"},
            {"source": "service_1", "target": "vuln_1", "type": "has_vulnerability"}
        ]
    }