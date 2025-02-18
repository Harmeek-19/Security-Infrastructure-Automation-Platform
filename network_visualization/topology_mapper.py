from typing import Dict, List, Optional
import logging
from django.db import transaction
from reconnaissance.models import Subdomain, Service
from .models import NetworkNode, NetworkConnection
import socket
from subprocess import Popen, PIPE
from datetime import datetime

class TopologyMapper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @transaction.atomic
    def create_network_map(self, target_domain: str) -> Dict:
        """Creates or updates the network topology for a target domain"""
        try:
            # Clean up old nodes and connections for this domain
            self._cleanup_old_data(target_domain)
            
            # Get all subdomains and services
            subdomains = Subdomain.objects.filter(domain=target_domain)
            
            # Create or update the main domain node
            try:
                domain_ip = socket.gethostbyname(target_domain)
            except:
                domain_ip = None

            domain_node = self._get_or_create_node(
                name=target_domain,
                domain=target_domain,
                node_type='host',
                ip_address=domain_ip
            )

            # Process subdomains
            subdomain_nodes = []
            for subdomain in subdomains:
                subdomain_node = self._get_or_create_node(
                    name=subdomain.subdomain,
                    domain=target_domain,
                    node_type='subdomain',
                    ip_address=subdomain.ip_address
                )
                subdomain_nodes.append(subdomain_node)
                
                # Create connection to domain
                self._create_connection(domain_node, subdomain_node, 'direct')

                # Process services for this subdomain
                services = Service.objects.filter(host=subdomain.subdomain)
                for service in services:
                    service_node = self._get_or_create_node(
                        name=f"{service.name}:{service.port}",
                        domain=target_domain,
                        node_type='service',
                        metadata={
                            'port': service.port,
                            'protocol': service.protocol,
                            'version': service.version
                        }
                    )
                    self._create_connection(subdomain_node, service_node, 'service')

            # Map network routes
            self._map_network_routes(domain_node, subdomain_nodes)

            # Get current node and connection counts for this domain
            current_nodes = NetworkNode.objects.filter(domain=target_domain, is_active=True).count()
            current_connections = NetworkConnection.objects.filter(
                source__domain=target_domain,
                is_active=True
            ).count()

            return {
                'status': 'success',
                'nodes': current_nodes,
                'connections': current_connections,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Error creating network map: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

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

    def _map_network_routes(self, domain_node: NetworkNode, subdomain_nodes: List[NetworkNode]):
        """Maps network routes between nodes using traceroute"""
        for subdomain_node in subdomain_nodes:
            if not subdomain_node.ip_address:
                continue

            try:
                # Create direct connection for local targets
                if any(local in subdomain_node.name for local in ['localhost', '127.0.0.1']):
                    self._create_connection(domain_node, subdomain_node, 'direct')
                    continue

                # For remote targets, try traceroute
                hops = self._run_traceroute(subdomain_node.ip_address)
                previous_node = domain_node

                for i, hop_ip in enumerate(hops):
                    gateway_node = self._get_or_create_node(
                        name=f"gateway_{hop_ip}",
                        domain=domain_node.domain,
                        node_type='gateway',
                        ip_address=hop_ip,
                        metadata={'hop_number': i + 1}
                    )
                    
                    self._create_connection(previous_node, gateway_node, 'gateway')
                    previous_node = gateway_node

                # Connect last hop to subdomain
                if previous_node != domain_node:
                    self._create_connection(previous_node, subdomain_node, 'gateway')
                else:
                    self._create_connection(domain_node, subdomain_node, 'direct')

            except Exception as e:
                self.logger.error(f"Error mapping route to {subdomain_node.name}: {str(e)}")
                self._create_connection(domain_node, subdomain_node, 'direct')

    def _run_traceroute(self, ip_address: str) -> List[str]:
        """Run traceroute command and return list of hops"""
        try:
            process = Popen(['traceroute', '-n', ip_address], stdout=PIPE, stderr=PIPE)
            output, error = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Traceroute failed: {error.decode()}")
                return []
                
            hops = []
            for line in output.decode().split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if ip != '*':
                            hops.append(ip)
            return hops
        except Exception as e:
            self.logger.error(f"Error running traceroute: {str(e)}")
            return []