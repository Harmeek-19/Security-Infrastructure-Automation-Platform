from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from .models import NetworkNode, NetworkConnection
from .topology_mapper import TopologyMapper
import logging

logger = logging.getLogger(__name__)

@require_http_methods(["GET"])
def get_network_topology(request, target_domain):
    """Get network topology for visualization"""
    try:
        # Create/update network map
        mapper = TopologyMapper()
        result = mapper.create_network_map(target_domain)
        
        if result['status'] == 'error':
            return JsonResponse(result, status=500)
            
        # Prepare nodes and links for visualization
        nodes = []
        links = []
        
        # Get domain-specific nodes
        domain_nodes = NetworkNode.objects.filter(
            domain=target_domain,
            is_active=True
        )
        
        # Get all nodes
        for node in domain_nodes:
            nodes.append({
                'id': node.id,
                'name': node.name,
                'type': node.node_type,
                'ip': node.ip_address,
                'metadata': node.metadata
            })
            
        # Get all connections for domain nodes
        node_ids = domain_nodes.values_list('id', flat=True)
        connections = NetworkConnection.objects.filter(
            source_id__in=node_ids,
            is_active=True
        )
        
        for conn in connections:
            links.append({
                'source': conn.source_id,
                'target': conn.target_id,
                'type': conn.connection_type,
                'metadata': conn.metadata
            })
            
        return JsonResponse({
            'status': 'success',
            'nodes': nodes,
            'links': links,
            'stats': {
                'total_nodes': len(nodes),
                'total_links': len(links)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting network topology: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@require_http_methods(["GET"])
def get_node_details(request, node_id):
    """Get detailed information about a specific node"""
    try:
        node = NetworkNode.objects.get(id=node_id, is_active=True)
        
        # Get connected nodes
        connected_nodes = NetworkNode.objects.filter(
            outgoing_connections__target=node,
            is_active=True
        ) | NetworkNode.objects.filter(
            incoming_connections__source=node,
            is_active=True
        )
        
        return JsonResponse({
            'status': 'success',
            'node': {
                'id': node.id,
                'name': node.name,
                'domain': node.domain,
                'type': node.node_type,
                'ip': node.ip_address,
                'metadata': node.metadata,
                'last_seen': node.last_seen.isoformat(),
                'connected_nodes': [
                    {
                        'id': n.id,
                        'name': n.name,
                        'type': n.node_type,
                        'connection_type': n.outgoing_connections.filter(target=node).first().connection_type
                        if n.outgoing_connections.filter(target=node).exists()
                        else n.incoming_connections.filter(source=node).first().connection_type
                    }
                    for n in connected_nodes
                ]
            }
        })
        
    except NetworkNode.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'error': 'Node not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error getting node details: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@require_http_methods(["GET"])
def get_network_stats(request, target_domain):
    """Get statistics about the network topology"""
    try:
        nodes = NetworkNode.objects.filter(
            domain=target_domain,
            is_active=True
        )
        node_ids = nodes.values_list('id', flat=True)
        connections = NetworkConnection.objects.filter(
            source_id__in=node_ids,
            is_active=True
        )
        
        stats = {
            'total_nodes': nodes.count(),
            'nodes_by_type': {},
            'total_connections': connections.count(),
            'connections_by_type': {},
            'domain_info': {
                'host_nodes': nodes.filter(node_type='host').count(),
                'subdomain_nodes': nodes.filter(node_type='subdomain').count(),
                'service_nodes': nodes.filter(node_type='service').count(),
                'gateway_nodes': nodes.filter(node_type='gateway').count(),
            }
        }
        
        # Count nodes by type
        for node_type, _ in NetworkNode.NODE_TYPES:
            stats['nodes_by_type'][node_type] = nodes.filter(node_type=node_type).count()
            
        # Count connections by type
        for conn_type, _ in NetworkConnection.CONNECTION_TYPES:
            stats['connections_by_type'][conn_type] = connections.filter(connection_type=conn_type).count()
            
        return JsonResponse({
            'status': 'success',
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting network stats: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)