# File: network_visualization/views.py
from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
import json
import logging
from urllib.parse import urlparse

from .models import NetworkNode, NetworkConnection
from .topology_mapper import TopologyMapper, generate_test_network_data

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class TopologyView(View):
    """View to get the network topology data for a target"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapper = TopologyMapper()
    
    def get(self, request, target=None):
        """Get the network topology for a target"""
        try:
            # Get target from URL parameter if not provided in the route
            if not target:
                target = request.GET.get('target')
            
            if not target:
                return JsonResponse({
                    'status': 'error',
                    'error': 'Target parameter is required'
                }, status=400)
            
            # Clean the target URL to extract just the domain
            parsed_url = urlparse(target)
            
            # If the target includes a protocol, extract just the domain
            if parsed_url.netloc:
                target_domain = parsed_url.netloc
            else:
                # If no protocol, the domain might be in the path
                target_domain = parsed_url.path
            
            # Remove port information if present
            if ':' in target_domain:
                target_domain = target_domain.split(':', 1)[0]
                
            # Remove trailing slashes
            target_domain = target_domain.rstrip('/')
            
            logger.info(f"Processing topology request for cleaned domain: {target_domain}")
            
            # Generate network map
            result = self.mapper.create_network_map(target_domain)
            
            # If no nodes found or error, return test data for development
            if result.get('status') == 'error' or not result.get('network_data', {}).get('nodes'):
                logger.warning(f"No network data found for {target_domain}, using test data")
                test_data = generate_test_network_data(target_domain)
                return JsonResponse({
                    'status': 'success',
                    'nodes': test_data['nodes'],
                    'links': test_data['links'],
                    'target': target_domain,
                    'test_data': True  # Flag that this is test data
                })
            
            # Return real data if available
            return JsonResponse({
                'status': 'success',
                'nodes': result['network_data']['nodes'],
                'links': result['network_data']['links'],
                'target': target_domain,
                'node_count': result['nodes'],
                'connection_count': result['connections']
            })
        
        except Exception as e:
            logger.error(f"Error generating topology: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'error': str(e)
            }, status=500)


class NetworkVisualizationView(View):
    """View to render the network visualization page"""
    
    def get(self, request, target=None):
        """Render the network visualization page"""
        if not target:
            target = request.GET.get('target', 'example.com')
        
        # Clean the target URL
        parsed_url = urlparse(target)
        
        # If the target includes a protocol, extract just the domain
        if parsed_url.netloc:
            target_domain = parsed_url.netloc
        else:
            # If no protocol, the domain might be in the path
            target_domain = parsed_url.path
        
        # Remove port information if present
        if ':' in target_domain:
            target_domain = target_domain.split(':', 1)[0]
            
        # Remove trailing slashes
        target_domain = target_domain.rstrip('/')
        
        # Get node count for the target
        node_count = NetworkNode.objects.filter(domain=target_domain, is_active=True).count()
        connection_count = NetworkConnection.objects.filter(source__domain=target_domain, is_active=True).count()
        
        return render(request, 'network_visualization/visualization.html', {
            'target': target_domain,
            'node_count': node_count,
            'connection_count': connection_count
        })

# Keep the rest of the file unchanged
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
        ).distinct()
        
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
    
@require_http_methods(["GET"])
def get_network_topology(request, target_domain):
    """Get network topology for visualization"""
    try:
        # Clean the target URL
        from urllib.parse import urlparse
        parsed_url = urlparse(target_domain)
        
        # If the target includes a protocol, extract just the domain
        if parsed_url.netloc:
            clean_domain = parsed_url.netloc
        else:
            # If no protocol, the domain might be in the path
            clean_domain = parsed_url.path
        
        # Remove port information if present
        if ':' in clean_domain:
            clean_domain = clean_domain.split(':', 1)[0]
            
        # Remove trailing slashes
        clean_domain = clean_domain.rstrip('/')
        
        logger.info(f"Getting network topology for cleaned domain: {clean_domain}")
        
        # Create/update network map
        mapper = TopologyMapper()
        result = mapper.create_network_map(clean_domain)
        
        if result['status'] == 'error':
            return JsonResponse(result, status=500)
            
        # Return the network data directly from the result
        if 'network_data' in result and result['network_data']:
            return JsonResponse({
                'status': 'success',
                'nodes': result['network_data']['nodes'],
                'links': result['network_data']['links'],
                'stats': {
                    'total_nodes': len(result['network_data']['nodes']),
                    'total_links': len(result['network_data']['links'])
                }
            })
        
        # Fallback to test data if no real data available
        test_data = generate_test_network_data(clean_domain)
        return JsonResponse({
            'status': 'success',
            'nodes': test_data['nodes'],
            'links': test_data['links'],
            'stats': {
                'total_nodes': len(test_data['nodes']),
                'total_links': len(test_data['links'])
            },
            'test_data': True
        })
        
    except Exception as e:
        logger.error(f"Error getting network topology: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)