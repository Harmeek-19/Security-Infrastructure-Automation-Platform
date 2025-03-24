# File: network_visualization/urls.py
from django.urls import path, re_path
from . import views

app_name = 'network_visualization'

urlpatterns = [
    # Main visualization pages
    path('', views.NetworkVisualizationView.as_view(), name='index'),
    path('visualization/', views.NetworkVisualizationView.as_view(), name='visualization'),
    path('visualization/<path:target>/', views.NetworkVisualizationView.as_view(), name='visualization_target'),
    
    # API endpoints for fetching network data using regex to handle URLs with protocols
    path('topology/', views.TopologyView.as_view(), name='topology'),
    re_path(r'^topology/(?P<target>.+)/$', views.TopologyView.as_view(), name='topology_target'),
    
    # Additional API endpoints for network data
    path('api/network-data/<path:target>/', views.get_network_topology, name='network_data'),
    path('api/node/<int:node_id>/', views.get_node_details, name='node_details'),
    path('api/stats/<path:target_domain>/', views.get_network_stats, name='network_stats'),
]