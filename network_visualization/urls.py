from django.urls import path
from . import views

app_name = 'network_visualization'

urlpatterns = [
    path('topology/<str:target_domain>/', views.get_network_topology, name='topology'),
    path('node/<int:node_id>/', views.get_node_details, name='node_details'),
    path('stats/<str:target_domain>/', views.get_network_stats, name='network_stats'),
]