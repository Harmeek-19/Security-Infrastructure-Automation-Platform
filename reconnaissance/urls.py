from django.urls import path
from . import views

app_name = 'reconnaissance'

urlpatterns = [
    # Results endpoint
    path('results/', views.ResultsView.as_view(), name='scan-results'),
    
    # Existing endpoints
    path('subdomain-scan/', views.SubdomainScanView.as_view(), name='subdomain-scan'),
    path('subdomains/', views.SubdomainListView.as_view(), name='subdomain-list'),
    path('subdomains/<int:subdomain_id>/', views.SubdomainDetailView.as_view(), name='subdomain-detail'),
    path('port-scan/', views.PortScanView.as_view(), name='port-scan'),
    path('port-scans/', views.PortScanListView.as_view(), name='portscan-list'),
    path('port-scans/<int:scan_id>/', views.PortScanDetailView.as_view(), name='portscan-detail'),
    path('services/scan/', views.ServiceScanView.as_view(), name='service-scan'),
    path('services/', views.ServiceListView.as_view(), name='service-list'),
    path('services/<int:service_id>/', views.ServiceDetailView.as_view(), name='service-detail'),
    path('statistics/', views.ScanStatisticsView.as_view(), name='scan-statistics'),
    path('summary/<str:host>/', views.HostSummaryView.as_view(), name='host-summary'),
]