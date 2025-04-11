# File: security_automation/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('recon/', include('reconnaissance.urls')),
    path('vulnerability/', include('vulnerability.urls')),
    path('reporting/', include('reporting.urls')),
    path('network/', include('network_visualization.urls')),
    path('automation/', include('automation.urls')),
    path('exploits/', include('exploit_manager.urls')),
    path('exploitation/', include('manual_exploitation.urls')),
# Add this line
]