from django.contrib import admin
from django.urls import path
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.contrib import messages
from .models import Service, Subdomain, PortScan, SystemLogEntry
import os
from django.conf import settings

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('host', 'port', 'name', 'version', 'category', 'risk_level', 'scan_date')
    list_filter = ('category', 'risk_level', 'protocol')
    search_fields = ('host', 'name', 'product')
    date_hierarchy = 'scan_date'
    readonly_fields = ('scan_date', 'last_seen')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('host', 'port', 'protocol', 'name')
        }),
        ('Service Details', {
            'fields': ('product', 'version', 'extra_info')
        }),
        ('Classification', {
            'fields': ('category', 'risk_level')
        }),
        ('Metadata', {
            'fields': ('scan_date', 'last_seen'),
            'classes': ('collapse',)
        }),
    )

@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ('domain', 'subdomain', 'ip_address', 'discovered_date')
    list_filter = ('domain', 'discovered_date')
    search_fields = ('domain', 'subdomain', 'ip_address')
    readonly_fields = ('discovered_date',)
    
    fieldsets = (
        (None, {
            'fields': ('domain', 'subdomain', 'ip_address', 'discovered_date')
        }),
    )

@admin.register(PortScan)
class PortScanAdmin(admin.ModelAdmin):
    list_display = ('host', 'port', 'service', 'state', 'scan_date')
    list_filter = ('state', 'scan_date')
    search_fields = ('host', 'service')
    readonly_fields = ('scan_date',)

@admin.register(SystemLogEntry)
class SystemLogAdmin(admin.ModelAdmin):
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('viewer/', 
                self.admin_site.admin_view(self.log_viewer_view), 
                name='log-viewer'),
            path('download/<str:log_file>/', 
                self.admin_site.admin_view(self.download_log), 
                name='download-log'),
            path('clear/<str:log_file>/', 
                self.admin_site.admin_view(self.clear_log), 
                name='clear-log'),
        ]
        return custom_urls + urls

    def log_viewer_view(self, request):
        logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        log_files = {}
        for log_file in ['debug.log', 'services.log', 'error.log']:
            file_path = os.path.join(logs_dir, log_file)
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                        log_files[log_file] = {
                            'content': ''.join(lines[-500:]),
                            'size': os.path.getsize(file_path),
                            'modified': os.path.getmtime(file_path)
                        }
                else:
                    open(file_path, 'a').close()
                    log_files[log_file] = {
                        'content': 'Log file is empty',
                        'size': 0,
                        'modified': os.path.getmtime(file_path)
                    }
            except Exception as e:
                log_files[log_file] = {
                    'content': f'Error reading log file: {str(e)}',
                    'size': 0,
                    'modified': 0
                }

        context = {
            'title': 'System Logs',
            'log_files': log_files,
            'is_nav_sidebar_enabled': True,
        }
        return TemplateResponse(request, 'admin/log_viewer.html', context)

    def download_log(self, request, log_file):
        file_path = os.path.join(settings.BASE_DIR, 'logs', log_file)
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    response = HttpResponse(f.read(), content_type='text/plain')
                    response['Content-Disposition'] = f'attachment; filename="{log_file}"'
                    return response
            else:
                messages.error(request, f'Log file {log_file} not found')
                return HttpResponse('Log file not found', status=404)
        except Exception as e:
            messages.error(request, f'Error downloading log file: {str(e)}')
            return HttpResponse('Error downloading log file', status=500)

    def clear_log(self, request, log_file):
        file_path = os.path.join(settings.BASE_DIR, 'logs', log_file)
        try:
            if os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write('')
                messages.success(request, f'Successfully cleared {log_file}')
            else:
                messages.warning(request, f'Log file {log_file} not found')
        except Exception as e:
            messages.error(request, f'Error clearing log file: {str(e)}')
        
        return self.log_viewer_view(request)

    def has_module_permission(self, request):
        return request.user.is_superuser

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False