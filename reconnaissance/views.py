from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Count, Q
from django.utils import timezone
from .models import Service, Subdomain, PortScan
from .service_identifier import ServiceIdentifier
import json
import logging
from .subdomain_enumerator import SubdomainEnumerator
from .scanner import PortScanner, ScanType
logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class SubdomainScanView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enumerator = SubdomainEnumerator()
        
    def get(self, request):
        try:
            target = request.GET.get('target')
            if not target:
                return JsonResponse({'error': 'Target parameter is required'}, status=400)
                
            subdomains = Subdomain.objects.filter(domain=target).values(
                'subdomain', 'ip_address', 'discovered_date', 'is_active'
            )
            
            return JsonResponse({
                'status': 'success',
                'target': target,
                'subdomains': list(subdomains)
            })
        except Exception as e:
            logger.error(f"Error retrieving subdomains: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

    def post(self, request):
        try:
            data = json.loads(request.body)
            domain = data.get('domain')
            
            if not domain:
                return JsonResponse({'error': 'Domain is required'}, status=400)
            
            # Perform actual subdomain enumeration
            discovered = self.enumerator.enumerate_subdomains(domain)
            
            # Save results to database
            saved_subdomains = []
            for subdomain_data in discovered:
                subdomain, created = Subdomain.objects.update_or_create(
                    domain=domain,
                    subdomain=subdomain_data['subdomain'],
                    defaults={
                        'ip_address': subdomain_data['ip_address'],
                        'is_active': True
                    }
                )
                saved_subdomains.append({
                    'id': subdomain.id,
                    'subdomain': subdomain.subdomain,
                    'ip_address': subdomain.ip_address,
                    'status': 'created' if created else 'updated'
                })
            
            return JsonResponse({
                'status': 'success',
                'message': 'Subdomain scan completed',
                'domain': domain,
                'total_subdomains': len(saved_subdomains),
                'subdomains': saved_subdomains
            })
        except Exception as e:
            logger.error(f"Subdomain scan error: {str(e)}")
            return JsonResponse({
                'error': str(e)
            }, status=500)

class SubdomainListView(View):
    def get(self, request):
        try:
            domain = request.GET.get('domain')
            query = Subdomain.objects.all()
            
            if domain:
                query = query.filter(domain=domain)
            
            subdomains = query.values('id', 'domain', 'subdomain', 
                                    'ip_address', 'discovered_date')
            
            return JsonResponse({
                'status': 'success',
                'subdomains': list(subdomains)
            })
        except Exception as e:
            logger.error(f"Error listing subdomains: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

class SubdomainDetailView(View):
    def get(self, request, subdomain_id):
        try:
            subdomain = Subdomain.objects.get(id=subdomain_id)
            return JsonResponse({
                'status': 'success',
                'subdomain': {
                    'id': subdomain.id,
                    'domain': subdomain.domain,
                    'subdomain': subdomain.subdomain,
                    'ip_address': subdomain.ip_address,
                    'discovered_date': subdomain.discovered_date.isoformat(),
                    'is_active': subdomain.is_active
                }
            })
        except Subdomain.DoesNotExist:
            return JsonResponse({'error': 'Subdomain not found'}, status=404)
        except Exception as e:
            logger.error(f"Error retrieving subdomain details: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class PortScanView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scanner = PortScanner()
        self.logger = logging.getLogger(__name__)

    def post(self, request):
        try:
            data = json.loads(request.body)
            target = data.get('target')
            scan_type = data.get('scan_type', 'quick')
            custom_ports = data.get('ports')

            if not target:
                return JsonResponse({'error': 'Target is required'}, status=400)

            if scan_type not in ScanType.__members__ and not custom_ports:
                return JsonResponse({
                    'error': f'Invalid scan type. Available types: {", ".join(ScanType.__members__.keys())}'
                }, status=400)

            # Start the scan
            self.logger.info(f"Starting {scan_type} port scan for {target}")
            scan_result = self.scanner.scan(target, scan_type)

            if scan_result['status'] == 'success':
                saved_ports = []
                
                # Process and save results
                for host in scan_result['results']:
                    for port_data in host['ports']:
                        scan = PortScan.objects.create(
                            host=target,
                            port=port_data['port'],
                            service=port_data['service'],
                            state=port_data['state'],
                            protocol='tcp',
                            scan_status='completed',
                            scan_type=scan_type,
                            banner=port_data.get('extrainfo', ''),
                            notes=f"Version: {port_data.get('version', 'unknown')}"
                        )
                        saved_ports.append({
                            'port': scan.port,
                            'state': scan.state,
                            'service': scan.service
                        })

                return JsonResponse({
                    'status': 'success',
                    'message': f'Port scan completed for {target}',
                    'target': target,
                    'scan_type': scan_type,
                    'total_ports': len(saved_ports),
                    'open_ports': len([p for p in saved_ports if p['state'] == 'open']),
                    'ports': saved_ports,
                    'scan_time': scan_result['scan_info']['scan_time']
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'error': scan_result.get('error', 'Unknown error during scan')
                }, status=500)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            self.logger.error(f"Port scan error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

    def get(self, request):
        """Get scan results for a target"""
        try:
            target = request.GET.get('target')
            if not target:
                return JsonResponse({'error': 'Target parameter is required'}, status=400)

            scans = PortScan.objects.filter(
                host=target, 
                scan_status='completed'
            ).values(
                'port', 'service', 'state', 'protocol', 
                'banner', 'scan_date'
            ).order_by('port')

            return JsonResponse({
                'status': 'success',
                'target': target,
                'total_ports': len(scans),
                'open_ports': scans.filter(state='open').count(),
                'ports': list(scans)
            })

        except Exception as e:
            self.logger.error(f"Error retrieving port scan results: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

    def _estimate_scan_time(self, scan_type, ports):
        """Estimate scan time based on scan type and ports"""
        if scan_type == 'quick':
            return "1-2 minutes"
        elif scan_type == 'partial':
            return "5-10 minutes"
        elif scan_type == 'complete':
            return "30-60 minutes"
        elif scan_type == 'full':
            return "1-2 hours"
        else:
            # Custom port range
            port_count = len(ports.split(','))
            if port_count < 100:
                return "1-5 minutes"
            elif port_count < 1000:
                return "5-15 minutes"
            else:
                return "15+ minutes"

class PortScanListView(View):
    def get(self, request):
        try:
            host = request.GET.get('host')
            state = request.GET.get('state')
            
            query = PortScan.objects.all()
            if host:
                query = query.filter(host=host)
            if state:
                query = query.filter(state=state)
                
            scans = query.values('id', 'host', 'port', 'service', 
                               'state', 'protocol', 'scan_date')
            
            return JsonResponse({
                'status': 'success',
                'scans': list(scans)
            })
        except Exception as e:
            logger.error(f"Error listing port scans: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

class PortScanDetailView(View):
    def get(self, request, scan_id):
        try:
            scan = PortScan.objects.get(id=scan_id)
            return JsonResponse({
                'status': 'success',
                'scan': {
                    'id': scan.id,
                    'host': scan.host,
                    'port': scan.port,
                    'service': scan.service,
                    'state': scan.state,
                    'protocol': scan.protocol,
                    'scan_date': scan.scan_date.isoformat(),
                    'banner': scan.banner,
                    'notes': scan.notes
                }
            })
        except PortScan.DoesNotExist:
            return JsonResponse({'error': 'Scan not found'}, status=404)
        except Exception as e:
            logger.error(f"Error retrieving scan details: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class ServiceScanView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identifier = ServiceIdentifier()
        self.logger = logging.getLogger(__name__)

    def post(self, request):
        try:
            data = json.loads(request.body)
            target = data.get('target')
            scan_type = data.get('scan_type', 'standard')

            if not target:
                return JsonResponse({'error': 'Target is required'}, status=400)

            # Start service identification
            self.logger.info(f"Starting {scan_type} service scan for {target}")
            results = self.identifier.identify_services(target, scan_type)

            if results['status'] == 'success':
                # Save discovered services
                saved_services = []
                for service_data in results['services']:
                    try:
                        service, created = Service.objects.update_or_create(
                            host=target,
                            port=service_data['port'],
                            protocol=service_data['protocol'],
                            defaults={
                                'name': service_data['service']['name'],
                                'product': service_data['service']['product'],
                                'version': service_data['service']['version'],
                                'extra_info': service_data['service'].get('extrainfo', ''),
                                'category': service_data['category'],
                                'risk_level': service_data['risk_level'],
                                'cpe': service_data['service'].get('cpe', [])
                            }
                        )
                        saved_services.append({
                            'id': service.id,
                            'port': service.port,
                            'name': service.name,
                            'version': service.version,
                            'risk_level': service.risk_level,
                            'status': 'created' if created else 'updated'
                        })
                    except Exception as e:
                        self.logger.error(f"Error saving service: {str(e)}")

                return JsonResponse({
                    'status': 'success',
                    'message': f"Service scan completed for {target}",
                    'target': target,
                    'total_services': len(saved_services),
                    'services': saved_services,
                    'scan_stats': results['scan_stats']
                })

            return JsonResponse({
                'status': 'error',
                'error': results.get('error', 'Unknown error'),
                'details': results.get('details', '')
            }, status=500)

        except Exception as e:
            self.logger.error(f"Service scan error: {str(e)}")
            return JsonResponse({
                'error': str(e)
            }, status=500)

    def get(self, request):
        try:
            target = request.GET.get('target')
            if not target:
                return JsonResponse({'error': 'Target parameter is required'}, status=400)
            
            # Get all services for target
            services = Service.objects.filter(host=target).values(
                'id', 'port', 'protocol', 'name', 'product',
                'version', 'category', 'risk_level', 'last_seen'
            )

            # Group by risk level
            risk_summary = {
                'HIGH': services.filter(risk_level='HIGH').count(),
                'MEDIUM': services.filter(risk_level='MEDIUM').count(),
                'LOW': services.filter(risk_level='LOW').count()
            }

            return JsonResponse({
                'status': 'success',
                'target': target,
                'services': list(services),
                'risk_summary': risk_summary,
                'total_services': len(services)
            })

        except Exception as e:
            self.logger.error(f"Error retrieving services: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

class ServiceListView(View):
    def get(self, request):
        try:
            category = request.GET.get('category')
            risk_level = request.GET.get('risk_level')
            
            query = Service.objects.all()
            if category:
                query = query.filter(category=category)
            if risk_level:
                query = query.filter(risk_level=risk_level)
                
            services = query.values('id', 'host', 'port', 'name', 
                                  'category', 'risk_level', 'last_seen')
            
            return JsonResponse({
                'status': 'success',
                'services': list(services)
            })
        except Exception as e:
            logger.error(f"Error listing services: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

class ServiceDetailView(View):
    def get(self, request, service_id):
        try:
            service = Service.objects.get(id=service_id)
            return JsonResponse({
                'status': 'success',
                'service': {
                    'id': service.id,
                    'host': service.host,
                    'port': service.port,
                    'protocol': service.protocol,
                    'name': service.name,
                    'product': service.product,
                    'version': service.version,
                    'category': service.category,
                    'risk_level': service.risk_level,
                    'extra_info': service.extra_info,
                    'cpe': service.cpe,
                    'last_seen': service.last_seen.isoformat()
                }
            })
        except Service.DoesNotExist:
            return JsonResponse({'error': 'Service not found'}, status=404)
        except Exception as e:
            logger.error(f"Error retrieving service details: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

class ScanStatisticsView(View):
    def get(self, request):
        try:
            # Get time range from request
            days = int(request.GET.get('days', 7))
            time_threshold = timezone.now() - timezone.timedelta(days=days)
            
            # Collect statistics
            stats = {
                'total_subdomains': Subdomain.objects.count(),
                'active_subdomains': Subdomain.objects.filter(is_active=True).count(),
                'total_services': Service.objects.count(),
                'services_by_risk': {
                    level: Service.objects.filter(risk_level=level).count()
                    for level, _ in Service.RISK_LEVELS
                },
                'services_by_category': {
                    category: Service.objects.filter(category=category).count()
                    for category, _ in Service.CATEGORIES
                },
                'recent_scans': {
                    'port_scans': PortScan.objects.filter(
                        scan_date__gte=time_threshold).count(),
                    'service_scans': Service.objects.filter(
                        scan_date__gte=time_threshold).count(),
                }
            }
            
            return JsonResponse({
                'status': 'success',
                'statistics': stats
            })
        except Exception as e:
            logger.error(f"Error generating statistics: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

class HostSummaryView(View):
    def get(self, request, host):
        try:
            # Collect host information
            summary = {
                'subdomains': list(Subdomain.objects.filter(
                    domain=host).values('subdomain', 'ip_address')),
                'services': list(Service.objects.filter(
                    host=host).values('port', 'name', 'risk_level')),
                'port_scans': list(PortScan.objects.filter(
                    host=host).values('port', 'state', 'service')),
                'risk_assessment': {
                    'high_risk_services': Service.objects.filter(
                        host=host, risk_level='HIGH').count(),
                    'open_ports': PortScan.objects.filter(
                        host=host, state='open').count(),
                }
            }
            
            return JsonResponse({
                'status': 'success',
                'host': host,
                'summary': summary
            })
            

        except Exception as e:
            logger.error(f"Error generating host summary: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
        
class ResultsView(View):
    def get(self, request):
        """Get all scan results for a target"""
        try:
            target = request.GET.get('target')
            if not target:
                return JsonResponse({'error': 'Target parameter is required'}, status=400)

            # Get subdomain results
            subdomains = Subdomain.objects.filter(domain=target).values(
                'subdomain', 'ip_address', 'discovered_date', 'is_active'
            )

            # Get port scan results
            ports = PortScan.objects.filter(host=target).values(
                'port', 'service', 'state', 'protocol', 'banner'
            )

            # Get service results
            services = Service.objects.filter(host=target).values(
                'port', 'name', 'product', 'version', 'category', 'risk_level'
            )

            return JsonResponse({
                'status': 'success',
                'target': target,
                'results': {
                    'subdomains': list(subdomains),
                    'ports': list(ports),
                    'services': list(services),
                    'summary': {
                        'total_subdomains': len(subdomains),
                        'open_ports': ports.filter(state='open').count(),
                        'high_risk_services': services.filter(risk_level='HIGH').count()
                    }
                }
            })

        except Exception as e:
            logger.error(f"Error retrieving results: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)