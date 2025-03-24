from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.template.loader import render_to_string
from django.conf import settings
from .models import Report
from .report_generator import ReportGenerator
import json
import os
import logging
import tempfile
from datetime import datetime
from django.core.serializers.json import DjangoJSONEncoder
from weasyprint import HTML, CSS

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class GenerateReportView(View):
    def __init__(self):
        super().__init__()
        self.generator = ReportGenerator()

    def post(self, request):
        try:
            data = json.loads(request.body)
            report_type = data.get('report_type', 'basic')
            target = data.get('target')
            workflow_id = data.get('workflow_id')  # Capture workflow_id if provided

            if not target:
                return JsonResponse({
                    'error': 'Target is required'
                }, status=400)

            # Generate and save the report
            report = self.generator.generate_report(report_type, target)

            response_data = {
                'status': 'success',
                'message': 'Report generated successfully',
                'report_id': report.id,
                'report_type': report_type,
                'report_title': report.title
            }
            
            # Add workflow_id to the response if it was provided
            if workflow_id:
                response_data['workflow_id'] = workflow_id
                
            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({
                'error': 'Report generation failed',
                'details': str(e)
            }, status=500)

class ReportListView(View):
    def get(self, request):
        reports = Report.objects.all().values(
            'id', 'title', 'creation_date', 'report_type'
        ).order_by('-creation_date')
        return JsonResponse(list(reports), safe=False)

@method_decorator(csrf_exempt, name='dispatch')
class DownloadReportView(View):
    def get(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            workflow_id = request.GET.get('workflow_id')  # Get workflow_id from request
            
            try:
                # Parse the stored JSON content
                report_content = json.loads(report.content)
            except json.JSONDecodeError as e:
                return JsonResponse({
                    'error': 'Invalid report format',
                    'details': str(e)
                }, status=500)
            
            # Format the complete report
            formatted_report = {
                'id': report.id,
                'title': report.title,
                'content': report_content,
                'creation_date': report.creation_date.isoformat(),
                'report_type': report.report_type,
            }
            
            # Add workflow_id if available
            if workflow_id:
                formatted_report['workflow_id'] = workflow_id
            
            # Handle download request
            if request.GET.get('download') == 'true':
                try:
                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
                        # Write formatted JSON to temp file
                        json.dump(formatted_report, tmp_file, indent=2, cls=DjangoJSONEncoder)
                    
                    # Prepare file response
                    filename = f"security_report_{report.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    response = FileResponse(
                        open(tmp_file.name, 'rb'),
                        content_type='application/json',
                        as_attachment=True,
                        filename=filename
                    )
                    
                    # Clean up temp file after response is sent
                    os.unlink(tmp_file.name)
                    
                    return response
                    
                except Exception as e:
                    return JsonResponse({
                        'error': 'Error creating download file',
                        'details': str(e)
                    }, status=500)
            
            # Return regular JSON response
            return JsonResponse(formatted_report)
            
        except Report.DoesNotExist:
            return JsonResponse({
                'error': 'Report not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'error': 'Error retrieving report',
                'details': str(e)
            }, status=500)

# File: reporting/views.py
def download_pdf_view(request, report_id):
        """Generate and download a PDF version of the report with proper port information"""
        report = get_object_or_404(Report, id=report_id)
        
        try:
            # Parse the JSON content
            import json
            report_data = json.loads(report.content)
            
            # Basic report info
            target = report_data.get('target', '')
            scan_date = report_data.get('scan_date', datetime.now().isoformat())
            report_date = datetime.now().strftime('%Y-%m-%d, %H:%M %p')
            
            # Initialize summary data
            summary = {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0,
                'open_ports_count': 0
            }
            
            # Update summary with data from report if available
            if 'summary' in report_data:
                for key, value in report_data['summary'].items():
                    if key in summary:
                        summary[key] = value
            
            # Get workflow ID from report_data first (if stored there) or from request parameters
            workflow_id = report_data.get('workflow_id') or request.GET.get('workflow_id')
            logger.info(f"PDF generation with workflow_id: {workflow_id}")
            
            # Initialize open ports list
            open_ports = report_data.get('open_ports', [])
            
            # If we have a workflow_id, try to get port data directly from task results
            if workflow_id:
                logger.info(f"Workflow ID provided: {workflow_id}")
                
                from automation.models import ScanTask
                
                # Get port scan task
                port_scan_task = ScanTask.objects.filter(
                    workflow_id=workflow_id,
                    task_type='port_scanning',
                    status='completed'
                ).first()
                
                # Get ports from task results if available
                task_ports = []
                if port_scan_task and port_scan_task.result:
                    try:
                        port_task_data = json.loads(port_scan_task.result)
                        logger.info(f"Port scan task data retrieved")
                        
                        # Extract open ports from task data
                        for host in port_task_data.get('results', []):
                            for port_info in host.get('ports', []):
                                if port_info.get('state') == 'open':
                                    # Add to open ports list
                                    task_ports.append({
                                        'port': port_info.get('port'),
                                        'service': port_info.get('service', ''),
                                        'protocol': 'tcp',
                                        'state': 'open'
                                    })
                        
                        logger.info(f"Found {len(task_ports)} open ports from task result")
                        
                        # Use task ports if we found any
                        if task_ports:
                            open_ports = task_ports
                            summary['open_ports_count'] = len(open_ports)
                        
                    except Exception as e:
                        logger.error(f"Error processing port scan task result: {str(e)}")
            
            # Log final data for debugging
            logger.info(f"PDF Report data - Target: {target}, Open ports: {len(open_ports)}, Vulnerabilities: {len(report_data.get('vulnerabilities', []))}")
            
            # Create context for PDF template
            context = {
                'report': report,
                'target': target,
                'report_date': report_date,
                'scan_date': scan_date,
                'summary': summary,
                'vulnerabilities': report_data.get('vulnerabilities', []),
                'open_ports': open_ports
            }
            
            # Render PDF template
            html_string = render_to_string('reporting/pdf_report.html', context)
            
            # Generate PDF
            base_url = request.build_absolute_uri('/')
            html = HTML(string=html_string, base_url=base_url)
            
            # Add custom CSS
            css = CSS(string='''
                @page {
                    size: letter;
                    margin: 1cm;
                    @bottom-right {
                        content: "Page " counter(page) " of " counter(pages);
                    }
                }
                body { font-size: 12px; }
                
                /* Table formatting */
                table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                
                /* Evidence box */
                .evidence-box { 
                    background-color: #f8f8f8; 
                    padding: 10px; 
                    margin: 10px 0; 
                    font-family: monospace;
                    white-space: pre-wrap;
                    font-size: 11px;
                    max-height: 300px;
                    overflow: hidden;
                }
            ''')
            
            result = html.write_pdf(stylesheets=[css])
            
            # Return PDF response
            response = HttpResponse(result, content_type='application/pdf')
            filename = f"security_report_{target}_{datetime.now().strftime('%Y%m%d')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating PDF for report {report_id}: {str(e)}", exc_info=True)
            return HttpResponse(f"Error generating PDF: {str(e)}", status=500)

def view_html_report(request, report_id):
    """View an HTML report"""
    report = get_object_or_404(Report, id=report_id)
    workflow_id = request.GET.get('workflow_id')  # Get workflow_id from request
    
    try:
        # Parse the JSON content
        import json
        report_data = json.loads(report.content)
        
        # Render the report using a template
        return render(request, 'reporting/html_report.html', {
            'report': report,
            'report_data': report_data,
            'workflow_id': workflow_id  # Pass workflow_id to template
        })
    except:
        # If JSON parsing fails, just display the raw content
        return HttpResponse(f"<pre>{report.content}</pre>")
    
def comprehensive_html_report(request, report_id):
    """View a comprehensive HTML report that includes all phase results"""
    report = get_object_or_404(Report, id=report_id)
    
    try:
        # Parse the JSON content with improved error handling
        import json
        try:
            report_data = json.loads(report.content)
            logger.info(f"Successfully parsed report data for report ID {report_id}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error for report ID {report_id}: {str(e)}")
            # Return raw content with error message for debugging
            error_message = f"Error parsing report JSON: {str(e)}"
            return HttpResponse(f"<h1>Error Rendering Report</h1><p>{error_message}</p><pre>{report.content}</pre>")
        
        # Get the workflow id from the URL query parameter
        workflow_id = request.GET.get('workflow_id')
        logger.info(f"Processing report with workflow_id={workflow_id}")
        
        # If workflow_id provided, fetch all task results
        workflow = None
        tasks = []
        task_results = []
        
        if workflow_id:
            from automation.models import ScanWorkflow, ScanTask
            
            try:
                workflow = ScanWorkflow.objects.get(id=workflow_id)
                tasks = ScanTask.objects.filter(workflow_id=workflow_id).order_by('order')
                logger.info(f"Found workflow {workflow_id} with {tasks.count()} tasks")
                
                # Collect all task results
                task_results = []
                for i, task in enumerate(tasks):
                    result_data = {}
                    if task.result:
                        try:
                            result_data = json.loads(task.result)
                            logger.info(f"Parsed task result for task {task.id} ({task.task_type})")
                        except json.JSONDecodeError as e:
                            logger.error(f"Error parsing task result for task {task.id}: {str(e)}")
                            result_data = {'error': f'Invalid JSON result: {str(e)}'}
                    
                    task_results.append({
                        'id': task.id,
                        'name': task.name,
                        'type': task.task_type,
                        'status': task.status,
                        'start_time': task.start_time,
                        'end_time': task.end_time,
                        'duration': task.end_time - task.start_time if task.start_time and task.end_time else None,
                        'result_data': result_data
                    })
                
                # Check if comprehensive_report.html template exists in the correct location
                from django.template.loader import get_template
                try:
                    template = get_template('reporting/comprehensive_report.html')
                    logger.info("Successfully located comprehensive report template")
                except Exception as e:
                    logger.error(f"Template error: {str(e)}")
                    # Check all template directories for debugging
                    from django.conf import settings
                    template_dirs = settings.TEMPLATES[0]['DIRS']
                    logger.error(f"Template directories: {template_dirs}")
                    return HttpResponse(f"<h1>Template Error</h1><p>Could not find template: {str(e)}</p>")
                
                # Render the comprehensive report
                context = {
                    'report': report,
                    'report_data': report_data,
                    'workflow': workflow,
                    'tasks': tasks,
                    'task_results': task_results,
                    'workflow_id': workflow_id  # Make sure to pass the workflow_id to template
                }
                
                # Log context summary for debugging
                logger.info(f"Report context: report_id={report_id}, workflow={workflow_id}, tasks={len(tasks)}, task_results={len(task_results)}")
                
                return render(request, 'reporting/comprehensive_report.html', context)
                
            except ScanWorkflow.DoesNotExist:
                logger.error(f"Workflow {workflow_id} not found")
                # Fall back to regular report if workflow not found
                return render(request, 'reporting/html_report.html', {
                    'report': report,
                    'report_data': report_data,
                    'error_message': f"Workflow with ID {workflow_id} not found"
                })
        
        # Default to standard report if no workflow_id or workflow not found
        logger.info(f"Rendering standard HTML report for report ID {report_id} (no workflow_id provided)")
        return render(request, 'reporting/html_report.html', {
            'report': report,
            'report_data': report_data
        })
    except Exception as e:
        logger.error(f"Error rendering comprehensive report: {str(e)}")
        # Return a more user-friendly error page with details
        return HttpResponse(
            f"<h1>Error Rendering Report</h1>"
            f"<p>An error occurred while rendering the report: {str(e)}</p>"
            f"<h2>Report Content</h2>"
            f"<pre>{report.content}</pre>"
        )