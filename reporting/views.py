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

            if not target:
                return JsonResponse({
                    'error': 'Target is required'
                }, status=400)

            # Generate and save the report
            report = self.generator.generate_report(report_type, target)

            return JsonResponse({
                'status': 'success',
                'message': 'Report generated successfully',
                'report_id': report.id,
                'report_type': report_type,
                'report_title': report.title
            })

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
                'report_type': report.report_type
            }
            
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

def download_pdf_view(request, report_id):
    """Generate and download a PDF version of the report"""
    report = get_object_or_404(Report, id=report_id)
    
    try:
        # Parse the JSON content
        import json
        report_data = json.loads(report.content)
        
        # Get workflow info if available
        workflow_id = request.GET.get('workflow_id')
        workflow = None
        tasks = []
        task_results = []
        
        if workflow_id:
            from automation.models import ScanWorkflow, ScanTask
            try:
                workflow = ScanWorkflow.objects.get(id=workflow_id)
                tasks = ScanTask.objects.filter(workflow_id=workflow_id).order_by('order')
                
                # Collect task results
                for task in tasks:
                    result_data = {}
                    if task.result:
                        try:
                            result_data = json.loads(task.result)
                        except:
                            result_data = {'error': 'Invalid JSON result'}
                    
                    task_results.append({
                        'id': task.id,
                        'name': task.name,
                        'type': task.task_type,
                        'status': task.status,
                        'start_time': task.start_time,
                        'end_time': task.end_time,
                        'duration': task.duration,
                        'result_data': result_data
                    })
            except ScanWorkflow.DoesNotExist:
                pass
        
        # Render HTML content for PDF
        html_string = render_to_string('reporting/pdf_report.html', {
            'report': report,
            'report_data': report_data,
            'workflow': workflow,
            'tasks': tasks,
            'task_results': task_results
        })
        
        # Create PDF from HTML
        html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
        result = html.write_pdf()
        
        # Create response with PDF content
        response = HttpResponse(result, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{report_id}.pdf"'
        return response
        
    except Exception as e:
        logger.error(f"Error generating PDF for report {report_id}: {str(e)}")
        return HttpResponse(f"Error generating PDF: {str(e)}", status=500)    

def view_html_report(request, report_id):
    """View an HTML report"""
    report = get_object_or_404(Report, id=report_id)
    
    try:
        # Parse the JSON content
        import json
        report_data = json.loads(report.content)
        
        # Render the report using a template
        return render(request, 'reporting/html_report.html', {
            'report': report,
            'report_data': report_data
        })
    except:
        # If JSON parsing fails, just display the raw content
        return HttpResponse(f"<pre>{report.content}</pre>")
    
def comprehensive_html_report(request, report_id):
    """View a comprehensive HTML report that includes all phase results"""
    report = get_object_or_404(Report, id=report_id)
    
    try:
        # Parse the JSON content
        import json
        report_data = json.loads(report.content)
        
        # Get the workflow id from the URL query parameter
        workflow_id = request.GET.get('workflow_id')
        
        # If workflow_id provided, fetch all task results
        if workflow_id:
            from automation.models import ScanWorkflow, ScanTask
            
            try:
                workflow = ScanWorkflow.objects.get(id=workflow_id)
                tasks = ScanTask.objects.filter(workflow_id=workflow_id).order_by('order')
                
                # Collect all task results
                task_results = []
                for task in tasks:
                    result_data = {}
                    if task.result:
                        try:
                            result_data = json.loads(task.result)
                        except:
                            result_data = {'error': 'Invalid JSON result'}
                    
                    task_results.append({
                        'id': task.id,
                        'name': task.name,
                        'type': task.task_type,
                        'status': task.status,
                        'start_time': task.start_time,
                        'end_time': task.end_time,
                        'duration': task.duration,
                        'result_data': result_data
                    })
                
                # Render the comprehensive report
                return render(request, 'reporting/comprehensive_report.html', {
                    'report': report,
                    'report_data': report_data,
                    'workflow': workflow,
                    'tasks': tasks,
                    'task_results': task_results
                })
                
            except ScanWorkflow.DoesNotExist:
                # Fall back to regular report if workflow not found
                pass
        
        # Default to standard report if no workflow_id or workflow not found
        return render(request, 'reporting/html_report.html', {
            'report': report,
            'report_data': report_data
        })
    except Exception as e:
        logger.error(f"Error rendering comprehensive report: {str(e)}")
        # If JSON parsing fails, just display the raw content
        return HttpResponse(f"<pre>{report.content}</pre>")