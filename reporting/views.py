from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models import Report
from .report_generator import ReportGenerator
import json
from django.core.serializers.json import DjangoJSONEncoder

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

from django.http import JsonResponse, HttpResponse, FileResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.conf import settings
import json
import os
from datetime import datetime
import tempfile

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