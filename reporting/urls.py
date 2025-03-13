from django.urls import path
from . import views

urlpatterns = [
    path('generate/', views.GenerateReportView.as_view(), name='generate-report'),
    path('list/', views.ReportListView.as_view(), name='report-list'),
    path('view/<int:report_id>/', views.view_html_report, name='view_html_report'),
    path('comprehensive/<int:report_id>/', views.comprehensive_html_report, name='comprehensive_report'),
    path('download/<int:report_id>/', views.DownloadReportView.as_view(), name='download-report'),
    path('download/<int:report_id>/pdf/', views.download_pdf_view, name='download_pdf')
]