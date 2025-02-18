from django.urls import path
from . import views

urlpatterns = [
    path('generate/', views.GenerateReportView.as_view(), name='generate-report'),
    path('list/', views.ReportListView.as_view(), name='report-list'),
    path('download/<int:report_id>/', views.DownloadReportView.as_view(), name='download-report'),
]