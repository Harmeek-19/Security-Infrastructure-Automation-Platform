# automation/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'workflows', views.WorkflowViewSet)
router.register(r'scheduled-tasks', views.ScheduledTaskViewSet)
router.register(r'tasks', views.TaskViewSet)
router.register(r'notifications', views.NotificationViewSet)

app_name = 'automation'

urlpatterns = [
    # API routes
    path('api/', include(router.urls)),
    
    # Add this to the main urls.py
    # path('automation/', include('automation.urls')),
]