# automation/views.py

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
import logging
import threading

from .models import ScanWorkflow, ScanTask, ScheduledTask, Notification
from .serializers import (
    WorkflowSerializer, WorkflowCreateSerializer,
    ScanTaskSerializer, ScheduledTaskSerializer,
    NotificationSerializer
)
from .workflow_orchestrator import WorkflowOrchestrator
from .scheduler import ScanScheduler

logger = logging.getLogger(__name__)

class WorkflowViewSet(viewsets.ModelViewSet):
    """
    API endpoint for scan workflows
    """
    queryset = ScanWorkflow.objects.all().order_by('-created_at')
    serializer_class = WorkflowSerializer
    # Removed authentication requirement
    
    def get_serializer_class(self):
        if self.action == 'create':
            return WorkflowCreateSerializer
        return WorkflowSerializer
    
    def perform_create(self, serializer):
        """Create a new workflow using the orchestrator"""
        # Save the model first
        workflow = serializer.save()
        
        # Set up the workflow with tasks and dependencies
        orchestrator = WorkflowOrchestrator()
        
        # Set target and other values for the existing workflow
        workflow.target = workflow.target
        workflow.name = workflow.name
        workflow.scan_profile = workflow.scan_profile
        workflow.scheduled_time = workflow.scheduled_time
        workflow.notification_email = workflow.notification_email
        workflow.save()
        
        # Setup tasks for the existing workflow instead of creating a new one
        orchestrator.setup_workflow(
            workflow=workflow,
            target=workflow.target,
            scan_profile=workflow.scan_profile
        )
        
        # If it's not scheduled, start it immediately
        if not workflow.scheduled_time:
            # Run in background thread to avoid blocking the API response
            threading.Thread(
                target=orchestrator.start_workflow,
                args=(workflow.id,),
                daemon=True
            ).start()
    
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a workflow"""
        workflow = self.get_object()
        
        # Check if workflow can be started
        if workflow.status not in ['pending', 'scheduled']:
            return Response(
                {'error': f"Cannot start workflow in '{workflow.status}' status"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Start the workflow
        orchestrator = WorkflowOrchestrator()
        
        # Run in background thread
        threading.Thread(
            target=orchestrator.start_workflow,
            args=(workflow.id,),
            daemon=True
        ).start()
        
        return Response({'status': 'starting workflow'})
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a workflow"""
        workflow = self.get_object()
        
        # Check if workflow can be cancelled
        if workflow.status in ['completed', 'failed', 'canceled']:
            return Response(
                {'error': f"Cannot cancel workflow in '{workflow.status}' status"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Cancel the workflow
        orchestrator = WorkflowOrchestrator()
        success = orchestrator.cancel_workflow(workflow.id)
        
        if success:
            return Response({'status': 'workflow canceled'})
        else:
            return Response(
                {'error': 'Failed to cancel workflow'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """Get detailed workflow status"""
        workflow = self.get_object()
        
        orchestrator = WorkflowOrchestrator()
        workflow_status = orchestrator.get_workflow_status(workflow.id)
        
        return Response(workflow_status)
    
    @action(detail=True, methods=['get'])
    def tasks(self, request, pk=None):
        """Get tasks for a workflow"""
        workflow = self.get_object()
        tasks = ScanTask.objects.filter(workflow=workflow).order_by('order')
        serializer = ScanTaskSerializer(tasks, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def notifications(self, request, pk=None):
        """Get notifications for a workflow"""
        workflow = self.get_object()
        notifications = Notification.objects.filter(workflow=workflow).order_by('-created_at')
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

class ScheduledTaskViewSet(viewsets.ModelViewSet):
    """
    API endpoint for scheduled tasks
    """
    queryset = ScheduledTask.objects.all().order_by('-created_at')
    serializer_class = ScheduledTaskSerializer
    # Removed authentication requirement
    
    def perform_create(self, serializer):
        """Create a new scheduled task"""
        # Add the current user as creator if provided in request data
        if not serializer.validated_data.get('created_by') and hasattr(self.request, 'user') and self.request.user.is_authenticated:
            serializer.validated_data['created_by'] = self.request.user.username
            
        serializer.save()
    
    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable a scheduled task"""
        scheduler = ScanScheduler()
        success = scheduler.enable_scheduled_task(pk)
        
        if success:
            return Response({'status': 'scheduled task enabled'})
        else:
            return Response(
                {'error': 'Failed to enable scheduled task'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def disable(self, request, pk=None):
        """Disable a scheduled task"""
        scheduler = ScanScheduler()
        success = scheduler.disable_scheduled_task(pk)
        
        if success:
            return Response({'status': 'scheduled task disabled'})
        else:
            return Response(
                {'error': 'Failed to disable scheduled task'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def run_now(self, request, pk=None):
        """Run a scheduled task immediately"""
        scheduled_task = self.get_object()
        
        # Create and start a workflow
        orchestrator = WorkflowOrchestrator()
        scheduler = ScanScheduler()
        
        try:
            # Create workflow with name including "manual run"
            name = f"{scheduled_task.name} - Manual Run - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
            
            workflow = orchestrator.create_workflow(
                target=scheduled_task.target,
                name=name,
                scan_profile=scheduled_task.scan_profile,
                notify_email=scheduled_task.notification_email
            )
            
            # Start workflow in background
            threading.Thread(
                target=orchestrator.start_workflow,
                args=(workflow.id,),
                daemon=True
            ).start()
            
            # Update scheduled task
            scheduled_task.last_execution = timezone.now()
            scheduled_task.last_status = 'started'
            scheduled_task.last_workflow = workflow
            scheduled_task.save()
            
            return Response({
                'status': 'scheduled task triggered',
                'workflow_id': workflow.id
            })
        
        except Exception as e:
            logger.error(f"Error running scheduled task: {str(e)}")
            return Response(
                {'error': f"Failed to run scheduled task: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TaskViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing scan tasks
    """
    queryset = ScanTask.objects.all().order_by('-created_at')
    serializer_class = ScanTaskSerializer
    # Removed authentication requirement
    
    @action(detail=True, methods=['get'])
    def result(self, request, pk=None):
        """Get task result data"""
        task = self.get_object()
        
        if not task.result:
            return Response({'result': None})
        
        import json
        try:
            result_data = json.loads(task.result)
            return Response(result_data)
        except json.JSONDecodeError:
            return Response(
                {'error': 'Invalid result data'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing notifications
    """
    queryset = Notification.objects.all().order_by('-created_at')
    serializer_class = NotificationSerializer
    # Removed authentication requirement