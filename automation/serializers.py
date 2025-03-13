# automation/serializers.py

from rest_framework import serializers
from django.utils import timezone
from .models import ScanWorkflow, ScanTask, ScheduledTask, Notification

class ScanTaskSerializer(serializers.ModelSerializer):
    """Serializer for scan tasks"""
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanTask
        fields = [
            'id', 'task_type', 'name', 'status', 'order', 'start_time', 
            'end_time', 'result', 'duration', 'created_at'
        ]
        read_only_fields = fields
    
    def get_duration(self, obj):
        """Calculate task duration"""
        if obj.start_time and obj.end_time:
            return (obj.end_time - obj.start_time).total_seconds()
        return None

class WorkflowSerializer(serializers.ModelSerializer):
    """Serializer for scan workflows"""
    tasks = ScanTaskSerializer(many=True, read_only=True)
    progress = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanWorkflow
        fields = [
            'id', 'name', 'target', 'scan_profile', 'status', 'created_at',
            'scheduled_time', 'start_time', 'end_time', 'notification_email',
            'metadata', 'tasks', 'progress', 'duration'
        ]
        read_only_fields = [
            'id', 'created_at', 'start_time', 'end_time', 'tasks', 
            'progress', 'duration'
        ]
    
    def get_progress(self, obj):
        """Calculate workflow progress percentage"""
        tasks = obj.tasks.all()
        total_tasks = tasks.count()
        if total_tasks == 0:
            return 0
            
        completed_tasks = tasks.filter(
            status__in=['completed', 'skipped', 'canceled']
        ).count()
        
        return int(completed_tasks / total_tasks * 100)
    
    def get_duration(self, obj):
        """Calculate workflow duration"""
        if obj.start_time and obj.end_time:
            return (obj.end_time - obj.start_time).total_seconds()
        return None

class WorkflowCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating scan workflows"""
    
    class Meta:
        model = ScanWorkflow
        fields = [
            'name', 'target', 'scan_profile', 'scheduled_time', 
            'notification_email'
        ]
    
    def validate_scheduled_time(self, value):
        """Ensure scheduled time is in the future"""
        if value and value < timezone.now():
            raise serializers.ValidationError("Scheduled time must be in the future")
        return value
    
    def validate_scan_profile(self, value):
        """Validate scan profile"""
        valid_profiles = [choice[0] for choice in ScanWorkflow.PROFILE_CHOICES]
        if value not in valid_profiles:
            raise serializers.ValidationError(
                f"Invalid scan profile. Valid options are: {', '.join(valid_profiles)}"
            )
        return value

class ScheduledTaskSerializer(serializers.ModelSerializer):
    """Serializer for scheduled tasks"""
    last_workflow_status = serializers.SerializerMethodField()
    next_run = serializers.SerializerMethodField()
    
    class Meta:
        model = ScheduledTask
        fields = [
            'id', 'name', 'target', 'scan_profile', 'frequency', 
            'cron_expression', 'start_date', 'end_date', 'is_active',
            'notification_email', 'created_at', 'created_by',
            'last_execution', 'last_status', 'last_workflow',
            'last_workflow_status', 'next_run'
        ]
        read_only_fields = [
            'id', 'created_at', 'last_execution', 'last_status',
            'last_workflow', 'last_workflow_status', 'next_run'
        ]
    
    def get_last_workflow_status(self, obj):
        """Get status of the last workflow"""
        if obj.last_workflow:
            return obj.last_workflow.status
        return None
    
    def get_next_run(self, obj):
        """Calculate next run time"""
        from .scheduler import ScanScheduler
        scheduler = ScanScheduler()
        next_run = scheduler._calculate_next_run(obj)
        if next_run:
            return next_run.isoformat()
        return None
    
    def validate_frequency(self, value):
        """Validate frequency"""
        valid_frequencies = [choice[0] for choice in ScheduledTask.FREQUENCY_CHOICES]
        if value not in valid_frequencies:
            raise serializers.ValidationError(
                f"Invalid frequency. Valid options are: {', '.join(valid_frequencies)}"
            )
        return value
    
    def validate(self, data):
        """Validate that cron expression is provided for custom frequency"""
        if data.get('frequency') == 'custom' and not data.get('cron_expression'):
            raise serializers.ValidationError(
                {"cron_expression": "Cron expression is required for custom frequency"}
            )
        return data

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""
    
    class Meta:
        model = Notification
        fields = [
            'id', 'workflow', 'notification_type', 'recipient',
            'subject', 'message', 'created_at', 'sent', 'sent_time'
        ]
        read_only_fields = fields