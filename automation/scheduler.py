# automation/scheduler.py

import logging
import json
from datetime import datetime, timedelta
from django.utils import timezone
from croniter import croniter

from .models import ScheduledTask, ScanWorkflow
from .workflow_orchestrator import WorkflowOrchestrator

logger = logging.getLogger(__name__)

class ScanScheduler:
    """
    Handles scheduling and execution of recurring security scans
    """
    
    def __init__(self):
        self.orchestrator = WorkflowOrchestrator()
    
    def process_scheduled_tasks(self) -> int:
        """
        Check for scheduled tasks that need to be triggered and create workflows
        
        Returns:
            int: Number of workflows created
        """
        now = timezone.now()
        active_schedules = ScheduledTask.objects.filter(is_active=True)
        
        workflows_created = 0
        
        for schedule in active_schedules:
            try:
                # Skip if end date is set and has passed
                if schedule.end_date and schedule.end_date < now.date():
                    continue
                
                # Determine next execution time
                next_run = self._calculate_next_run(schedule)
                
                # Check if it's time to run (or overdue)
                if next_run and next_run <= now:
                    # Create a new workflow
                    name = f"{schedule.name} - {now.strftime('%Y-%m-%d %H:%M')}"
                    
                    workflow = self.orchestrator.create_workflow(
                        target=schedule.target,
                        name=name,
                        scan_profile=schedule.scan_profile,
                        notify_email=schedule.notification_email
                    )
                    
                    # Start the workflow immediately
                    self.orchestrator.start_workflow(workflow.id)
                    
                    # Update the schedule's last execution
                    schedule.last_execution = now
                    schedule.last_status = 'started'
                    schedule.last_workflow = workflow
                    schedule.save()
                    
                    logger.info(f"Created scheduled workflow {workflow.id} for schedule {schedule.id}")
                    workflows_created += 1
            
            except Exception as e:
                logger.error(f"Error processing scheduled task {schedule.id}: {str(e)}")
        
        return workflows_created
    
    def _calculate_next_run(self, schedule: ScheduledTask) -> datetime:
        """
        Calculate the next run time for a scheduled task
        
        Args:
            schedule: The scheduled task
            
        Returns:
            datetime: Next execution time or None if cannot be determined
        """
        now = timezone.now()
        
        # If never run, use start_date as base
        if schedule.last_execution is None:
            base_time = datetime.combine(schedule.start_date, datetime.min.time())
            base_time = timezone.make_aware(base_time)
            
            # If start date is in future, return that
            if base_time > now:
                return base_time
        else:
            base_time = schedule.last_execution
        
        # Calculate next run based on frequency
        if schedule.frequency == 'daily':
            # Add 24 hours to last execution
            return base_time + timedelta(days=1)
            
        elif schedule.frequency == 'weekly':
            # Add 7 days to last execution
            return base_time + timedelta(days=7)
            
        elif schedule.frequency == 'monthly':
            # Add roughly a month (30 days) to last execution
            return base_time + timedelta(days=30)
            
        elif schedule.frequency == 'custom' and schedule.cron_expression:
            try:
                # Use croniter to calculate next run based on cron expression
                cron = croniter(schedule.cron_expression, base_time)
                return cron.get_next(datetime)
            except Exception as e:
                logger.error(f"Error parsing cron expression for schedule {schedule.id}: {str(e)}")
                return None
        
        return None
    
    def create_scheduled_task(self, name: str, target: str, frequency: str, 
                          start_date: datetime.date, end_date=None, 
                          scan_profile: str='standard', cron_expression=None, 
                          notification_email=None, created_by=None) -> ScheduledTask:
        """
        Create a new scheduled task
        
        Args:
            name: Name of the scheduled task
            target: Target domain/IP
            frequency: Frequency (daily, weekly, monthly, custom)
            start_date: Start date
            end_date: End date (optional)
            scan_profile: Scan profile (quick, standard, full)
            cron_expression: Cron expression for custom frequency
            notification_email: Email to notify
            created_by: User who created the schedule
            
        Returns:
            ScheduledTask: The created scheduled task
        """
        if frequency == 'custom' and not cron_expression:
            raise ValueError("Cron expression is required for custom frequency")
        
        scheduled_task = ScheduledTask.objects.create(
            name=name,
            target=target,
            frequency=frequency,
            start_date=start_date,
            end_date=end_date,
            scan_profile=scan_profile,
            cron_expression=cron_expression,
            notification_email=notification_email,
            created_by=created_by
        )
        
        logger.info(f"Created scheduled task {scheduled_task.id} for {target}")
        return scheduled_task
    
    def update_scheduled_task(self, task_id: int, **kwargs) -> ScheduledTask:
        """
        Update a scheduled task
        
        Args:
            task_id: ID of the task to update
            **kwargs: Fields to update
            
        Returns:
            ScheduledTask: The updated task
        """
        try:
            task = ScheduledTask.objects.get(id=task_id)
            
            # Update fields
            for field, value in kwargs.items():
                if hasattr(task, field):
                    setattr(task, field, value)
            
            task.save()
            logger.info(f"Updated scheduled task {task_id}")
            return task
            
        except ScheduledTask.DoesNotExist:
            logger.error(f"Scheduled task {task_id} not found")
            raise ValueError(f"Scheduled task {task_id} not found")
    
    def delete_scheduled_task(self, task_id: int) -> bool:
        """
        Delete a scheduled task
        
        Args:
            task_id: ID of the task to delete
            
        Returns:
            bool: True if successfully deleted
        """
        try:
            task = ScheduledTask.objects.get(id=task_id)
            task.delete()
            logger.info(f"Deleted scheduled task {task_id}")
            return True
            
        except ScheduledTask.DoesNotExist:
            logger.error(f"Scheduled task {task_id} not found")
            return False
    
    def disable_scheduled_task(self, task_id: int) -> bool:
        """
        Disable a scheduled task
        
        Args:
            task_id: ID of the task to disable
            
        Returns:
            bool: True if successfully disabled
        """
        try:
            task = ScheduledTask.objects.get(id=task_id)
            task.is_active = False
            task.save()
            logger.info(f"Disabled scheduled task {task_id}")
            return True
            
        except ScheduledTask.DoesNotExist:
            logger.error(f"Scheduled task {task_id} not found")
            return False
    
    def enable_scheduled_task(self, task_id: int) -> bool:
        """
        Enable a scheduled task
        
        Args:
            task_id: ID of the task to enable
            
        Returns:
            bool: True if successfully enabled
        """
        try:
            task = ScheduledTask.objects.get(id=task_id)
            task.is_active = True
            task.save()
            logger.info(f"Enabled scheduled task {task_id}")
            return True
            
        except ScheduledTask.DoesNotExist:
            logger.error(f"Scheduled task {task_id} not found")
            return False