# automation/management/commands/run_automation.py

import time
import logging
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone
from datetime import datetime, timedelta

from automation.workflow_orchestrator import WorkflowOrchestrator
from automation.scheduler import ScanScheduler

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Run the security automation system with scheduling and workflow processing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--daemon', 
            action='store_true',
            help='Run continuously in daemon mode'
        )
        parser.add_argument(
            '--interval', 
            type=int,
            default=60,
            help='Interval in seconds between daemon runs'
        )
        parser.add_argument(
            '--one-time',
            action='store_true',
            help='Process all current pending workflows and scheduled tasks, then exit'
        )
        parser.add_argument(
            '--only-scheduler',
            action='store_true',
            help='Only run the scheduler component'
        )
        parser.add_argument(
            '--only-workflows',
            action='store_true',
            help='Only process pending workflows'
        )

    def handle(self, *args, **options):
        daemon_mode = options.get('daemon', False)
        interval = options.get('interval', 60)
        one_time = options.get('one_time', False)
        only_scheduler = options.get('only_scheduler', False)
        only_workflows = options.get('only_workflows', False)
        
        # Initialize components
        orchestrator = WorkflowOrchestrator()
        scheduler = ScanScheduler()
        
        self.stdout.write(self.style.SUCCESS(f"Starting security automation system"))
        
        if daemon_mode:
            self.stdout.write(f"Running in daemon mode with {interval} second interval")
            self._run_daemon(orchestrator, scheduler, interval, only_scheduler, only_workflows)
        elif one_time:
            self.stdout.write("Running in one-time mode")
            self._run_once(orchestrator, scheduler, only_scheduler, only_workflows)
        else:
            self.stdout.write("Running in one-time mode (default)")
            self._run_once(orchestrator, scheduler, only_scheduler, only_workflows)
    
    def _run_once(self, orchestrator, scheduler, only_scheduler, only_workflows):
        """Run the automation components once and exit"""
        try:
            # Process scheduled tasks
            if not only_workflows:
                scheduled_tasks = scheduler.process_scheduled_tasks()
                self.stdout.write(f"Processed {scheduled_tasks} scheduled tasks")
            
            # Process workflows
            if not only_scheduler:
                # Start pending workflows
                started_workflows = orchestrator.check_pending_workflows()
                self.stdout.write(f"Started {started_workflows} pending workflows")
                
                # Process workflow queue
                processed_tasks = orchestrator.process_workflow_queue()
                self.stdout.write(f"Processed {processed_tasks} workflow tasks")
                
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Error in automation system: {str(e)}"))
        finally:
            # Close database connections
            connection.close()
    
    def _run_daemon(self, orchestrator, scheduler, interval, only_scheduler, only_workflows):
        """Run the automation components in daemon mode"""
        try:
            while True:
                start_time = time.time()
                self.stdout.write(f"Running automation cycle at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                try:
                    # Process scheduled tasks
                    if not only_workflows:
                        scheduled_tasks = scheduler.process_scheduled_tasks()
                        if scheduled_tasks > 0:
                            self.stdout.write(f"Processed {scheduled_tasks} scheduled tasks")
                    
                    # Process workflows
                    if not only_scheduler:
                        # Start pending workflows
                        started_workflows = orchestrator.check_pending_workflows()
                        if started_workflows > 0:
                            self.stdout.write(f"Started {started_workflows} pending workflows")
                        
                        # Process workflow queue
                        processed_tasks = orchestrator.process_workflow_queue()
                        if processed_tasks > 0:
                            self.stdout.write(f"Processed {processed_tasks} workflow tasks")
                    
                except Exception as e:
                    self.stderr.write(self.style.ERROR(f"Error in automation cycle: {str(e)}"))
                finally:
                    # Close database connections
                    connection.close()
                
                # Calculate sleep time to maintain interval
                elapsed = time.time() - start_time
                sleep_time = max(0, interval - elapsed)
                
                if sleep_time > 0:
                    self.stdout.write(f"Sleeping for {sleep_time:.2f} seconds...")
                    time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS("\nAutomation system gracefully stopped"))