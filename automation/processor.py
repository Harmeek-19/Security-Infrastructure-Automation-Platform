# automation/processor.py

import threading
import time
import logging
from django.conf import settings
from django.db import connection

from .workflow_orchestrator import WorkflowOrchestrator
from .scheduler import ScanScheduler

logger = logging.getLogger(__name__)

class AutomationProcessor:
    """
    Process automation workflows and scheduled tasks in the background.
    Implemented as a singleton to ensure only one instance is running.
    """
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        """Get or create the singleton instance"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        self.orchestrator = WorkflowOrchestrator()
        self.scheduler = ScanScheduler()
        self.stop_flag = threading.Event()
        self.processing_thread = None
        self.interval = getattr(settings, 'AUTOMATION_PROCESSING_INTERVAL', 60)  # seconds
    
    def start(self):
        """Start the background processing thread if not already running"""
        if self.processing_thread and self.processing_thread.is_alive():
            logger.warning("Automation processor already running")
            return False
            
        self.stop_flag.clear()
        self.processing_thread = threading.Thread(
            target=self._processing_loop,
            daemon=True
        )
        self.processing_thread.start()
        logger.info("Automation processor started")
        return True
    
    def stop(self):
        """Stop the background processing thread"""
        if not self.processing_thread or not self.processing_thread.is_alive():
            logger.warning("Automation processor not running")
            return False
            
        self.stop_flag.set()
        self.processing_thread.join(timeout=10)
        logger.info("Automation processor stopped")
        return True
    
    def is_running(self):
        """Check if the processor is running"""
        return self.processing_thread is not None and self.processing_thread.is_alive()
    
    def _processing_loop(self):
        """Main processing loop for automation tasks"""
        logger.info("Automation processing loop started")
        
        while not self.stop_flag.is_set():
            try:
                # Process scheduled tasks
                scheduled_count = self.scheduler.process_scheduled_tasks()
                if scheduled_count > 0:
                    logger.info(f"Processed {scheduled_count} scheduled tasks")
                
                # Start pending workflows
                started_count = self.orchestrator.check_pending_workflows()
                if started_count > 0:
                    logger.info(f"Started {started_count} pending workflows")
                
                # Process workflow queue
                processed_count = self.orchestrator.process_workflow_queue()
                if processed_count > 0:
                    logger.info(f"Processed {processed_count} workflow tasks")
                
            except Exception as e:
                logger.error(f"Error in automation processing: {str(e)}")
            finally:
                # Close database connections to prevent connection leaks
                connection.close()
            
            # Sleep until next interval
            self.stop_flag.wait(self.interval)
        
        logger.info("Automation processing loop stopped")
    
    @classmethod
    def run_once(cls):
        """
        Run a single cycle of the processor, useful for cron jobs or manual triggers
        """
        processor = cls()
        
        try:
            # Process scheduled tasks
            scheduled_count = processor.scheduler.process_scheduled_tasks()
            
            # Start pending workflows
            started_count = processor.orchestrator.check_pending_workflows()
            
            # Process workflow queue
            processed_count = processor.orchestrator.process_workflow_queue()
            
            return {
                'scheduled_tasks_processed': scheduled_count,
                'workflows_started': started_count,
                'tasks_processed': processed_count
            }
            
        except Exception as e:
            logger.error(f"Error in one-time automation processing: {str(e)}")
            return {
                'error': str(e)
            }
        finally:
            # Close database connections
            connection.close()