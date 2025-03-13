# automation/middleware.py

import logging
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger(__name__)

class AutomationProcessorMiddleware(MiddlewareMixin):
    """
    Middleware to automatically start the automation processor when Django starts.
    Only starts the processor if AUTOMATION_AUTOSTART=True in settings.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self.processor_started = False
        
        # Check if autostart is enabled
        autostart = getattr(settings, 'AUTOMATION_AUTOSTART', False)
        
        if autostart:
            self._start_processor()
    
    def _start_processor(self):
        """Start the automation processor if not already started"""
        if not self.processor_started:
            try:
                from .processor import AutomationProcessor
                processor = AutomationProcessor.get_instance()
                
                if not processor.is_running():
                    success = processor.start()
                    if success:
                        self.processor_started = True
                        logger.info("Automation processor automatically started")
                else:
                    self.processor_started = True
                    logger.info("Automation processor already running")
                    
            except Exception as e:
                logger.error(f"Error starting automation processor: {str(e)}")