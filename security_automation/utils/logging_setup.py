import os
import logging

def setup_logging(base_dir):
    """Setup logging directories and basic configuration"""
    
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(base_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create individual log files
    log_files = ['debug.log', 'services.log', 'error.log']
    for log_file in log_files:
        log_path = os.path.join(logs_dir, log_file)
        # Create the file if it doesn't exist
        if not os.path.exists(log_path):
            with open(log_path, 'w') as f:
                f.write('')
            
    print(f"Logging setup completed. Log files created in: {logs_dir}")
    return logs_dir