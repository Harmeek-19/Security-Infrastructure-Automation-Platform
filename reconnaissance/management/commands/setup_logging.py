from django.core.management.base import BaseCommand
from django.conf import settings
import os

class Command(BaseCommand):
    help = 'Sets up logging directories and files'

    def handle(self, *args, **options):
        logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        
        try:
            # Create logs directory
            os.makedirs(logs_dir, exist_ok=True)
            self.stdout.write(self.style.SUCCESS(f'Created logs directory at {logs_dir}'))
            
            # Create log files
            log_files = ['debug.log', 'services.log', 'error.log']
            for log_file in log_files:
                log_path = os.path.join(logs_dir, log_file)
                if not os.path.exists(log_path):
                    with open(log_path, 'w') as f:
                        f.write('')
                    self.stdout.write(self.style.SUCCESS(f'Created log file: {log_file}'))
                else:
                    self.stdout.write(self.style.WARNING(f'Log file already exists: {log_file}'))
                    
            # Set appropriate permissions
            for root, dirs, files in os.walk(logs_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
                    
            self.stdout.write(self.style.SUCCESS('Logging setup completed successfully'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error setting up logging: {str(e)}'))