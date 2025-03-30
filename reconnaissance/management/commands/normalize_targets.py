# reconnaissance/management/commands/normalize_targets.py

from django.core.management.base import BaseCommand
from vulnerability.models import Vulnerability, NucleiFinding
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Normalize all target URLs in the vulnerability database'

    def normalize_target(self, target_str):
        """Normalize target URL to consistent format"""
        if not target_str:
            return target_str
            
        # Remove protocol prefix
        if '://' in target_str:
            target_str = target_str.split('://', 1)[1]
        
        # Remove path, trailing slash, etc.
        if '/' in target_str:
            target_str = target_str.split('/', 1)[0]
            
        # Remove port if present
        if ':' in target_str:
            target_str = target_str.split(':', 1)[0]
            
        # Remove 'www.' prefix if present
        if target_str.startswith('www.'):
            target_str = target_str[4:]
            
        return target_str.lower()

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting target normalization...'))
        
        # Get all unique targets
        targets = Vulnerability.objects.values_list('target', flat=True).distinct()
        
        # Map of original targets to normalized versions
        target_mapping = {}
        for target in targets:
            normalized = self.normalize_target(target)
            target_mapping[target] = normalized
        
        # Group targets by normalized version
        normalized_groups = {}
        for original, normalized in target_mapping.items():
            if normalized not in normalized_groups:
                normalized_groups[normalized] = []
            normalized_groups[normalized].append(original)
        
        # Process each group of targets that normalize to the same value
        updates = 0
        for normalized, originals in normalized_groups.items():
            # Skip if there's only one version and it's already normalized
            if len(originals) == 1 and originals[0] == normalized:
                continue
                
            # Update all vulnerabilities for these targets
            for original in originals:
                count = Vulnerability.objects.filter(target=original).update(target=normalized)
                updates += count
                self.stdout.write(f"Updated {count} vulnerabilities from '{original}' to '{normalized}'")
            
            # Also update NucleiFinding targets if they exist
            for original in originals:
                count = NucleiFinding.objects.filter(target=original).update(target=normalized)
                if count > 0:
                    self.stdout.write(f"Updated {count} nuclei findings from '{original}' to '{normalized}'")
                    updates += count
        
        # Run deduplication after normalization
        for normalized in normalized_groups.keys():
            stats = Vulnerability.deduplicate_vulnerabilities(normalized)
            self.stdout.write(f"Deduplication for '{normalized}': {stats}")
        
        self.stdout.write(self.style.SUCCESS(f'Successfully normalized {updates} records'))