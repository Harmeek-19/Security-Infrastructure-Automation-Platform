from django import template
from django.utils.safestring import mark_safe
import json

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """
    Get an item from a dictionary or list by index/key
    
    Usage: {{ dictionary|get_item:key }}
    """
    if isinstance(dictionary, list):
        try:
            return dictionary[int(key)]
        except (IndexError, ValueError):
            return None
    elif isinstance(dictionary, dict):
        return dictionary.get(key)
    return None

@register.filter
def get_attr(obj, attr):
    """Get an attribute from an object"""
    if obj is None:
        return None
    return getattr(obj, attr, None)

@register.filter
def json_pretty(data):
    """
    Format JSON data in a readable way
    
    Usage: {{ data|json_pretty }}
    """
    if not data:
        return "No data"
        
    try:
        # If it's already a string, try to load it as JSON
        if isinstance(data, str):
            data = json.loads(data)
            
        # Pretty print with indentation
        return json.dumps(data, indent=2)
    except:
        # If it's not valid JSON or there's an error, return as is
        return data

@register.filter
def to_json(value):
    """Convert value to JSON string safely for use in JavaScript"""
    try:
        return mark_safe(json.dumps(value))
    except Exception as e:
        return '{}'

@register.filter
def severity_class(severity):
    """Convert severity level to CSS class"""
    severity = severity.lower() if severity else ""
    if severity in ["critical", "high"]:
        return "danger"
    elif severity == "medium":
        return "warning"
    elif severity == "low":
        return "info"
    return "secondary"

@register.filter
def status_class(status):
    """Convert task status to CSS class"""
    status = status.lower() if status else ""
    if status == "completed":
        return "success"
    elif status == "failed":
        return "danger"
    elif status == "in_progress":
        return "primary"
    elif status == "skipped":
        return "secondary"
    return "light"

# reporting/templatetags/report_filters.py




@register.filter
def multiply(value, arg):
    """
    Multiply the value by the argument
    
    Usage: {{ value|multiply:100 }}
    """
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0