from django import template
from django.utils.safestring import mark_safe
import json

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get an item from a dictionary or list using a key or index"""
    if dictionary is None:
        return None
    if isinstance(dictionary, list):
        try:
            index = int(key)
            if 0 <= index < len(dictionary):
                return dictionary[index]
            return None
        except (ValueError, IndexError):
            return None
    return dictionary.get(key)

@register.filter
def get_attr(obj, attr):
    """Get an attribute from an object"""
    if obj is None:
        return None
    return getattr(obj, attr, None)

@register.filter
def json_pretty(value):
    """Format JSON nicely"""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except:
            return value
    return json.dumps(value, indent=2)

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