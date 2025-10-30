import requests
from urllib.parse import urlparse

def is_url_accessible(url):
    """Check if a URL is accessible"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        return response.status_code == 200
    except:
        return False

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def sanitize_input(input_string):
    """Basic input sanitization"""
    if not input_string:
        return ""
    return input_string.strip()