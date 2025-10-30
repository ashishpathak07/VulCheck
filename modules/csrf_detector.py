import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

class CSRFDetector:
    def __init__(self):
        self.csrf_token_names = [
            'csrf', 'csrf_token', 'csrfmiddlewaretoken', 
            'authenticity_token', 'token', '_token',
            'anticsrf', 'csrf-token'
        ]

    def scan(self, target_url):
        vulnerabilities = []
        
        try:
            # Check for forms without CSRF protection
            vulnerabilities.extend(self.check_forms(target_url))
            
        except Exception as e:
            vulnerabilities.append({
                'name': 'Scan Error',
                'description': f'Error during CSRF scan: {str(e)}',
                'severity': 'Info',
                'location': target_url,
                'payload': '',
                'recommendation': 'Check target URL accessibility'
            })
        
        return vulnerabilities

    def check_forms(self, url):
        vulnerabilities = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action')
                form_method = form.get('method', 'get').lower()
                form_url = urljoin(url, form_action) if form_action else url
                
                # Skip forms that are GET (less critical for CSRF)
                if form_method != 'post':
                    continue
                
                # Check if form has CSRF protection
                has_csrf_protection = self.has_csrf_token(form)
                
                if not has_csrf_protection:
                    vulnerabilities.append({
                        'name': 'CSRF Vulnerability',
                        'description': f'Form without CSRF protection detected',
                        'severity': 'Medium',
                        'location': form_url,
                        'payload': '',
                        'recommendation': 'Implement CSRF tokens and validate same-origin requests'
                    })
                
                # Check for SameSite cookie attribute
                cookie_vulnerability = self.check_cookie_security(response.headers)
                if cookie_vulnerability:
                    vulnerabilities.append(cookie_vulnerability)
                    
        except Exception as e:
            # Silently continue if form parsing fails
            pass
        
        return vulnerabilities

    def has_csrf_token(self, form):
        # Check for hidden input fields with CSRF token names
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        for input_field in hidden_inputs:
            input_name = input_field.get('name', '').lower()
            if any(token_name in input_name for token_name in self.csrf_token_names):
                return True
        
        # Check for meta tags with CSRF tokens
        meta_tags = form.find_all('meta', attrs={'name': True})
        for meta in meta_tags:
            meta_name = meta.get('name', '').lower()
            if any(token_name in meta_name for token_name in self.csrf_token_names):
                return True
        
        return False

    def check_cookie_security(self, headers):
        cookies = headers.get('Set-Cookie', '')
        
        # Check for Secure flag
        if 'secure' not in cookies.lower():
            return {
                'name': 'Insecure Cookie',
                'description': 'Cookies without Secure flag detected',
                'severity': 'Medium',
                'location': 'HTTP Headers',
                'payload': '',
                'recommendation': 'Set Secure flag for cookies transmitted over HTTPS'
            }
        
        # Check for HttpOnly flag
        if 'httponly' not in cookies.lower():
            return {
                'name': 'Cookie without HttpOnly',
                'description': 'Cookies without HttpOnly flag detected',
                'severity': 'Low',
                'location': 'HTTP Headers',
                'payload': '',
                'recommendation': 'Set HttpOnly flag to prevent XSS-based cookie theft'
            }
        
        # Check for SameSite attribute
        if 'samesite' not in cookies.lower():
            return {
                'name': 'Cookie without SameSite',
                'description': 'Cookies without SameSite attribute detected',
                'severity': 'Low',
                'location': 'HTTP Headers',
                'payload': '',
                'recommendation': 'Set SameSite attribute to Lax or Strict for CSRF protection'
            }
        
        return None