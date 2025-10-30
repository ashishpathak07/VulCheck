import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<a href=javascript:alert('XSS')>click</a>",
            "<div onmouseover=alert('XSS')>hover</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<math href=javascript:alert('XSS')>test</math>",
            "javascript:alert('XSS')",
            "JaVaScRiPt:alert('XSS')",
            "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;"
        ]

    def scan(self, target_url):
        vulnerabilities = []
        
        try:
            # Test URL parameters
            vulnerabilities.extend(self.test_url_parameters(target_url))
            
            # Test form parameters
            vulnerabilities.extend(self.test_forms(target_url))
            
        except Exception as e:
            vulnerabilities.append({
                'name': 'Scan Error',
                'description': f'Error during XSS scan: {str(e)}',
                'severity': 'Info',
                'location': target_url,
                'payload': '',
                'recommendation': 'Check target URL accessibility'
            })
        
        return vulnerabilities

    def test_url_parameters(self, url):
        vulnerabilities = []
        parsed_url = urlparse(url)
        query_params = {}
        
        if parsed_url.query:
            from urllib.parse import parse_qs
            query_params = parse_qs(parsed_url.query)
        
        # If no parameters, add test parameters
        if not query_params:
            test_params = {'q': 'search', 'name': 'test', 'message': 'hello'}
        else:
            test_params = {key: value[0] for key, value in query_params.items()}
        
        for param_name, original_value in test_params.items():
            for payload in self.payloads:
                try:
                    # Create test URL with payload
                    test_params_copy = test_params.copy()
                    test_params_copy[param_name] = payload
                    
                    # Reconstruct URL with payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params_copy.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    if self.detect_xss_success(response.text, payload):
                        vulnerabilities.append({
                            'name': 'Cross-Site Scripting (XSS)',
                            'description': f'XSS vulnerability detected in parameter: {param_name}',
                            'severity': 'High',
                            'location': test_url,
                            'payload': payload,
                            'recommendation': 'Implement proper output encoding and input validation'
                        })
                        break  # Stop testing this parameter if vulnerability found
                        
                except requests.RequestException:
                    continue
        
        return vulnerabilities

    def test_forms(self, url):
        vulnerabilities = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action')
                form_method = form.get('method', 'get').lower()
                form_url = urljoin(url, form_action) if form_action else url
                
                # Find all input fields
                inputs = form.find_all('input')
                textareas = form.find_all('textarea')
                form_data = {}
                
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    
                    if input_name and input_type not in ['submit', 'button', 'hidden']:
                        form_data[input_name] = 'test'
                
                for textarea in textareas:
                    textarea_name = textarea.get('name')
                    if textarea_name:
                        form_data[textarea_name] = 'test'
                
                # Test each input field with XSS payloads
                for field_name in form_data.keys():
                    for payload in self.payloads:
                        try:
                            test_data = form_data.copy()
                            test_data[field_name] = payload
                            
                            if form_method == 'post':
                                response = requests.post(form_url, data=test_data, timeout=10, verify=False)
                            else:
                                response = requests.get(form_url, params=test_data, timeout=10, verify=False)
                            
                            if self.detect_xss_success(response.text, payload):
                                vulnerabilities.append({
                                    'name': 'Cross-Site Scripting (XSS)',
                                    'description': f'XSS vulnerability detected in form field: {field_name}',
                                    'severity': 'High',
                                    'location': form_url,
                                    'payload': payload,
                                    'recommendation': 'Implement proper output encoding and input validation'
                                })
                                break  # Stop testing this field if vulnerability found
                                
                        except requests.RequestException:
                            continue
                            
        except Exception as e:
            # Silently continue if form parsing fails
            pass
        
        return vulnerabilities

    def detect_xss_success(self, response_text, payload):
        # Check if payload appears in response without proper encoding
        if payload in response_text:
            return True
        
        # Check for decoded entities
        decoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if decoded_payload not in response_text and payload not in response_text:
            # Payload was modified/encoded, likely safe
            return False
        
        # Check for script tags or event handlers in response
        script_patterns = [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=',
            r'javascript:',
            r'<iframe[^>]*>',
            r'<img[^>]*onerror='
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False