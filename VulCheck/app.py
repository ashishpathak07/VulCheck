from flask import Flask, render_template, request, jsonify, session
import json
import time
from modules.sql_injection import SQLInjectionScanner
from modules.xss_scanner import XSSScanner
from modules.csrf_detector import CSRFDetector

app = Flask(__name__)
app.secret_key = 'vulcheck_secret_key_2025'

# Initialize scanners
sql_scanner = SQLInjectionScanner()
xss_scanner = XSSScanner()
csrf_detector = CSRFDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        scan_type = request.form.getlist('scan_type')
        
        if not target_url:
            return render_template('scan.html', error="Please provide a target URL")
        
        # Store scan parameters in session
        session['target_url'] = target_url
        session['scan_type'] = scan_type
        
        return render_template('scan.html', 
                             target_url=target_url, 
                             scan_type=scan_type,
                             message="Scan parameters saved. Click 'Start Scan' to begin.")
    
    return render_template('scan.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    target_url = session.get('target_url')
    scan_types = session.get('scan_type', [])
    
    if not target_url:
        return jsonify({'error': 'No target URL specified'})
    
    results = {
        'target_url': target_url,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'vulnerabilities': []
    }
    
    # Perform scans based on selected types
    if 'sql' in scan_types:
        sql_results = sql_scanner.scan(target_url)
        results['vulnerabilities'].extend(sql_results)
    
    if 'xss' in scan_types:
        xss_results = xss_scanner.scan(target_url)
        results['vulnerabilities'].extend(xss_results)
    
    if 'csrf' in scan_types:
        csrf_results = csrf_detector.scan(target_url)
        results['vulnerabilities'].extend(csrf_results)
    
    # Store results in session
    session['scan_results'] = results
    
    return jsonify(results)

@app.route('/results')
def results():
    results = session.get('scan_results', {})
    return render_template('results.html', results=results)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target_url = data.get('target_url')
    scan_types = data.get('scan_types', ['sql', 'xss', 'csrf'])
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'})
    
    results = {
        'target_url': target_url,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'vulnerabilities': []
    }
    
    # Perform scans
    if 'sql' in scan_types:
        sql_results = sql_scanner.scan(target_url)
        results['vulnerabilities'].extend(sql_results)
    
    if 'xss' in scan_types:
        xss_results = xss_scanner.scan(target_url)
        results['vulnerabilities'].extend(xss_results)
    
    if 'csrf' in scan_types:
        csrf_results = csrf_detector.scan(target_url)
        results['vulnerabilities'].extend(csrf_results)
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)