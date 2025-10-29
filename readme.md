# VulCheck - A basic vulnerability assessment tool for web applications.

## Features : 
  - SQL Injection scanning
  - XSS (Cross-Site Scripting) detection
  - CSRF vulnerability checking
  - Simple web interface
  - REST API

## Quick Start
  Using Docker - 
    docker-compose up --build
## Local Installation -
  pip install -r requirements.txt
  python app.py
  Then open http://localhost:5000

## Usage
  Go to "New Scan"
  Enter target URL (e.g., http://testphp.vulnweb.com)
  Select scan types
  Click "Start Scan"
  View results
  
## API
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://example.com", "scan_types": ["sql", "xss"]}'

## Project Structure

vulcheck/<br>
├── app.py              # Main app <br>
├── requirements.txt    # Dependencies <br>
├── Dockerfile         # Docker config <br>
├── templates/         # HTML pages <br>
└── modules/           # Scanner modules <br>



