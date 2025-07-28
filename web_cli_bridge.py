#!/usr/bin/env python3
"""
Simple Web-CLI Bridge for EndPointHawk
Provides a clean web interface that calls the CLI backend directly
This avoids all Flask environment conflicts while providing web accessibility
"""

import subprocess
import sys
import json
import os
import re
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import threading
import time

class EndPointHawkHandler(BaseHTTPRequestHandler):
    def _validate_repo_path(self, repo_path: str) -> bool:
        """
        Validate repository path to prevent command injection and path traversal.
        
        Args:
            repo_path: User-provided repository path
            
        Returns:
            True if path is safe
        """
        if not repo_path:
            return False
        
        # Remove any shell metacharacters that could be used for injection
        dangerous_chars = ['|', '&', ';', '$', '`', '(', ')', '<', '>', '"', "'", '\\']
        if any(char in repo_path for char in dangerous_chars):
            return False
        
        # Ensure path exists and is a directory
        try:
            path = Path(repo_path).resolve()
            return path.exists() and path.is_dir()
        except (OSError, ValueError):
            return False
    
    def _sanitize_repo_path(self, repo_path: str) -> str:
        """
        Sanitize repository path for safe subprocess execution.
        
        Args:
            repo_path: User-provided repository path
            
        Returns:
            Sanitized path
        """
        # Convert to absolute path and resolve any .. components
        try:
            return str(Path(repo_path).resolve())
        except (OSError, ValueError):
            raise ValueError(f"Invalid repository path: {repo_path}")

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = '''
<!DOCTYPE html>
<html>
<head>
    <title>EndPointHawk Web-CLI Bridge</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .form-group { margin: 20px 0; }
        input[type="text"] { width: 500px; padding: 10px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .results { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .loading { color: #007bff; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 EndPointHawk Web-CLI Bridge</h1>
        <p>Direct interface to the CLI backend - No Flask conflicts!</p>
        
        <div class="form-group">
            <label for="repo_path">Repository Path:</label><br>
            <input type="text" id="repo_path" placeholder="/path/to/your/repository" value="/path/to/your/repository">
        </div>
        
        <div class="form-group">
            <label>
                <input type="checkbox" id="use_ai"> Use AI Analysis
            </label>
        </div>
        
        <button onclick="startScan()">🚀 Start CLI Scan</button>
        
        <div id="results" class="results" style="display: none;">
            <h3>Scan Results:</h3>
            <div id="output"></div>
        </div>
    </div>

    <script>
        async function startScan() {
            const repoPath = document.getElementById('repo_path').value;
            const useAI = document.getElementById('use_ai').checked;
            
            if (!repoPath) {
                alert('Please enter a repository path');
                return;
            }
            
            const resultsDiv = document.getElementById('results');
            const outputDiv = document.getElementById('output');
            
            resultsDiv.style.display = 'block';
            outputDiv.innerHTML = '<div class="loading">🔄 Scanning repository...</div>';
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        repo_path: repoPath,
                        use_ai: useAI
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    outputDiv.innerHTML = `
                        <div class="success">
                            <h4>✅ Scan completed successfully!</h4>
                            <p><strong>Total routes:</strong> ${result.total_routes}</p>
                            <p><strong>High risk routes:</strong> ${result.high_risk_routes}</p>
                            <p><strong>Medium risk routes:</strong> ${result.medium_risk_routes}</p>
                            <p><strong>Low risk routes:</strong> ${result.low_risk_routes}</p>
                            <p><strong>Services found:</strong> ${result.services_found}</p>
                            <p><strong>Scan duration:</strong> ${result.scan_duration.toFixed(2)}s</p>
                            <p><strong>Frameworks detected:</strong> ${result.frameworks_detected.join(', ')}</p>
                        </div>
                    `;
                } else {
                    outputDiv.innerHTML = `
                        <div class="error">
                            <h4>❌ Scan failed</h4>
                            <p><strong>Error:</strong> ${result.error}</p>
                            <p><strong>Type:</strong> ${result.error_type}</p>
                        </div>
                    `;
                }
            } catch (error) {
                outputDiv.innerHTML = `
                    <div class="error">
                        <h4>❌ Network error</h4>
                        <p>${error.message}</p>
                    </div>
                `;
            }
        }
    </script>
</body>
</html>
            '''
            
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def do_POST(self):
        if self.path == '/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                repo_path = data.get('repo_path', '')
                use_ai = data.get('use_ai', False)
                
                # Validate repository path
                if not self._validate_repo_path(repo_path):
                    self.send_error_response({
                        'success': False,
                        'error': 'Invalid repository path',
                        'error_type': 'ValidationError'
                    })
                    return
                
                # Sanitize path
                try:
                    sanitized_path = self._sanitize_repo_path(repo_path)
                except ValueError as e:
                    self.send_error_response({
                        'success': False,
                        'error': str(e),
                        'error_type': 'ValidationError'
                    })
                    return
                
                # Build command
                cmd = [
                    sys.executable, 'endpointhawk.py',
                    '--repo-path', sanitized_path,
                    '--output-format', 'json',
                    '--output-dir', 'reports'
                ]
                
                if use_ai:
                    cmd.append('--use-ai')
                
                # Run the scan
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout
                    )
                    
                    if result.returncode == 0:
                        # Parse JSON output
                        try:
                            scan_data = json.loads(result.stdout)
                            self.send_json_response(scan_data)
                        except json.JSONDecodeError:
                            # Fallback to parsing terminal output
                            self.send_json_response({
                                'success': True,
                                'message': 'Scan completed successfully',
                                'output': result.stdout
                            })
                    else:
                        self.send_error_response({
                            'success': False,
                            'error': result.stderr,
                            'error_type': 'ScanError'
                        })
                        
                except subprocess.TimeoutExpired:
                    self.send_error_response({
                        'success': False,
                        'error': 'Scan timed out after 5 minutes',
                        'error_type': 'TimeoutError'
                    })
                except Exception as e:
                    self.send_error_response({
                        'success': False,
                        'error': str(e),
                        'error_type': type(e).__name__
                    })
                    
            except json.JSONDecodeError:
                self.send_error_response({
                    'success': False,
                    'error': 'Invalid JSON data',
                    'error_type': 'JSONError'
                })
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def send_json_response(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_error_response(self, error_data):
        self.send_response(400)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())

def run_server(port=8182):
    """Run the web server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, EndPointHawkHandler)
    print(f"🌐 EndPointHawk Web-CLI Bridge running on http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server() 