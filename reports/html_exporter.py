import logging
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

from models import ScanResult

class HTMLExporter:
    """
    Export scan results to HTML format.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def export(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Export scan result to HTML file.
        """
        try:
            self.logger.info("Starting HTML export...")
            
            # Generate HTML content
            self.logger.info("Generating HTML content...")
            html_content = self._generate_html(scan_result)
            
            self.logger.info("Writing HTML file...")
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report exported to {output_path}")
            return True
            
        except Exception as e:
            import traceback
            self.logger.error(f"Error exporting HTML report: {e}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    def _generate_html(self, scan_result: ScanResult) -> str:
        """
        Generate HTML content for the scan result.
        """
        # Calculate stats
        total_routes = len(scan_result.routes)
        high_risk = len([r for r in scan_result.routes if str(r.risk_level) == 'HIGH'])
        medium_risk = len([r for r in scan_result.routes if str(r.risk_level) == 'MEDIUM'])
        low_risk = len([r for r in scan_result.routes if str(r.risk_level) == 'LOW'])
        
        frameworks = list(set(str(route.framework) for route in scan_result.routes))
        
        # CSS styles as a separate string to avoid f-string parsing issues
        css_styles = """
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { text-align: center; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
        .metric h3 { margin: 0; color: #2c3e50; }
        .metric .value { font-size: 2em; font-weight: bold; color: #e74c3c; }
        .routes { margin-top: 20px; }
        .route { border: 1px solid #ddd; margin-bottom: 15px; padding: 15px; border-radius: 5px; }
        .route-header { font-weight: bold; color: #2c3e50; margin-bottom: 10px; }
        .risk-HIGH { border-left: 5px solid #e74c3c; }
        .risk-MEDIUM { border-left: 5px solid #f39c12; }
        .risk-LOW { border-left: 5px solid #27ae60; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .route-row.risk-HIGH { background-color: #fdf2f2; }
        .route-row.risk-MEDIUM { background-color: #fdf9f2; }
        .route-row.risk-LOW { background-color: #f2f9f2; }
        """
        
        # Generate route rows
        route_rows = self._generate_route_rows(scan_result.routes[:100])  # Limit to first 100 for HTML
        
        # Build HTML using regular string formatting
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>EndPointHawk Attack Surface Report</title>
    <style>{css_styles}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 EndPointHawk Attack Surface Report</h1>
            <p>Security Analysis Results</p>
        </div>
        
        <div class="summary">
            <div class="metric">
                <h3>Total Routes</h3>
                <div class="value">{total_routes}</div>
            </div>
            <div class="metric">
                <h3>High Risk</h3>
                <div class="value">{high_risk}</div>
            </div>
            <div class="metric">
                <h3>Medium Risk</h3>
                <div class="value">{medium_risk}</div>
            </div>
            <div class="metric">
                <h3>Low Risk</h3>
                <div class="value">{low_risk}</div>
            </div>
        </div>
        
        <div class="routes">
            <h2>Detected Routes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Framework</th>
                        <th>Risk Level</th>
                        <th>Auth Type</th>
                        <th>Location</th>
                        <th>Findings</th>
                        <th>Commit Info</th>
                    </tr>
                </thead>
                <tbody>
                    {route_rows}
                </tbody>
            </table>
        </div>
        
        <div class="summary">
            <h3>Frameworks Detected: {', '.join(frameworks)}</h3>
        </div>
    </div>
</body>
</html>"""
        
        return html_content
    
    def _generate_route_rows(self, routes) -> str:
        """
        Generate HTML table rows for routes.
        """
        rows = []
        for route in routes:
            findings_count = len(route.security_findings)
            findings_text = f"{findings_count} findings" if findings_count > 0 else "No findings"
            
            # Generate commit info cell
            commit_info = ""
            if hasattr(route, 'commit_author') and route.commit_author:
                commit_date = route.commit_date.strftime('%Y-%m-%d') if hasattr(route, 'commit_date') and route.commit_date else 'N/A'
                commit_info = f"""
                <div><strong>Author:</strong> {route.commit_author}</div>
                <div><strong>Date:</strong> {commit_date}</div>
                <div><strong>Hash:</strong> {getattr(route, 'commit_hash', 'N/A')[:8] if getattr(route, 'commit_hash', '') else 'N/A'}</div>
                """
            
            row = f"""
            <tr class="route-row risk-{str(route.risk_level)}">
                <td>{str(route.method)}</td>
                <td>{route.path}</td>
                <td>{str(route.framework)}</td>
                <td>{str(route.risk_level)}</td>
                <td>{str(route.auth_type)}</td>
                <td>{route.file_path}:{route.line_number}</td>
                <td>{findings_text}</td>
                <td>{commit_info}</td>
            </tr>
            """
            rows.append(row)
        
        return '\n'.join(rows)
    
    def _generate_service_rows(self, services) -> str:
        """
        Generate HTML table rows for services.
        """
        rows = []
        for service in services:
            framework = str(service.framework) if service.framework else 'Unknown'
            row = f"""
            <tr>
                <td>{service.name}</td>
                <td>{service.path}</td>
                <td>{framework}</td>
                <td>{service.language}</td>
                <td>{service.route_count}</td>
            </tr>
            """
            rows.append(row)
        
        return '\n'.join(rows) 