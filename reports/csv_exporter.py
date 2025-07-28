import csv
import logging
from typing import List, Dict, Any
from pathlib import Path

from models import ScanResult, RouteInfo
from analyzers.duplicate_route_analyzer import DuplicateRouteAnalyzer

class CSVExporter:
    """
    Export scan results to CSV format.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def export(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Export scan result to CSV file.
        """
        try:
            # Prepare CSV data
            csv_data = self._prepare_csv_data(scan_result)
            
            # Define CSV columns (comprehensive set matching csv_extract.py)
            fieldnames = [
                'method', 'path', 'original_path', 'file_path', 'line_number', 'framework',
                'auth_type', 'authenticated', 'risk_level', 'risk_score',
                'risk_factors_count', 'risk_factors',
                'parameters_count', 'parameters', 'has_parameters',
                'security_findings_count', 'security_findings', 'security_types', 'has_security_issues',
                'service_name',
                # Enhanced duplicate analysis columns
                'duplicate_count', 'services', 'duplicate_type', 'primary_service', 
                'conflict_level', 'template_resolved', 'resolved_path',
                # Git commit information columns
                'commit_author', 'commit_author_email', 'commit_hash', 'commit_date', 'commit_message'
            ]
            
            # Write to CSV file
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_data)
            
            self.logger.info(f"CSV report exported to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting CSV report: {e}")
            return False
    
    def _prepare_csv_data(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """
        Convert scan results to CSV-ready data with enhanced duplicate analysis.
        """
        csv_data = []
        
        # Handle routes - prioritize direct routes list to avoid duplication
        routes_to_process = []
        
        # First, try to get routes directly from scan_result.routes (preferred)
        if hasattr(scan_result, 'routes') and scan_result.routes:
            for route in scan_result.routes:
                service_name = getattr(route, 'service_name', '')
                routes_to_process.append((route, service_name))
        
        # Only fall back to services if no direct routes available (avoid duplication)
        elif hasattr(scan_result, 'services') and scan_result.services:
            for service in scan_result.services:
                if hasattr(service, 'routes'):
                    for route in service.routes:
                        routes_to_process.append((route, service.name))
        
        self.logger.debug(f"Processing {len(routes_to_process)} routes for CSV export")
        
        # Perform duplicate analysis
        all_routes = [route for route, _ in routes_to_process]
        duplicate_analyzer = DuplicateRouteAnalyzer()
        duplicate_analysis = duplicate_analyzer.analyze_routes(all_routes)
        
        # Create lookup for duplicate information
        duplicate_lookup = {}
        for dup in duplicate_analysis:
            for route_instance in dup.route_instances:
                method_value = route_instance.method.value if hasattr(route_instance.method, 'value') else str(route_instance.method)
                key = (method_value, route_instance.path)
                duplicate_lookup[key] = dup
        
        # Process all routes with duplicate analysis
        for route, service_name in routes_to_process:
            # Get security findings as structured strings (safely)
            security_findings_list = []
            security_types = []
            security_findings = getattr(route, 'security_findings', [])
            for finding in security_findings:
                security_findings_list.append(f"{str(finding.severity)}: {finding.description}")
                security_types.append(finding.type)
            
            # Get parameters as structured strings
            parameters = getattr(route, 'parameters', [])
            parameter_names = [getattr(param, 'name', str(param)) for param in parameters]
            
            # Get risk factors if available
            risk_factors = getattr(route, 'risk_factors', [])
            
            # Get duplicate analysis information
            method_value = route.method.value if hasattr(route.method, 'value') else str(route.method)
            duplicate_info = duplicate_lookup.get((method_value, route.path))
            
            row = {
                'method': str(route.method) if route.method else '',
                'path': getattr(route, 'full_path', None) or route.path or '',  # Use resolved path when available
                'original_path': getattr(route, 'original_path', None) or route.path or '',  # Store original with variables
                'file_path': getattr(route, 'file_path', '') or '',
                'line_number': getattr(route, 'line_number', '') or '',
                'framework': str(route.framework) if route.framework else '',
                'auth_type': str(route.auth_type) if route.auth_type else '',
                'authenticated': 'Yes' if getattr(route, 'auth_required', getattr(route, 'authenticated', False)) else 'No',
                'risk_level': str(getattr(route, 'risk_level', '')),
                'risk_score': round(getattr(route, 'risk_score', 0), 2),
                'risk_factors_count': len(risk_factors),
                'risk_factors': '; '.join(risk_factors) if risk_factors else 'None',
                'parameters_count': len(parameters),
                'parameters': '; '.join(parameter_names) if parameter_names else 'None',
                'has_parameters': 'Yes' if parameters else 'No',
                'security_findings_count': len(security_findings),
                'security_findings': '; '.join(security_findings_list) if security_findings_list else 'None',
                'security_types': '; '.join(security_types) if security_types else 'None',
                'has_security_issues': 'Yes' if security_findings else 'No',
                'service_name': service_name or getattr(route, 'service_name', '') or '',
                # Enhanced duplicate analysis columns
                'duplicate_count': duplicate_info.duplicate_count if duplicate_info else 1,
                'services': '; '.join(duplicate_info.services) if duplicate_info else service_name or '',
                'duplicate_type': duplicate_info.duplicate_type.value if duplicate_info else 'unique',
                'primary_service': duplicate_info.primary_service if duplicate_info else service_name or '',
                'conflict_level': duplicate_info.conflict_level.value if duplicate_info else 'none',
                'template_resolved': 'Yes' if duplicate_info and duplicate_info.template_resolved else 'No',
                'resolved_path': getattr(route, 'full_path', None) or route.path or '',
                # Git commit information columns
                'commit_author': getattr(route, 'commit_author', '') or '',
                'commit_author_email': getattr(route, 'commit_author_email', '') or '',
                'commit_hash': getattr(route, 'commit_hash', '') or '',
                'commit_date': getattr(route, 'commit_date', '') or '',
                'commit_message': getattr(route, 'commit_message', '') or ''
            }
            
            csv_data.append(row)
        
        return csv_data 