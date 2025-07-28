import json
import logging
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

from models import ScanResult

class JSONExporter:
    """
    Export scan results to JSON format.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def export(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Export scan result to JSON file.
        """
        try:
            self.logger.info("Starting JSON export...")
            
            # Convert scan result to JSON-serializable format
            self.logger.info("Serializing scan result...")
            json_data = self._serialize_scan_result(scan_result)
            
            self.logger.info("Writing JSON file...")
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON report exported to {output_path}")
            return True
            
        except Exception as e:
            import traceback
            self.logger.error(f"Error exporting JSON report: {e}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    def _serialize_scan_result(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Convert ScanResult to serializable dictionary.
        """
        return {
            "scan_metadata": {
                "tool_name": "EndPointHawk Attack Surface Discovery Tool",
                "scan_timestamp": scan_result.scan_time.isoformat() if scan_result.scan_time else datetime.now().isoformat(),
                "total_routes": len(scan_result.routes),
                "total_services": len(scan_result.services),
                "scan_config": self._serialize_config(getattr(scan_result, 'config', None)) if hasattr(scan_result, 'config') and scan_result.config else None
            },
            "services": [self._serialize_service(service) for service in scan_result.services],
            "routes": [self._serialize_route(route) for route in scan_result.routes],
            "summary": {
                "frameworks_detected": list(set(str(route.framework) for route in scan_result.routes)),
                "risk_distribution": self._calculate_risk_distribution(scan_result.routes),
                "security_findings_count": sum(len(route.security_findings) for route in scan_result.routes),
                "technology_analytics": self._calculate_technology_analytics(scan_result.services),
                "service_classification": self._calculate_service_classification(scan_result.services),
                "business_criticality_distribution": self._calculate_criticality_distribution(scan_result.services)
            }
        }
    
    def _serialize_service(self, service) -> Dict[str, Any]:
        """
        Convert ServiceInfo to serializable dictionary with safe attribute access.
        """
        return {
            "name": getattr(service, 'name', ''),
            "path": getattr(service, 'path', ''),
            "framework": str(getattr(service, 'framework', '')),
            "routes": [self._serialize_route(route) for route in getattr(service, 'routes', [])],
            "route_count": len(getattr(service, 'routes', [])),
            "dependencies": getattr(service, 'dependencies', [])
        }
    
    def _serialize_route_summary(self, route) -> Dict[str, Any]:
        """
        Serialize route summary for service context.
        """
        return {
            "method": str(route.method),
            "path": route.path,
            "risk_level": str(route.risk_level),
            "auth_required": route.auth_required,
            "risk_score": getattr(route, 'risk_score', 0.0)
        }
    
    def _calculate_service_risk_summary(self, routes) -> Dict[str, Any]:
        """
        Calculate aggregated risk summary for a service.
        """
        if not routes:
            return {"high": 0, "medium": 0, "low": 0, "total": 0}
        
        risk_counts = {"high": 0, "medium": 0, "low": 0}
        
        for route in routes:
            risk_level = str(route.risk_level).lower()
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        return {
            **risk_counts,
            "total": len(routes)
        }
    
    def _serialize_route(self, route) -> Dict[str, Any]:
        """
        Serialize RouteInfo to dictionary.
        """
        route_data = {
            "method": str(route.method),
            "path": route.path,
            "file_path": route.file_path,
            "line_number": route.line_number,
            "framework": str(route.framework),
            "auth_type": str(route.auth_type),
            "risk_level": str(route.risk_level),
            "parameters": [self._serialize_parameter(param) for param in route.parameters],
            "security_findings": [self._serialize_finding(finding) for finding in route.security_findings],
            "metadata": route.metadata
        }
        
        # Add prefix information if available
        if hasattr(route, 'full_path') and route.full_path:
            route_data["full_path"] = route.full_path
        
        if hasattr(route, 'original_path') and route.original_path:
            route_data["original_path"] = route.original_path
        
        if hasattr(route, 'prefix_info') and route.prefix_info:
            route_data["prefix_info"] = {
                "framework": route.prefix_info.framework,
                "service": route.prefix_info.service,
                "infrastructure": route.prefix_info.infrastructure,
                "full": route.prefix_info.full,
                "source": route.prefix_info.source,
                "confidence": route.prefix_info.confidence,
                "conflicts": route.prefix_info.conflicts
            }
        
        if hasattr(route, 'prefix_breakdown') and route.prefix_breakdown:
            route_data["prefix_breakdown"] = {
                "infrastructure": route.prefix_breakdown.infrastructure,
                "service": route.prefix_breakdown.service,
                "api": route.prefix_breakdown.api,
                "route": route.prefix_breakdown.route
            }
        
        # Add commit information if available
        if hasattr(route, 'commit_author') and route.commit_author:
            route_data["commit_info"] = {
                "author": route.commit_author,
                "author_email": getattr(route, 'commit_author_email', ''),
                "hash": getattr(route, 'commit_hash', ''),
                "date": route.commit_date.isoformat() if hasattr(route, 'commit_date') and route.commit_date else None,
                "message": getattr(route, 'commit_message', '')
            }
        
        return route_data
    
    def _serialize_parameter(self, parameter) -> Dict[str, Any]:
        """
        Serialize RouteParameter to dictionary with safe attribute access.
        """
        return {
            "name": getattr(parameter, 'name', ''),
            "type": getattr(parameter, 'type', None),
            "required": getattr(parameter, 'required', True),
            "validation": getattr(parameter, 'validation', None)
        }
    
    def _serialize_finding(self, finding) -> Dict[str, Any]:
        """
        Serialize SecurityFinding to dictionary.
        """
        return {
            "type": finding.type,
            "severity": finding.severity,
            "description": finding.description,
            "location": finding.location,
            "recommendation": finding.recommendation if hasattr(finding, 'recommendation') else None
        }
    
    def _serialize_config(self, config) -> Dict[str, Any]:
        """
        Serialize ScanConfig to dictionary.
        """
        return {
            "target_paths": config.target_paths,
            "exclude_patterns": config.exclude_patterns,
            "include_patterns": config.include_patterns,
            "max_depth": config.max_depth,
            "enable_ai_analysis": config.enable_ai_analysis
        }
    
    def _calculate_risk_distribution(self, routes) -> Dict[str, int]:
        """
        Calculate distribution of risk levels.
        """
        distribution = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for route in routes:
            # Extract just the enum value part (e.g., 'HIGH' from 'RiskLevel.HIGH')
            risk_level_str = str(route.risk_level)
            if '.' in risk_level_str:
                risk_level = risk_level_str.split('.')[-1]  # Get part after the dot
            else:
                risk_level = risk_level_str
            
            if risk_level in distribution:
                distribution[risk_level] += 1
        return distribution
    
    def _calculate_technology_analytics(self, services) -> Dict[str, Any]:
        """
        Calculate technology stack analytics across all services.
        """
        tech_usage = {}
        database_technologies = set()
        messaging_technologies = set()
        external_integrations = set()
        
        for service in services:
            tech_stack = getattr(service, 'technology_stack', [])
            
            for tech in tech_stack:
                tech_usage[tech] = tech_usage.get(tech, 0) + 1
                
                # Categorize technologies
                tech_lower = tech.lower()
                if any(db in tech_lower for db in ['postgresql', 'mongodb', 'redis', 'mysql', 'typeorm']):
                    database_technologies.add(tech)
                elif any(msg in tech_lower for msg in ['kafka', 'sqs', 'bull', 'rabbitmq']):
                    messaging_technologies.add(tech)
                elif any(ext in tech_lower for ext in ['shopify', 'google', 'aws', 'slack', 'salesforce']):
                    external_integrations.add(tech)
        
        return {
            "technology_usage": dict(sorted(tech_usage.items(), key=lambda x: x[1], reverse=True)),
            "database_technologies": list(database_technologies),
            "messaging_technologies": list(messaging_technologies),
            "external_integrations": list(external_integrations),
            "total_unique_technologies": len(tech_usage)
        }
    
    def _calculate_service_classification(self, services) -> Dict[str, Any]:
        """
        Calculate service type distribution.
        """
        service_types = {}
        frameworks = {}
        
        for service in services:
            service_type = getattr(service, 'service_type', 'unknown')
            service_types[service_type] = service_types.get(service_type, 0) + 1
            
            framework = str(service.framework) if service.framework else 'unknown'
            frameworks[framework] = frameworks.get(framework, 0) + 1
        
        return {
            "service_types": dict(sorted(service_types.items(), key=lambda x: x[1], reverse=True)),
            "framework_distribution": dict(sorted(frameworks.items(), key=lambda x: x[1], reverse=True)),
            "total_services": len(services)
        }
    
    def _calculate_criticality_distribution(self, services) -> Dict[str, Any]:
        """
        Calculate business criticality distribution.
        """
        criticality_counts = {}
        critical_services = []
        
        for service in services:
            criticality = getattr(service, 'business_criticality', 'unknown')
            criticality_counts[criticality] = criticality_counts.get(criticality, 0) + 1
            
            if criticality == 'critical':
                critical_services.append({
                    "name": service.name,
                    "service_type": getattr(service, 'service_type', 'unknown'),
                    "route_count": len(service.routes),
                    "technology_stack": getattr(service, 'technology_stack', [])
                })
        
        return {
            "criticality_distribution": criticality_counts,
            "critical_services": critical_services,
            "critical_service_count": len(critical_services)
        } 