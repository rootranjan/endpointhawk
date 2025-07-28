import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from models import ScanResult, SecurityFinding

class SARIFExporter:
    """
    Export scan results to SARIF (Static Analysis Results Interchange Format) format.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def export(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Export scan result to SARIF file.
        """
        try:
            # Generate SARIF document
            sarif_doc = self._generate_sarif(scan_result)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif_doc, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"SARIF report exported to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting SARIF report: {e}")
            return False
    
    def _generate_sarif(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Generate SARIF document structure.
        """
        # Collect all security findings from routes
        all_findings = []
        for route in scan_result.routes:
            for finding in route.security_findings:
                all_findings.append((route, finding))
        
        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "EndPointHawk Attack Surface Discovery Tool",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/rootranjan/endpointhawk",
                            "shortDescription": {
                                "text": "AI-powered attack surface discovery tool for modern applications"
                            },
                            "fullDescription": {
                                "text": "EndPointHawk discovers API routes, endpoints, and security vulnerabilities across modern microservices architecture using AI-powered analysis."
                            },
                            "rules": self._generate_rules(all_findings)
                        }
                    },
                    "results": self._generate_results(all_findings),
                    "artifacts": self._generate_artifacts(scan_result.routes),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": scan_result.scan_time.isoformat() if scan_result.scan_time else datetime.now().isoformat(),
                            "endTimeUtc": datetime.now().isoformat()
                        }
                    ]
                }
            ]
        }
    
    def _generate_rules(self, findings: List[tuple]) -> List[Dict[str, Any]]:
        """
        Generate SARIF rules from security findings.
        """
        # Get unique finding types
        unique_types = set(finding.type for _, finding in findings)
        
        rules = []
        for finding_type in unique_types:
            rule = {
                "id": self._sanitize_rule_id(finding_type),
                "name": finding_type,
                "shortDescription": {
                    "text": finding_type
                },
                "fullDescription": {
                    "text": f"Security finding: {finding_type}"
                },
                "defaultConfiguration": {
                    "level": "warning"
                },
                "helpUri": "https://github.com/rootranjan/endpointhawk#security-findings",
                "properties": {
                    "category": finding.type,
                    "tags": ["security", "api", "endpointhawk"]
                }
            }
            rules.append(rule)
        
        return rules
    
    def _generate_results(self, findings: List[tuple]) -> List[Dict[str, Any]]:
        """
        Generate SARIF results from security findings.
        """
        results = []
        for route, finding in findings:
            result = {
                "ruleId": self._sanitize_rule_id(finding.type),
                "level": self._map_severity_to_level(finding.severity),
                "message": {
                    "text": finding.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": route.file_path,
                                "uriBaseId": "SRCROOT"
                            },
                            "region": {
                                "startLine": route.line_number,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "route_method": str(route.method),
                    "route_path": route.path,
                    "framework": str(route.framework),
                    "auth_type": str(route.auth_type),
                    "risk_level": str(route.risk_level),
                    "commit_author": getattr(route, 'commit_author', ''),
                    "commit_hash": getattr(route, 'commit_hash', ''),
                    "commit_date": route.commit_date.isoformat() if hasattr(route, 'commit_date') and route.commit_date else None
                }
            }
            
            # Add recommendation if available
            if hasattr(finding, 'recommendation') and finding.recommendation:
                result["fixes"] = [
                    {
                        "description": {
                            "text": finding.recommendation
                        }
                    }
                ]
            
            results.append(result)
        
        return results
    
    def _generate_artifacts(self, routes) -> List[Dict[str, Any]]:
        """
        Generate SARIF artifacts from routes.
        """
        # Get unique file paths
        unique_files = set(route.file_path for route in routes)
        
        artifacts = []
        for file_path in unique_files:
            artifact = {
                "location": {
                    "uri": file_path,
                    "uriBaseId": "SRCROOT"
                },
                "mimeType": "text/plain",
                "properties": {
                    "routes_count": len([r for r in routes if r.file_path == file_path])
                }
            }
            artifacts.append(artifact)
        
        return artifacts
    
    def _sanitize_rule_id(self, finding_type: str) -> str:
        """
        Sanitize finding type to create valid SARIF rule ID.
        """
        # Replace spaces and special characters with underscores
        sanitized = finding_type.replace(' ', '_').replace('-', '_')
        # Remove non-alphanumeric characters except underscores
        sanitized = ''.join(c for c in sanitized if c.isalnum() or c == '_')
        return sanitized.upper()
    
    def _map_severity_to_level(self, severity: str) -> str:
        """
        Map security finding severity to SARIF level.
        """
        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return severity_map.get(severity.lower(), 'warning') 