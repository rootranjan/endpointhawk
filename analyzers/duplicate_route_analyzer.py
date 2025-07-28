"""
Duplicate Route Analyzer for API Gateway Analysis

This module provides intelligent analysis of duplicate routes in API gateway environments,
classifying duplicates by type and providing service-aware context.
"""

import re
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass
from enum import Enum

from models import RouteInfo, Framework, HTTPMethod


class DuplicateType(Enum):
    """Types of route duplication"""
    LEGITIMATE_DUPLICATE = "legitimate_duplicate"  # Same route in different services
    CONFIGURATION_DUPLICATE = "configuration_duplicate"  # Same route with different configs
    ERROR_DUPLICATE = "error_duplicate"  # Accidental duplicate in same service
    TEMPLATE_DUPLICATE = "template_duplicate"  # Same route due to unresolved templates
    UNKNOWN = "unknown"


class ConflictLevel(Enum):
    """Level of conflict between duplicate routes"""
    NONE = "none"  # No conflicts
    LOW = "low"  # Minor differences
    MEDIUM = "medium"  # Moderate differences
    HIGH = "high"  # Significant differences


@dataclass
class DuplicateRouteInfo:
    """Information about a duplicate route"""
    method: HTTPMethod
    path: str
    original_path: str
    duplicate_count: int
    services: List[str]
    duplicate_type: DuplicateType
    primary_service: str
    conflict_level: ConflictLevel
    template_resolved: bool
    route_instances: List[RouteInfo]
    differences: Dict[str, List[str]]


class DuplicateRouteAnalyzer:
    """
    Analyzes duplicate routes in API gateway environments
    """
    
    def __init__(self):
        self.route_groups: Dict[Tuple[str, str], List[RouteInfo]] = defaultdict(list)
        self.service_patterns = [
            r'src/routes/([^/]+)/',
            r'src/api/([^/]+)/',
            r'routes/([^/]+)/',
            r'api/([^/]+)/',
            r'controllers/([^/]+)/',
            r'services/([^/]+)/',
        ]
    
    def analyze_routes(self, routes: List[RouteInfo]) -> List[DuplicateRouteInfo]:
        """
        Analyze routes for duplicates and return detailed analysis
        """
        # Group routes by method and path
        self._group_routes(routes)
        
        # Analyze each group
        duplicate_analysis = []
        
        for (method, path), route_instances in self.route_groups.items():
            if len(route_instances) > 1:
                analysis = self._analyze_duplicate_group(method, path, route_instances)
                duplicate_analysis.append(analysis)
        
        return duplicate_analysis
    
    def _group_routes(self, routes: List[RouteInfo]):
        """Group routes by method and path"""
        self.route_groups.clear()
        
        for route in routes:
            # Use normalized path for grouping
            normalized_path = self._normalize_path(route.path)
            method_value = route.method.value if hasattr(route.method, 'value') else str(route.method)
            key = (method_value, normalized_path)
            self.route_groups[key].append(route)
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path for comparison"""
        # Remove trailing slashes
        path = path.rstrip('/')
        # Handle empty paths
        if not path:
            path = '/'
        return path
    
    def _analyze_duplicate_group(self, method: str, path: str, route_instances: List[RouteInfo]) -> DuplicateRouteInfo:
        """Analyze a group of duplicate routes"""
        
        # Extract services from file paths
        services = [self._extract_service(route.file_path) for route in route_instances]
        service_counter = Counter(services)
        primary_service = service_counter.most_common(1)[0][0]
        
        # Determine duplicate type
        duplicate_type = self._classify_duplicate_type(route_instances, services)
        
        # Check for conflicts
        conflict_level = self._assess_conflict_level(route_instances)
        
        # Check template resolution
        template_resolved = all('${' not in route.path for route in route_instances)
        
        # Find differences
        differences = self._find_differences(route_instances)
        
        return DuplicateRouteInfo(
            method=HTTPMethod(method),
            path=path,
            original_path=route_instances[0].original_path if hasattr(route_instances[0], 'original_path') else path,
            duplicate_count=len(route_instances),
            services=services,
            duplicate_type=duplicate_type,
            primary_service=primary_service,
            conflict_level=conflict_level,
            template_resolved=template_resolved,
            route_instances=route_instances,
            differences=differences
        )
    
    def _extract_service(self, file_path: str) -> str:
        """Extract service name from file path"""
        for pattern in self.service_patterns:
            match = re.search(pattern, file_path)
            if match:
                return match.group(1)
        
        # Fallback: extract from directory structure
        parts = file_path.split('/')
        for i, part in enumerate(parts):
            if part in ['routes', 'api', 'controllers', 'services'] and i + 1 < len(parts):
                return parts[i + 1]
        
        # Final fallback: use filename
        return file_path.split('/')[-1].split('.')[0]
    
    def _classify_duplicate_type(self, route_instances: List[RouteInfo], services: List[str]) -> DuplicateType:
        """Classify the type of duplication"""
        
        # Check for template duplicates
        if any('${' in route.path for route in route_instances):
            return DuplicateType.TEMPLATE_DUPLICATE
        
        # Check for error duplicates (same service, same file)
        service_file_pairs = [(service, route.file_path) for service, route in zip(services, route_instances)]
        if len(set(service_file_pairs)) < len(route_instances):
            return DuplicateType.ERROR_DUPLICATE
        
        # Check for configuration duplicates (same service, different files)
        service_counter = Counter(services)
        if len(service_counter) == 1 and len(set(route.file_path for route in route_instances)) > 1:
            return DuplicateType.CONFIGURATION_DUPLICATE
        
        # Check for legitimate duplicates (different services)
        if len(service_counter) > 1:
            return DuplicateType.LEGITIMATE_DUPLICATE
        
        return DuplicateType.UNKNOWN
    
    def _assess_conflict_level(self, route_instances: List[RouteInfo]) -> ConflictLevel:
        """Assess the level of conflict between duplicate routes"""
        
        # Compare authentication requirements
        auth_types = [route.auth_required for route in route_instances]
        if len(set(auth_types)) > 1:
            return ConflictLevel.HIGH
        
        # Compare middleware (if available)
        middleware_sets = []
        for route in route_instances:
            if hasattr(route, 'middleware') and route.middleware:
                middleware_sets.append(set(route.middleware))
            elif hasattr(route, 'context') and route.context and hasattr(route.context, 'middleware'):
                middleware_sets.append(set(route.context.middleware))
            else:
                middleware_sets.append(set())
        
        if len(set(tuple(sorted(mw)) for mw in middleware_sets)) > 1:
            return ConflictLevel.MEDIUM
        
        # Compare parameters
        param_counts = [len(route.parameters) if route.parameters else 0 for route in route_instances]
        if len(set(param_counts)) > 1:
            return ConflictLevel.LOW
        
        return ConflictLevel.NONE
    
    def _find_differences(self, route_instances: List[RouteInfo]) -> Dict[str, List[str]]:
        """Find differences between route instances"""
        differences = defaultdict(list)
        
        # Compare authentication
        auth_types = [route.auth_required for route in route_instances]
        if len(set(auth_types)) > 1:
            differences['authentication'] = [str(auth) for auth in set(auth_types)]
        
        # Compare middleware (if available)
        middleware_sets = []
        for route in route_instances:
            if hasattr(route, 'middleware') and route.middleware:
                middleware_sets.append(set(route.middleware))
            elif hasattr(route, 'context') and route.context and hasattr(route.context, 'middleware'):
                middleware_sets.append(set(route.context.middleware))
            else:
                middleware_sets.append(set())
        
        unique_middleware = set()
        for mw_set in middleware_sets:
            unique_middleware.update(mw_set)
        
        if len(unique_middleware) > 0:
            differences['middleware'] = list(unique_middleware)
        
        # Compare parameters
        all_params = []
        for route in route_instances:
            if route.parameters:
                all_params.extend([f"{p.name}:{p.type}" for p in route.parameters])
        
        if all_params:
            differences['parameters'] = list(set(all_params))
        
        # Compare file paths
        file_paths = [route.file_path for route in route_instances]
        differences['file_paths'] = list(set(file_paths))
        
        return dict(differences)
    
    def generate_summary(self, duplicate_analysis: List[DuplicateRouteInfo]) -> Dict:
        """Generate a summary of duplicate analysis"""
        
        total_duplicates = len(duplicate_analysis)
        total_instances = sum(dup.duplicate_count for dup in duplicate_analysis)
        
        # Count by type
        type_counts = Counter(dup.duplicate_type for dup in duplicate_analysis)
        
        # Count by conflict level
        conflict_counts = Counter(dup.conflict_level for dup in duplicate_analysis)
        
        # Template resolution stats
        template_resolved_count = sum(1 for dup in duplicate_analysis if dup.template_resolved)
        template_resolution_rate = (template_resolved_count / total_duplicates * 100) if total_duplicates > 0 else 0
        
        # Service overlap analysis
        service_overlap = defaultdict(int)
        for dup in duplicate_analysis:
            for service in dup.services:
                service_overlap[service] += 1
        
        return {
            'total_unique_routes': total_duplicates,
            'total_route_instances': total_instances,
            'duplicate_distribution': dict(type_counts),
            'conflict_distribution': dict(conflict_counts),
            'template_resolution_rate': template_resolution_rate,
            'service_overlap': dict(service_overlap),
            'high_conflict_routes': [
                dup for dup in duplicate_analysis 
                if dup.conflict_level in [ConflictLevel.HIGH, ConflictLevel.MEDIUM]
            ]
        }
    
    def get_deduplicated_routes(self, routes: List[RouteInfo], 
                              include_duplicates: bool = True,
                              duplicate_type_filter: Optional[DuplicateType] = None) -> List[RouteInfo]:
        """
        Get deduplicated routes based on configuration
        
        Args:
            routes: List of all routes
            include_duplicates: Whether to include duplicate routes
            duplicate_type_filter: Filter by duplicate type
        
        Returns:
            List of deduplicated routes
        """
        if not include_duplicates:
            # Return only unique routes (one per method+path combination)
            seen = set()
            unique_routes = []
            
            for route in routes:
                method_value = route.method.value if hasattr(route.method, 'value') else str(route.method)
                key = (method_value, self._normalize_path(route.path))
                if key not in seen:
                    seen.add(key)
                    unique_routes.append(route)
            
            return unique_routes
        
        # If filtering by duplicate type, analyze and filter
        if duplicate_type_filter:
            duplicate_analysis = self.analyze_routes(routes)
            filtered_routes = []
            
            for dup in duplicate_analysis:
                if dup.duplicate_type == duplicate_type_filter:
                    filtered_routes.extend(dup.route_instances)
            
            return filtered_routes
        
        return routes 