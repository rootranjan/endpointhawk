from abc import ABC, abstractmethod
from typing import List, Optional, Dict
import os
import logging
from datetime import datetime

from models import RouteInfo, Framework
from utils.git_utils import extract_commit_info_for_route

class BaseDetector(ABC):
    """
    Abstract base class for all route detectors.
    Each framework detector should inherit from this class.
    """
    
    def __init__(self, framework: Framework):
        self.framework = framework
        self.logger = logging.getLogger(f"detector.{framework.value.lower()}")
    
    @abstractmethod
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """
        Detect routes in the given file content.
        
        Args:
            file_path: Path to the file being analyzed
            content: File content as string
            
        Returns:
            List of RouteInfo objects found in the file
        """
        pass
    
    def can_handle_file(self, file_path: str, content: str) -> bool:
        """
        Check if this detector can handle the given file.
        Override this method for custom file detection logic.
        
        Args:
            file_path: Path to the file
            content: File content as string
            
        Returns:
            True if this detector can handle the file
        """
        return True
    
    def get_supported_extensions(self) -> List[str]:
        """
        Get list of file extensions this detector supports.
        Override this method to specify supported extensions.
        
        Returns:
            List of file extensions (e.g., ['.ts', '.js'])
        """
        return []
    
    def preprocess_content(self, content: str) -> str:
        """
        Preprocess file content before analysis.
        Override this method for custom preprocessing.
        
        Args:
            content: Original file content
            
        Returns:
            Preprocessed content
        """
        return content
    
    def postprocess_routes(self, routes: List[RouteInfo]) -> List[RouteInfo]:
        """
        Postprocess detected routes.
        Override this method for custom postprocessing.
        
        Args:
            routes: List of detected routes
            
        Returns:
            Processed list of routes
        """
        return routes
    
    def extract_service_name(self, file_path: str) -> Optional[str]:
        """
        Extract service name from file path.
        Uses common organization service patterns.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Service name if detected, None otherwise
        """
        path_parts = file_path.replace('\\', '/').split('/')
        
        # Organization service patterns
        organization_patterns = [
            'user-service', 'auth-service', 'payment-service',
            'admin-service', 'api-service', 'core-service',
            'services/', 'api/', 'apps/'
        ]
        
        for i, part in enumerate(path_parts):
            for pattern in organization_patterns:
                if pattern in part:
                    # Try to get the specific service name
                    if pattern.endswith('/'):
                        # For directories like 'services/', get the next part
                        if i + 1 < len(path_parts):
                            return path_parts[i + 1]
                    else:
                        return part
        
        # Fallback: use directory name containing src or apps
        for i, part in enumerate(path_parts):
            if part in ['src', 'apps'] and i > 0:
                return path_parts[i - 1]
        
        return None
    
    def is_test_file(self, file_path: str) -> bool:
        """
        Check if the file is a test file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if it's a test file
        """
        test_indicators = [
            '.test.', '.spec.', '__tests__', '/test/', '/tests/',
            '.e2e.', 'test-utils', 'mock'
        ]
        
        return any(indicator in file_path.lower() for indicator in test_indicators)
    
    def extract_imports(self, content: str) -> List[str]:
        """
        Extract import statements from file content.
        
        Args:
            content: File content
            
        Returns:
            List of imported modules/packages
        """
        import re
        
        imports = []
        
        # Common import patterns
        patterns = [
            r'import\s+.*?\s+from\s+[\'"`]([^\'"`]+)[\'"`]',  # ES6 imports
            r'import\s+[\'"`]([^\'"`]+)[\'"`]',              # Side-effect imports
            r'require\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*\)',   # CommonJS require
            r'from\s+[\'"`]([^\'"`]+)[\'"`]\s+import',       # Python imports
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            imports.extend(matches)
        
        return imports
    

    
    def detect_organization_packages(self, content: str) -> List[str]:
        """
        Detect organization-specific package usage.
        
        Args:
            content: File content
            
        Returns:
            List of organization packages used
        """
        imports = self.extract_imports(content)
        
        organization_packages = []
        organization_prefixes = ['@yourorg/', '@internal/', 'internal-']
        
        for import_stmt in imports:
            for prefix in organization_prefixes:
                if import_stmt.startswith(prefix):
                    organization_packages.append(import_stmt)
        
        return organization_packages
    
    def log_detection_result(self, file_path: str, routes_count: int):
        """
        Log detection results.
        
        Args:
            file_path: Path to the analyzed file
            routes_count: Number of routes detected
        """
        self.logger.debug(
            f"Detected {routes_count} routes in {file_path} using {self.framework.value} detector"
        )
    
    def validate_route_info(self, route: RouteInfo) -> bool:
        """
        Validate that a RouteInfo object is properly formed.
        
        Args:
            route: RouteInfo object to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['method', 'path', 'file_path', 'line_number']
        
        for field in required_fields:
            if not hasattr(route, field) or getattr(route, field) is None:
                self.logger.warning(f"Route missing required field: {field}")
                return False
        
        # Additional validation
        if not route.path.startswith('/') and route.path != '*':
            self.logger.warning(f"Route path should start with '/': {route.path}")
            return False
        
        if route.line_number < 1:
            self.logger.warning(f"Invalid line number: {route.line_number}")
            return False
        
        return True 
    
    def add_commit_info_to_route(self, route: RouteInfo, repo_path: str, config=None) -> RouteInfo:
        """
        Add git commit information to a route.
        
        Args:
            route: RouteInfo object to enhance
            repo_path: Path to the git repository
            config: ScanConfig object to check if commit info should be included
            
        Returns:
            Enhanced RouteInfo with commit information
        """
        try:
            # Check if commit info should be included
            if config and hasattr(config, 'include_commit_info') and not config.include_commit_info:
                return route
            
            if not route.file_path or not route.line_number:
                return route
            
            # Extract commit information for this specific line
            prefer_original_author = True
            if config and hasattr(config, 'prefer_original_author'):
                prefer_original_author = config.prefer_original_author
                
            commit_info = extract_commit_info_for_route(
                repo_path=repo_path,
                file_path=route.file_path,
                line_number=route.line_number,
                prefer_original_author=prefer_original_author
            )
            
            # Add commit information to the route
            route.commit_author = commit_info.get('commit_author')
            route.commit_author_email = commit_info.get('commit_author_email')
            route.commit_hash = commit_info.get('commit_hash')
            route.commit_message = commit_info.get('commit_message')
            
            # Parse commit date
            commit_date_str = commit_info.get('commit_date')
            if commit_date_str:
                try:
                    route.commit_date = datetime.fromisoformat(commit_date_str)
                except ValueError:
                    route.commit_date = None
            
            # Add authorship history if enabled
            if config and hasattr(config, 'include_authorship_history') and config.include_authorship_history:
                from utils.git_utils import extract_authorship_history_for_route
                authorship_history = extract_authorship_history_for_route(
                    repo_path=repo_path,
                    file_path=route.file_path,
                    line_number=route.line_number,
                    max_history=5
                )
                route.authorship_history = authorship_history
            
            return route
            
        except Exception as e:
            self.logger.warning(f"Error adding commit info to route: {e}")
            return route 