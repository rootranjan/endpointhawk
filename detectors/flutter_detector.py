"""
Enhanced Flutter detector for Dart/Flutter applications.
Handles API endpoints, HTTP calls, service patterns, and security configurations.
"""

import re
import logging
from typing import List, Optional, Dict, Any, Set
from pathlib import Path

from .base_detector import BaseDetector
from models import RouteInfo, Framework, HTTPMethod, AuthType, RouteParameter, SecurityFinding, RiskLevel


class FlutterDetector(BaseDetector):
    """
    Flutter/Dart application detector with comprehensive pattern recognition for mobile apps.
    """
    
    def __init__(self):
        super().__init__(Framework.FLUTTER)
        self.logger = logging.getLogger(__name__)
        self.seen_routes = set()  # For deduplication
        self.global_variables = {}  # Global variable map across all files
        
        # Flutter/Dart file indicators
        self.flutter_indicators = [
            # Core Flutter imports
            r'import\s+[\'"`]package:flutter/',
            r'import\s+[\'"`]package:dart:',
            r'import\s+[\'"`]dart:',
            
            # Flutter framework patterns
            r'class\s+\w+\s+extends\s+StatefulWidget',
            r'class\s+\w+\s+extends\s+StatelessWidget',
            r'class\s+\w+\s+extends\s+ChangeNotifier',
            r'class\s+\w+\s+extends\s+Consumer',
            
            # Flutter app patterns
            r'runApp\s*\(',
            r'MaterialApp\s*\(',
            r'CupertinoApp\s*\(',
            r'WidgetsApp\s*\(',
            
            # Flutter service patterns
            r'abstract\s+class\s+\w+Service',
            r'class\s+\w+Service\s+implements',
            r'class\s+\w+Repository',
            r'class\s+\w+ViewModel',
            
            # HTTP client patterns
            r'import\s+[\'"`]package:dio',
            r'import\s+[\'"`]package:http/',
            r'import\s+[\'"`]package:chopper/',
            r'Dio\s*\(',
            r'HttpClient\s*\(',
        ]
        
        # API endpoint patterns
        self.endpoint_patterns = [
            # Static endpoint constants
            r'static\s+const\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'const\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'final\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            
            # API configuration patterns
            r'endpoint(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'api(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'url(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            
            # Base URL patterns
            r'baseUrl\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'base_url\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'apiUrl\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'api_url\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
        ]
        
        # HTTP method patterns
        self.http_method_patterns = [
            # Dio HTTP calls
            r'(\w+)\.get\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\.post\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\.put\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\.delete\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\.patch\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\.head\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\.options\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            
            # HTTP client calls
            r'http\.get\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'http\.post\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'http\.put\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'http\.delete\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'http\.patch\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'http\.head\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'http\.options\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            
                            # Network service calls (common in Flutter repositories) - more specific patterns
                r'_networkService\.get\s*\(\s*APIConfig\.(\w+)\s*\)',
                r'_networkService\.post\s*\(\s*APIConfig\.(\w+)\s*\)',
                r'_networkService\.put\s*\(\s*APIConfig\.(\w+)\s*\)',
                r'_networkService\.delete\s*\(\s*APIConfig\.(\w+)\s*\)',
                r'_networkService\.patch\s*\(\s*APIConfig\.(\w+)\s*\)',
            
            # HTTP service calls - more specific patterns
            r'_httpService\.get\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_httpService\.post\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_httpService\.put\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_httpService\.delete\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_httpService\.patch\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            
            # API service calls - more specific patterns
            r'_apiService\.get\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_apiService\.post\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_apiService\.put\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_apiService\.delete\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'_apiService\.patch\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]',
            
            # Variable-based calls that need resolution - more specific to avoid capturing extra characters
            r'_networkService\.get\s*\(\s*(\w+)\s*\)',
            r'_networkService\.post\s*\(\s*(\w+)\s*\)',
            r'_networkService\.put\s*\(\s*(\w+)\s*\)',
            r'_networkService\.delete\s*\(\s*(\w+)\s*\)',
            r'_networkService\.patch\s*\(\s*(\w+)\s*\)',
            
            # Chopper HTTP calls
            r'@Get\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Post\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Put\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Delete\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Patch\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
        ]
        
        # Flutter authentication patterns
        self.auth_patterns = [
            # JWT and token patterns
            r'jwt|JWT|Jwt',
            r'bearer|Bearer',
            r'token|Token',
            r'auth|Auth',
            r'authentication|Authentication',
            
            # Flutter-specific auth
            r'FirebaseAuth',
            r'GoogleSignIn',
            r'FacebookAuth',
            r'AppleSignIn',
            r'BiometricAuth',
            r'FingerprintAuth',
            
            # Custom auth patterns
            r'isAuthenticated',
            r'requireAuth',
            r'checkAuth',
            r'validateToken',
            r'verifyToken',
        ]
        
        # Flutter security patterns
        self.security_patterns = [
            # SSL/TLS patterns
            r'badCertificateCallback',
            r'validateCertificate',
            r'certificatePinning',
            r'SSL|ssl|TLS|tls',
            
            # Encryption patterns
            r'encrypt|Encrypt',
            r'decrypt|Decrypt',
            r'hash|Hash',
            r'crypto|Crypto',
            
            # Secure storage
            r'FlutterSecureStorage',
            r'secureStorage',
            r'encryptedStorage',
            r'Keychain',
            
            # Network security
            r'certificatePinning',
            r'publicKeyPinning',
            r'networkSecurityConfig',
        ]
        
        # Flutter service types
        self.service_types = {
            'auth': ['auth', 'login', 'signin', 'signup', 'logout', 'register'],
            'payment': ['payment', 'billing', 'transaction', 'checkout', 'order'],
            'user': ['user', 'profile', 'account', 'customer', 'member'],
            'notification': ['notification', 'push', 'message', 'alert'],
            'data': ['data', 'api', 'service', 'repository', 'model'],
            'config': ['config', 'configuration', 'settings', 'preferences'],
        }
        
        # Flutter risk patterns
        self.risk_patterns = {
            'high': [
                'payment', 'billing', 'transaction', 'checkout',
                'auth', 'login', 'signin', 'register',
                'user', 'profile', 'account', 'personal',
                'delete', 'remove', 'destroy',
                'admin', 'manage', 'control'
            ],
            'medium': [
                'get', 'fetch', 'retrieve', 'load',
                'update', 'modify', 'change', 'edit',
                'notification', 'message', 'alert',
                'config', 'settings', 'preferences'
            ],
            'low': [
                'ping', 'health', 'status', 'version',
                'info', 'describe', 'schema', 'meta'
            ]
        }
    
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Detect Flutter/Dart API endpoints and HTTP calls."""
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self._is_flutter_file(file_path, content):
            return routes
        
        # Step 1: Extract variable declarations for template resolution
        variables = self._extract_flutter_variables(content)
        
        # Step 1.5: If this is api_config.dart, store the constants globally
        if 'api_config.dart' in file_path:
            self.global_variables.update(variables)
            self.logger.debug(f"Updated global variables from {file_path}: {list(variables.keys())}")
        
        # Step 1.6: Merge with global variables (from api_config.dart)
        variables.update(self.global_variables)
        
        try:
            # Step 4: Detect API endpoints from constants
            routes.extend(self._detect_api_endpoints(content, file_path, variables))
            
            # Step 5: Detect HTTP method calls
            routes.extend(self._detect_http_calls(content, file_path, variables))
            
            # Step 6: Detect Chopper service endpoints
            routes.extend(self._detect_chopper_endpoints(content, file_path, variables))
            
            # Step 7: Detect repository-specific HTTP calls
            routes.extend(self._detect_repository_calls(content, file_path, variables))
            
        except Exception as e:
            self.logger.error(f"Error detecting Flutter routes in {file_path}: {e}")
        
        return routes
    
    def detect_route_changes(self, current_content: str, previous_content: str) -> Dict[str, any]:
        """
        Detect changes in Flutter routes between two versions.
        Similar to the provided script's change detection logic.
        """
        import hashlib
        
        current_routes = {}
        previous_routes = {}
        
        # Extract routes from current content
        current_variables = self._extract_flutter_variables(current_content)
        current_variables.update(self.global_variables)
        
        # Extract routes from previous content
        previous_variables = self._extract_flutter_variables(previous_content)
        
        # Find endpoint definitions in both versions
        endpoint_pattern = re.compile(r'static\s+const\s+(\w+)\s*=\s*"([^"]+)"', re.MULTILINE)
        
        for match in endpoint_pattern.finditer(current_content):
            endpoint_name = match.group(1)
            endpoint_path = match.group(2)
            endpoint_definition = match.group(0)
            hash_digest = hashlib.md5(endpoint_definition.encode('utf-8')).hexdigest()
            
            current_routes[endpoint_path] = {
                'endpoint_name': endpoint_name,
                'endpoint_path': endpoint_path,
                'hash': hash_digest,
                'line': current_content[:match.start()].count('\n') + 1
            }
        
        for match in endpoint_pattern.finditer(previous_content):
            endpoint_name = match.group(1)
            endpoint_path = match.group(2)
            endpoint_definition = match.group(0)
            hash_digest = hashlib.md5(endpoint_definition.encode('utf-8')).hexdigest()
            
            previous_routes[endpoint_path] = {
                'endpoint_name': endpoint_name,
                'endpoint_path': endpoint_path,
                'hash': hash_digest,
                'line': previous_content[:match.start()].count('\n') + 1
            }
        
        # Calculate differences
        current_paths = set(current_routes.keys())
        previous_paths = set(previous_routes.keys())
        
        added = current_paths - previous_paths
        removed = previous_paths - current_paths
        modified = set()
        
        for path in current_paths & previous_paths:
            if current_routes[path]['hash'] != previous_routes[path]['hash']:
                modified.add(path)
        
        return {
            'added': {path: current_routes[path] for path in added},
            'removed': {path: previous_routes[path] for path in removed},
            'modified': {path: current_routes[path] for path in modified},
            'unchanged': {path: current_routes[path] for path in current_paths - added - modified}
        }
    
    def _is_flutter_file(self, file_path: str, content: str) -> bool:
        """Check if this is a Flutter/Dart file."""
        if not file_path.endswith('.dart'):
            return False
        
        # Check for Flutter indicators
        for pattern in self.flutter_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_flutter_variables(self, content: str) -> Dict[str, str]:
        """Dynamic runtime variable extraction with comprehensive Flutter/Dart template literal support"""
        variables = {}
        
        # Step 1: Extract all variable declarations dynamically
        var_patterns = [
            # Standard variable declarations
            r'(?:const|final|static\s+const)\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            # Template literal declarations
            r'(?:const|final|static\s+const)\s+(\w+)\s*=\s*`([^`]+)`',
            # Numeric and boolean declarations
            r'(?:const|final|static\s+const)\s+(\w+)\s*=\s*(\d+|true|false|null)',
            # Enhanced patterns for complex declarations
            r'(?:const|final|static\s+const)\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]\s*\+\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(?:const|final|static\s+const)\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]\s*\+\s*(\w+)',
            # Class property assignments
            r'(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            # Import patterns
            r'import\s+[\'"`]([^\'"`,]+)[\'"`]',
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                groups = match.groups()
                if len(groups) == 2:
                    var_name, var_value = groups
                    variables[var_name] = var_value
                elif len(groups) == 3:
                    # Handle complex patterns like "prefix + '/suffix'"
                    var_name, part1, part2 = groups
                    variables[var_name] = part1 + part2
                elif len(groups) == 4:
                    # Handle patterns like "prefix + '/suffix' + variable"
                    var_name, part1, part2, variable = groups
                    variables[var_name] = part1 + part2 + variable
        
        # Step 2: Extract import destructuring (Flutter/Dart specific)
        import_patterns = [
            r'import\s+[\'"`]([^\'"`,]+)[\'"`]\s+as\s+(\w+)',
            r'import\s+[\'"`]([^\'"`,]+)[\'"`]\s+show\s+([^;]+)',
            r'import\s+[\'"`]([^\'"`,]+)[\'"`]\s+hide\s+([^;]+)',
        ]
        
        for pattern in import_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                module_name = match.group(1)
                imported_items = match.group(2)
                # Handle multiple imports
                items = [item.strip() for item in imported_items.split(',')]
                for item in items:
                    variables[item] = f"IMPORT:{module_name}"
        
        # Step 3: Extract environment variables
        env_patterns = [
            r'String\.fromEnvironment\s*\(\s*[\'"`]([A-Z_][A-Z0-9_]*)[\'"`]',
            r'Platform\.environment\[[\'"`]([A-Z_][A-Z0-9_]*)[\'"`]\]',
            r'const\s+(\w+)\s*=\s*String\.fromEnvironment\s*\(\s*[\'"`]([A-Z_][A-Z0-9_]*)[\'"`]',
        ]
        
        for pattern in env_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if len(match.groups()) == 1:
                    env_var = match.group(1)
                    variables[env_var] = f"${{{env_var}}}"
                elif len(match.groups()) == 2:
                    var_name, env_var = match.groups()
                    variables[var_name] = f"${{{env_var}}}"
        
        # Step 4: Extract class constants and static members
        class_patterns = [
            r'class\s+(\w+)\s*\{[^}]*static\s+const\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'abstract\s+class\s+(\w+)\s*\{[^}]*static\s+const\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
        ]
        
        for pattern in class_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
            for match in matches:
                class_name, const_name, const_value = match.groups()
                variables[f"{class_name}.{const_name}"] = const_value
        
        # Step 5: Extract APIConfig constants specifically
        api_config_patterns = [
            r'static\s+const\s+(\w+)\s*=\s*"([^"]+)"',
        ]
        
        for pattern in api_config_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                const_name, const_value = match.groups()
                # Add both the direct name and the APIConfig prefixed name
                variables[const_name] = const_value
                variables[f"APIConfig.{const_name}"] = const_value
                self.logger.debug(f"Extracted APIConfig constant: {const_name} = {const_value}")
                self.logger.debug(f"Added to variables: APIConfig.{const_name} = {const_value}")
        
        # Step 5.5: Store APIConfig constants globally (handled in detect_routes)
        pass
        
        # Step 6: Dynamic template literal resolution
        # Find all string interpolation patterns and resolve them recursively
        template_patterns = [
            r'\$\{([^}]+)\}',  # String interpolation variables
            r'\{([^}]+)\}',    # Simple format variables
        ]
        
        for pattern in template_patterns:
            template_matches = re.finditer(pattern, content)
            for match in template_matches:
                template_var = match.group(1).strip()
                if template_var in variables:
                    # Resolve nested template literals
                    resolved_value = self._resolve_nested_template(template_var, variables, content, 0, set())
                    variables[template_var] = resolved_value
        
        return variables
    
    def _resolve_nested_template(self, template_var: str, variables: Dict[str, str], content: str, depth: int = 0, visited: set = None) -> str:
        """Recursively resolve nested template literals with depth limiting and cycle detection"""
        if visited is None:
            visited = set()
        
        # Prevent infinite recursion
        if depth > 10:  # Maximum recursion depth
            self.logger.warning(f"Maximum recursion depth exceeded for template variable: {template_var}")
            return template_var
        
        # Detect circular references
        if template_var in visited:
            self.logger.warning(f"Circular reference detected for template variable: {template_var}")
            return template_var
        
        if template_var not in variables:
            return template_var
        
        # Add to visited set to detect cycles
        visited.add(template_var)
        
        try:
            value = variables[template_var]
            
            # Check if the value contains more template literals
            template_pattern = r'\$\{([^}]+)\}'
            nested_matches = re.findall(template_pattern, value)
            
            if nested_matches:
                # Resolve nested templates
                for nested_var in nested_matches:
                    nested_var = nested_var.strip()
                    if nested_var in variables:
                        nested_value = self._resolve_nested_template(nested_var, variables, content, depth + 1, visited)
                        value = value.replace(f'${{{nested_var}}}', nested_value)
            
            return value
        finally:
            # Remove from visited set when done
            visited.discard(template_var)
    
    def _detect_api_endpoints(self, content: str, file_path: str, variables: Dict[str, str]) -> List[RouteInfo]:
        """Detect API endpoints from constant definitions."""
        routes = []
        
        for pattern in self.endpoint_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                groups = match.groups()
                if len(groups) >= 2:
                    endpoint_name, endpoint_path = groups[0], groups[1]
                    
                    # Skip non-API endpoints
                    if not self._is_api_endpoint(endpoint_path):
                        continue
                    
                    # Resolve template literals in the path
                    resolved_path = self._resolve_template_literal(endpoint_path, variables)
                    
                    # Determine HTTP method from endpoint name
                    http_method = self._determine_http_method_from_name(endpoint_name)
                    
                    # Create deduplication key
                    route_key = (http_method.value, resolved_path, file_path)
                    if route_key in self.seen_routes:
                        continue
                    self.seen_routes.add(route_key)
                    
                    # Create route info
                    line_number = self._find_line_number(content, match.start())
                    route_info = self._create_flutter_route_info(
                        method=http_method,
                        path=resolved_path,
                        original_path=endpoint_path,
                        file_path=file_path,
                        line_number=line_number,
                        endpoint_name=endpoint_name,
                        variables=variables,
                        content=content
                    )
                    
                    routes.append(route_info)
        
        return routes
    
    def _detect_http_calls(self, content: str, file_path: str, variables: Dict[str, str]) -> List[RouteInfo]:
        """Detect HTTP method calls in the code."""
        routes = []
        
        for pattern in self.http_method_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                groups = match.groups()
                
                if len(groups) >= 1:
                    # Extract method and path based on pattern type
                    if 'http.' in pattern:
                        # Direct http calls - extract method from pattern
                        if 'http.get' in pattern:
                            method_name = 'get'
                        elif 'http.post' in pattern:
                            method_name = 'post'
                        elif 'http.put' in pattern:
                            method_name = 'put'
                        elif 'http.delete' in pattern:
                            method_name = 'delete'
                        elif 'http.patch' in pattern:
                            method_name = 'patch'
                        elif 'http.head' in pattern:
                            method_name = 'head'
                        elif 'http.options' in pattern:
                            method_name = 'options'
                        else:
                            method_name = 'get'  # Default
                        path = groups[0] if len(groups) == 1 else groups[1]
                    elif '_networkService.' in pattern or '_httpService.' in pattern or '_apiService.' in pattern:
                        # Network service calls - extract method from pattern
                        if '.get' in pattern:
                            method_name = 'get'
                        elif '.post' in pattern:
                            method_name = 'post'
                        elif '.put' in pattern:
                            method_name = 'put'
                        elif '.delete' in pattern:
                            method_name = 'delete'
                        elif '.patch' in pattern:
                            method_name = 'patch'
                        else:
                            method_name = 'get'  # Default
                        # For network service calls, the path might be a variable
                        path = groups[0].strip()
                        # Try to resolve the path if it's a variable
                        if path in variables:
                            path = variables[path]
                    else:
                        # Dio or other client calls
                        method_name = groups[0] if len(groups) == 1 else groups[0]
                        path = groups[1] if len(groups) >= 2 else groups[0]
                    
                    # Convert method name to HTTP method
                    http_method = self._convert_to_http_method(method_name)
                    if not http_method:
                        continue
                    
                    # Resolve template literals in the path
                    resolved_path = self._resolve_template_literal(path, variables)
                    
                                                        # Try to resolve variable assignments if the path is a variable name
                    if resolved_path == path and not path.startswith('/') and not path.startswith('http'):
                        # Look for variable assignments in the same file
                        original_path = resolved_path
                        self.logger.debug(f"Attempting to resolve variable '{path}' in {file_path}")
                        self.logger.debug(f"Available variables: {list(variables.keys())}")
                        resolved_path = self._resolve_variable_assignment(path, content, variables)
                        if resolved_path != original_path:
                            self.logger.debug(f"Resolved variable '{original_path}' to '{resolved_path}' in {file_path}")
                        else:
                            self.logger.debug(f"Failed to resolve variable '{original_path}' in {file_path}")
                            # Check if this is a simple variable that should be resolved
                            if path in variables:
                                self.logger.debug(f"Variable '{path}' found in variables map: {variables[path]}")
                                resolved_path = variables[path]
                    
                    # If still unresolved or not a valid API path, skip
                    if resolved_path == path or not (resolved_path.startswith('/') or resolved_path.startswith('http') or '{' in resolved_path):
                        continue
                    
                    # Validate the resolved path - skip if it's not a valid API endpoint
                    if not self._is_valid_api_path(resolved_path):
                        continue
                    
                    # Additional check for the specific problematic pattern
                    if 'path);' in resolved_path or 'configurationResponse' in resolved_path:
                        continue
                    
                    # Create deduplication key
                    route_key = (http_method.value, resolved_path, file_path)
                    if route_key in self.seen_routes:
                        continue
                    self.seen_routes.add(route_key)
                    
                    # Create route info
                    line_number = self._find_line_number(content, match.start())
                    route_info = self._create_flutter_route_info(
                        method=http_method,
                        path=resolved_path,
                        original_path=path,
                        file_path=file_path,
                        line_number=line_number,
                        endpoint_name=f"{method_name}_call",
                        variables=variables,
                        content=content
                    )
                    
                    routes.append(route_info)
        
        return routes
    
    def _detect_chopper_endpoints(self, content: str, file_path: str, variables: Dict[str, str]) -> List[RouteInfo]:
        """Detect Chopper service endpoints."""
        routes = []
        
        # Chopper service patterns
        chopper_patterns = [
            r'@Get\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Post\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Put\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Delete\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
            r'@Patch\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)',
        ]
        
        method_mapping = {
            '@Get': HTTPMethod.GET,
            '@Post': HTTPMethod.POST,
            '@Put': HTTPMethod.PUT,
            '@Delete': HTTPMethod.DELETE,
            '@Patch': HTTPMethod.PATCH,
        }
        
        for pattern in chopper_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                path = match.group(1)
                
                # Determine HTTP method from annotation
                http_method = None
                for annotation, method in method_mapping.items():
                    if annotation in pattern:
                        http_method = method
                        break
                
                if not http_method:
                    continue
                
                # Resolve template literals in the path
                resolved_path = self._resolve_template_literal(path, variables)
                
                # Create deduplication key
                route_key = (http_method.value, resolved_path, file_path)
                if route_key in self.seen_routes:
                    continue
                self.seen_routes.add(route_key)
                
                # Create route info
                line_number = self._find_line_number(content, match.start())
                route_info = self._create_flutter_route_info(
                    method=http_method,
                    path=resolved_path,
                    original_path=path,
                    file_path=file_path,
                    line_number=line_number,
                    endpoint_name=f"chopper_{http_method.value.lower()}",
                    variables=variables,
                    content=content
                )
                
                routes.append(route_info)
        
        return routes
    
    def _detect_repository_calls(self, content: str, file_path: str, variables: Dict[str, str]) -> List[RouteInfo]:
        """Detect HTTP method calls in repository files with proper method resolution."""
        routes = []
        
        # Repository-specific patterns for HTTP method calls
        repo_patterns = [
            # Network service calls with method and endpoint - more specific to avoid capturing extra characters
            (r'_networkService\.(get|post|put|delete|patch)\s*\(\s*([^,)]+)', 'network_service'),
            (r'_httpService\.(get|post|put|delete|patch)\s*\(\s*([^,)]+)', 'http_service'),
            (r'_apiService\.(get|post|put|delete|patch)\s*\(\s*([^,)]+)', 'api_service'),
            (r'_dio\.(get|post|put|delete|patch)\s*\(\s*([^,)]+)', 'dio'),
            (r'_client\.(get|post|put|delete|patch)\s*\(\s*([^,)]+)', 'client'),
        ]
        
        for pattern, service_type in repo_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                groups = match.groups()
                if len(groups) >= 2:
                    method_name = groups[0]
                    endpoint_expr = groups[1].strip()
                    
                    # Convert method name to HTTP method
                    http_method = self._convert_to_http_method(method_name)
                    if not http_method:
                        continue
                    
                    # Resolve the endpoint expression
                    resolved_path = self._resolve_endpoint_expression(endpoint_expr, variables, content)
                    self.logger.debug(f"Repository call - endpoint_expr: '{endpoint_expr}', resolved_path: '{resolved_path}'")
                    
                    # Skip if not a valid API endpoint
                    if not self._is_api_endpoint(resolved_path):
                        self.logger.debug(f"Skipping invalid API endpoint: '{resolved_path}'")
                        continue
                    
                    # Create deduplication key
                    route_key = (http_method.value, resolved_path, file_path)
                    if route_key in self.seen_routes:
                        continue
                    self.seen_routes.add(route_key)
                    
                    # Create route info
                    line_number = self._find_line_number(content, match.start())
                    route_info = self._create_flutter_route_info(
                        method=http_method,
                        path=resolved_path,
                        original_path=endpoint_expr,
                        file_path=file_path,
                        line_number=line_number,
                        endpoint_name=f"{service_type}_{method_name}",
                        variables=variables,
                        content=content
                    )
                    
                    routes.append(route_info)
        
        return routes
    
    def _resolve_endpoint_expression(self, endpoint_expr: str, variables: Dict[str, str], content: str) -> str:
        """Resolve endpoint expressions that might be variables or constants."""
        # Remove quotes and whitespace
        endpoint_expr = endpoint_expr.strip().strip('"\'`')
        
        # If it's a variable, try to resolve it
        if endpoint_expr in variables:
            return variables[endpoint_expr]
        
        # If it's a class constant (e.g., APIConfig.endpointLogin)
        if '.' in endpoint_expr:
            parts = endpoint_expr.split('.')
            if len(parts) == 2:
                class_name, constant_name = parts
                const_key = f"{class_name}.{constant_name}"
                
                # Check if we have the constant in our variables
                if const_key in variables:
                    return variables[const_key]
                
                # Look for the constant definition in the content
                constant_pattern = rf'(?:const|static\s+const)\s+{constant_name}\s*=\s*[\'"`]([^\'"`,]+)[\'"`]'
                match = re.search(constant_pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
                
                # Try to find import statements for the class
                import_pattern = rf'import\s+[\'"`][^\'"`,]*{class_name.lower()}[^\'"`,]*[\'"`]'
                if re.search(import_pattern, content, re.IGNORECASE):
                    # This is an imported constant, keep as template for later resolution
                    return f"${{{class_name}.{constant_name}}}"
        
        # If it's a simple variable name (like 'path'), try to resolve its assignment
        if endpoint_expr.isidentifier():
            resolved_value = self._resolve_variable_assignment(endpoint_expr, content, variables)
            if resolved_value != endpoint_expr:
                return resolved_value
        
        # If it's a direct path, return as is
        return endpoint_expr
    
    def _is_api_endpoint(self, path: str) -> bool:
        """Check if a path looks like an API endpoint."""
        # Skip non-API paths
        non_api_patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # Just variable names
            r'^[0-9]+$',  # Just numbers
            r'^true$|^false$|^null$',  # Boolean/null values
        ]
        
        for pattern in non_api_patterns:
            if re.match(pattern, path):
                return False
        
        # Filter out UI routes (Flutter navigation routes)
        ui_route_patterns = [
            r'^/splash$',
            r'^/login$',
            r'^/home$',
            r'^/qr-code$',
            r'^/profile$',
            r'^/manager-login$',
            r'^/outlet-auth-code$',
            r'^/outlet-filter$',
            r'^/create-order$',
            r'^/assets/',  # Asset paths
            r'^/images/',  # Image paths
            r'^/fonts/',   # Font paths
        ]
        
        for pattern in ui_route_patterns:
            if re.match(pattern, path, re.IGNORECASE):
                return False
        
        # Check for API-like patterns
        api_patterns = [
            r'^/',  # Starts with slash
            r'^https?://',  # Full URL
            r'^api/',  # API prefix
            r'^v[0-9]+/',  # Version prefix
            r'[a-z]+/[a-z]+',  # Path-like structure
            r'sbgo-cashier',  # Specific API patterns
            r'checkout',      # Checkout API patterns
            r'transactions',  # Transaction API patterns
            r'auth',         # Auth API patterns
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        return False
    
    def _is_valid_api_path(self, path: str) -> bool:
        """Enhanced validation for API paths to filter out code fragments."""
        if not path or not isinstance(path, str):
            return False
        
        # Must start with / or be a dynamic parameter, or contain API-like patterns
        if not (path.startswith('/') or path.startswith('http') or '{' in path or 'api' in path.lower()):
            return False
        
        # Must not be too short (at least /a)
        if len(path) < 2:
            return False
        
        # Must not contain obvious code fragments or invalid characters
        invalid_patterns = [
            r'=.*;',  # Assignment statements
            r'//.*',  # Comments
            r'/\*.*\*/',  # Block comments
            r'\.\.\.',  # Ellipsis
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return False
        
        # For dynamic routes with parameters, be more lenient
        if '{' in path:
            # Allow dynamic routes like /api/{id} or /users/{userId}
            return True
        
        # Must contain only valid URL characters (more lenient for dynamic routes)
        valid_url_chars = r'^[/a-zA-Z0-9\-_~\.:@!$&\'()*+,;=\{\}]*$'
        if not re.match(valid_url_chars, path):
            return False
        
        return True
    
    def _resolve_variable_assignment(self, var_name: str, content: str, variables: Dict[str, str]) -> str:
        """Simple variable assignment resolution."""
        # Look for: final path = APIConfig.endpointConfiguration + key;
        assignment_pattern = rf'final\s+{var_name}\s*=\s*([^;]+);'
        match = re.search(assignment_pattern, content, re.MULTILINE)
        
        if match:
            assignment_value = match.group(1).strip()
            self.logger.debug(f"Found assignment: {var_name} = {assignment_value}")
            
            # Handle simple concatenation: APIConfig.endpointConfiguration + key
            if '+' in assignment_value:
                parts = [part.strip() for part in assignment_value.split('+')]
                resolved_parts = []
                
                for part in parts:
                    # Remove quotes
                    part = part.strip("'\"`")
                    
                    # Check if it's a known constant (like APIConfig.endpointConfiguration)
                    if part in variables:
                        resolved_parts.append(variables[part])
                    else:
                        # Keep as dynamic parameter
                        resolved_parts.append(f"{{{part}}}")
                
                resolved_value = ''.join(resolved_parts)
                self.logger.debug(f"Resolved to: {resolved_value}")
                return resolved_value
        
        # If no assignment found, return original
        return var_name
    
    def _resolve_template_literal(self, raw_path: str, variables: Dict[str, str]) -> str:
        """Dynamic runtime template literal resolution with comprehensive Flutter/Dart support"""
        resolved_path = raw_path
        
        # Step 1: Handle string interpolation: ${variable}
        template_vars = re.findall(r'\$\{([^}]+)\}', raw_path)
        
        for var_expr in template_vars:
            var_expr = var_expr.strip()
            
            # Simple variable reference - check if we have it in our variables
            if var_expr in variables:
                resolved_value = variables[var_expr]
                # Recursively resolve any nested template literals in the value
                if '${' in resolved_value:
                    resolved_value = self._resolve_nested_template(var_expr, variables, "", 0, set())
                resolved_path = resolved_path.replace(f'${{{var_expr}}}', resolved_value)
            
            # Class constant reference: APIConfig.endpointLogin
            elif '.' in var_expr:
                base_obj, prop = var_expr.split('.', 1)
                const_key = f"{base_obj}.{prop}"
                if const_key in variables:
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', variables[const_key])
                else:
                    # Keep as dynamic parameter
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
            
            # Function call: functionName()
            elif var_expr.endswith('()'):
                func_name = var_expr[:-2]
                if func_name in variables:
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', variables[func_name])
                else:
                    # Keep as dynamic parameter
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{func_name}}}')
            
            # Complex expressions: var + '/suffix' or mathematical operations
            elif any(op in var_expr for op in ['+', '-', '*', '/', '||', '&&']):
                # Try to resolve known variables in the expression
                resolved_expr = var_expr
                for var_name, var_value in variables.items():
                    if var_name in var_expr:
                        resolved_expr = resolved_expr.replace(var_name, f"'{var_value}'")
                
                # If we can't fully resolve, keep as dynamic parameter
                if '${' in resolved_expr or any(var in resolved_expr for var in variables.keys()):
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
                else:
                    # Try to evaluate the expression (safely)
                    try:
                        # Only allow safe operations
                        safe_expr = re.sub(r'[^a-zA-Z0-9_+\-*/()\'\"\s]', '', resolved_expr)
                        # This is a simplified approach - in production, you'd want a safer eval
                        resolved_path = resolved_path.replace(f'${{{var_expr}}}', safe_expr)
                    except:
                        resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
            
            # Unknown variable - keep as parameter
            else:
                resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
        
        # Step 2: Normalize the resolved path
        resolved_path = self._normalize_route_path(resolved_path)
        
        return resolved_path
    
    def _determine_http_method_from_name(self, endpoint_name: str) -> HTTPMethod:
        """Determine HTTP method from endpoint name."""
        endpoint_lower = endpoint_name.lower()
        
        if any(method in endpoint_lower for method in ['get', 'fetch', 'retrieve', 'load']):
            return HTTPMethod.GET
        elif any(method in endpoint_lower for method in ['post', 'create', 'add', 'submit']):
            return HTTPMethod.POST
        elif any(method in endpoint_lower for method in ['put', 'update', 'modify', 'change']):
            return HTTPMethod.PUT
        elif any(method in endpoint_lower for method in ['delete', 'remove', 'destroy']):
            return HTTPMethod.DELETE
        elif any(method in endpoint_lower for method in ['patch', 'partial']):
            return HTTPMethod.PATCH
        else:
            # Default to GET for unknown patterns
            return HTTPMethod.GET
    
    def _convert_to_http_method(self, method_string: str) -> Optional[HTTPMethod]:
        """Convert method string to HTTPMethod enum."""
        method_mapping = {
            'get': HTTPMethod.GET,
            'post': HTTPMethod.POST,
            'put': HTTPMethod.PUT,
            'delete': HTTPMethod.DELETE,
            'patch': HTTPMethod.PATCH,
            'head': HTTPMethod.HEAD,
            'options': HTTPMethod.OPTIONS,
        }
        
        return method_mapping.get(method_string.lower())
    
    def _normalize_route_path(self, path: str) -> str:
        """Normalize Flutter route path."""
        # Remove leading/trailing whitespace
        path = path.strip()
        
        # Ensure path starts with /
        if not path.startswith('/') and not path.startswith('http'):
            path = '/' + path
        
        # Remove trailing slash unless it's the root
        if path.endswith('/') and path != '/':
            path = path[:-1]
        
        return path
    
    def _find_line_number(self, content: str, match_start: int) -> int:
        """Find line number for a match position."""
        return content[:match_start].count('\n') + 1
    
    def _create_flutter_route_info(self, method: HTTPMethod, path: str, original_path: str,
                                  file_path: str, line_number: int, endpoint_name: str,
                                  variables: Dict[str, str], content: str) -> RouteInfo:
        """Create enhanced RouteInfo for Flutter routes."""
        
        # Extract authentication info
        auth_info = self._extract_flutter_auth_info(content, line_number)
        
        # Extract parameters
        route_parameters = self._extract_flutter_parameters(path, content, line_number)
        
        # Enhanced metadata with Flutter-specific info
        metadata = {
            'original_template': original_path if '${' in original_path else None,
            'resolved_variables': {k: v for k, v in variables.items() if f'${{{k}}}' in original_path},
            'endpoint_name': endpoint_name,
            'flutter_framework': True,
            'template_resolution': '${' in original_path
        }
        
        # Create route info
        route_info = RouteInfo(
            method=method,
            path=path,
            file_path=file_path,
            line_number=line_number,
            framework=self.framework,
            auth_type=auth_info.get('type', AuthType.UNKNOWN),
            auth_required=auth_info.get('required', False),
            parameters=route_parameters,
            metadata=metadata
        )
        
        # Set original path for prefix resolution
        if '${' in original_path:
            route_info.original_path = original_path
        
        # Enhanced risk assessment
        route_info.risk_level = self._assess_flutter_risk(path, method.value, route_info.auth_type)
        route_info.risk_score = self._calculate_flutter_risk_score(route_info, content)
        
        return route_info
    
    def _extract_flutter_auth_info(self, content: str, line_number: int) -> Dict[str, Any]:
        """Extract authentication information from Flutter code."""
        auth_info = {'type': AuthType.UNKNOWN, 'required': False}
        
        # Look for auth patterns around the line
        lines = content.split('\n')
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        context = '\n'.join(lines[start_line:end_line])
        
        # Check for authentication patterns
        for pattern in self.auth_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                if 'jwt' in pattern.lower() or 'bearer' in pattern.lower():
                    auth_info['type'] = AuthType.JWT
                    auth_info['required'] = True
                elif 'token' in pattern.lower():
                    auth_info['type'] = AuthType.BEARER_TOKEN
                    auth_info['required'] = True
                elif 'auth' in pattern.lower():
                    auth_info['type'] = AuthType.API_KEY
                    auth_info['required'] = True
                break
        
        return auth_info
    
    def _extract_flutter_parameters(self, path: str, content: str, line_number: int) -> List[RouteParameter]:
        """Extract parameters from Flutter route path."""
        parameters = []
        
        # Extract path parameters from {param} patterns
        path_params = re.findall(r'\{([^}]+)\}', path)
        for param in path_params:
            parameters.append(RouteParameter(
                name=param,
                type="string",
                required=True,
                location="path",
                description=f"Path parameter: {param}"
            ))
        
        return parameters
    
    def _assess_flutter_risk(self, path: str, method: str, auth_type: AuthType) -> RiskLevel:
        """Assess risk level for Flutter routes."""
        path_lower = path.lower()
        method_lower = method.lower()
        
        # High risk patterns
        high_risk_keywords = self.risk_patterns['high']
        if any(keyword in path_lower for keyword in high_risk_keywords):
            return RiskLevel.HIGH
        
        # Medium risk patterns
        medium_risk_keywords = self.risk_patterns['medium']
        if any(keyword in path_lower for keyword in medium_risk_keywords):
            return RiskLevel.MEDIUM
        
        # Low risk patterns
        low_risk_keywords = self.risk_patterns['low']
        if any(keyword in path_lower for keyword in low_risk_keywords):
            return RiskLevel.LOW
        
        # Default based on method
        if method_lower in ['post', 'put', 'delete', 'patch']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_flutter_risk_score(self, route_info: RouteInfo, content: str) -> float:
        """Calculate risk score for Flutter routes."""
        base_score = 1.0
        
        # Method-based scoring
        method_scores = {
            'GET': 1.0,
            'POST': 3.0,
            'PUT': 3.0,
            'DELETE': 4.0,
            'PATCH': 2.5,
            'HEAD': 1.0,
            'OPTIONS': 1.0,
        }
        
        # Handle method value safely
        method_value = route_info.method.value if hasattr(route_info.method, 'value') else str(route_info.method)
        base_score += method_scores.get(method_value, 1.0)
        
        # Authentication scoring
        if route_info.auth_type == AuthType.UNKNOWN:
            base_score += 2.0  # Higher risk for unauthenticated endpoints
        elif route_info.auth_type in [AuthType.JWT, AuthType.BEARER_TOKEN]:
            base_score -= 0.5  # Lower risk for properly authenticated endpoints
        
        # Path-based scoring
        path_lower = route_info.path.lower()
        if any(keyword in path_lower for keyword in ['payment', 'billing', 'transaction']):
            base_score += 2.0
        elif any(keyword in path_lower for keyword in ['auth', 'login', 'user']):
            base_score += 1.5
        elif any(keyword in path_lower for keyword in ['admin', 'manage']):
            base_score += 2.5
        
        # Security pattern scoring
        if any(pattern in content for pattern in self.security_patterns):
            base_score -= 0.5  # Lower risk if security patterns are present
        
        return min(max(base_score, 1.0), 10.0)  # Clamp between 1.0 and 10.0
    
    def can_handle_file(self, file_path: str, content: str) -> bool:
        """Check if this detector can handle the given file."""
        return self._is_flutter_file(file_path, content)
    
    def get_supported_extensions(self) -> Set[str]:
        """Get supported file extensions."""
        return {'.dart'} 