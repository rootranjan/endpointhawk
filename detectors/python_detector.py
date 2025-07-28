"""
Enhanced Python web framework route detector.
Supports FastAPI, Django, Flask, and modern Python web frameworks with comprehensive pattern detection.
"""

import re
import ast
import os
from typing import List, Dict, Optional, Set, Tuple, Any

from models import RouteInfo, Framework, HTTPMethod, AuthType, RiskLevel, RouteParameter, SecurityFinding
from detectors.base_detector import BaseDetector
from analyzers.template_resolver import get_template_resolver, FrameworkContext, ResolvedRoute


class PythonDetector(BaseDetector):
    """
    Enhanced Python detector with comprehensive modern framework support.
    Supports FastAPI, Django, Flask, Starlette, Quart, and enterprise patterns.
    """
    
    def __init__(self, framework: Framework = Framework.FASTAPI):
        super().__init__(framework)
        self.seen_routes = set()  # For deduplication
        
        # Initialize template resolver
        self.template_resolver = get_template_resolver(Framework.FASTAPI)
        
        # Enhanced Python framework detection patterns
        self.python_indicators = [
            # FastAPI patterns
            r'from\s+fastapi\s+import',
            r'import\s+fastapi',
            r'FastAPI\s*\(',
            r'@app\.(get|post|put|delete|patch|head|options)',
            r'APIRouter\s*\(',
            r'Depends\s*\(',
            r'Path\s*\(',
            r'Query\s*\(',
            r'Header\s*\(',
            r'Body\s*\(',
            
            # Django patterns
            r'from\s+django',
            r'import\s+django',
            r'django\.urls',
            r'django\.views',
            r'path\s*\(',
            r'url\s*\(',
            r're_path\s*\(',
            r'include\s*\(',
            r'from\s+rest_framework',
            r'APIView',
            r'ViewSet',
            r'ModelViewSet',
            
            # Flask patterns
            r'from\s+flask\s+import',
            r'import\s+flask',
            r'Flask\s*\(',
            r'@app\.route',
            r'Blueprint\s*\(',
            r'MethodView',
            r'flask_restful',
            r'Resource',
            
            # Modern async frameworks
            r'from\s+starlette',
            r'import\s+starlette',
            r'from\s+quart',
            r'import\s+quart',
            r'from\s+sanic',
            r'import\s+sanic',
            
            # Enterprise frameworks
            r'from\s+tornado',
            r'import\s+tornado',
            r'from\s+aiohttp',
            r'import\s+aiohttp',
        ]
        
        # Comprehensive Python framework patterns
        self.python_frameworks = {
            'fastapi': {
                'import_patterns': [
                    r'from\s+fastapi\s+import',
                    r'import\s+fastapi',
                    r'FastAPI\s*\(',
                    r'@app\.(get|post|put|delete|patch|head|options)',
                    r'APIRouter\s*\(',
                ],
                'route_patterns': [
                    # Standard decorator patterns
                    re.compile(r'@(\w+)\.(get|post|put|delete|patch|head|options)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'@(\w+)\.(get|post|put|delete|patch|head|options)\s*\(\s*f[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # add_api_route patterns
                    re.compile(r'(\w+)\.add_api_route\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.add_api_route\s*\(\s*f[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Router include patterns
                    re.compile(r'(\w+)\.include_router\s*\(\s*(\w+)'),
                    
                    # Modern async patterns
                    re.compile(r'async\s+def\s+\w+.*@(\w+)\.(get|post|put|delete|patch)'),
                    
                    # Path operations with dependencies
                    re.compile(r'@(\w+)\.(get|post|put|delete|patch|head|options)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`].*dependencies'),
                ],
                'dependency_patterns': [
                    r'Depends\s*\(',
                    r'Security\s*\(',
                    r'HTTPBearer\s*\(',
                    r'HTTPBasic\s*\(',
                    r'APIKeyHeader\s*\(',
                    r'APIKeyQuery\s*\(',
                    r'APIKeyCookie\s*\(',
                ],
                'model_patterns': [
                    r'BaseModel',
                    r'pydantic\.BaseModel',
                    r'Field\s*\(',
                    r'validator\s*\(',
                ]
            },
            'django': {
                'import_patterns': [
                    r'from\s+django',
                    r'import\s+django',
                    r'django\.urls',
                    r'django\.views',
                    r'from\s+rest_framework',
                    r'APIView',
                    r'ViewSet',
                ],
                'route_patterns': [
                    # URL patterns
                    re.compile(r'path\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'url\s*\(\s*r?[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r're_path\s*\(\s*r?[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # F-string patterns
                    re.compile(r'path\s*\(\s*f[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'url\s*\(\s*f[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Include patterns
                    re.compile(r'include\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'view_patterns': [
                    re.compile(r'class\s+(\w+)\s*\(\s*.*View'),
                    re.compile(r'class\s+(\w+)\s*\(\s*.*ViewSet'),
                    re.compile(r'def\s+(\w+)\s*\(\s*request'),
                    re.compile(r'@api_view\s*\(\s*\['),
                ],
                'drf_patterns': [
                    r'APIView',
                    r'ViewSet',
                    r'ModelViewSet',
                    r'GenericAPIView',
                    r'ListAPIView',
                    r'CreateAPIView',
                    r'RetrieveAPIView',
                    r'UpdateAPIView',
                    r'DestroyAPIView',
                    r'@api_view',
                    r'serializers\.',
                    r'permissions\.',
                ]
            },
            'flask': {
                'import_patterns': [
                    r'from\s+flask\s+import',
                    r'import\s+flask',
                    r'Flask\s*\(',
                    r'@app\.route',
                    r'Blueprint\s*\(',
                    r'flask_restful',
                ],
                'route_patterns': [
                    # Standard route decorators
                    re.compile(r'@(\w+)\.route\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'@(\w+)\.route\s*\(\s*f[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # URL rule patterns
                    re.compile(r'(\w+)\.add_url_rule\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.add_url_rule\s*\(\s*f[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Blueprint patterns
                    re.compile(r'(\w+)\.register_blueprint\s*\(\s*(\w+)'),
                    
                    # Flask-RESTful patterns
                    re.compile(r'api\.add_resource\s*\(\s*(\w+)\s*,\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Method-based routing
                    re.compile(r'@(\w+)\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'methods\s*=\s*\[\s*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
                    re.compile(r'methods\s*=\s*\[[\'"`](.*?)[\'"`]\]'),
                ],
                'restful_patterns': [
                    r'Resource',
                    r'MethodView',
                    r'flask_restful',
                    r'flask_restx',
                    r'flask_api',
                ]
            },
            'starlette': {
                'import_patterns': [
                    r'from\s+starlette',
                    r'import\s+starlette',
                    r'Starlette\s*\(',
                    r'Route\s*\(',
                    r'Mount\s*\(',
                ],
                'route_patterns': [
                    re.compile(r'Route\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'Mount\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
            },
            'aiohttp': {
                'import_patterns': [
                    r'from\s+aiohttp',
                    r'import\s+aiohttp',
                    r'web\.Application',
                    r'web\.RouteTableDef',
                ],
                'route_patterns': [
                    re.compile(r'@routes\.(get|post|put|delete|patch|head|options)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'app\.router\.add_route\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
            }
        }
        
        # Enhanced Python template and variable patterns
        self.python_patterns = {
            'var_assignment': re.compile(r'(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'const_assignment': re.compile(r'([A-Z_][A-Z0-9_]*)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'fstring': re.compile(r'f[\'"`]([^\'"`,]*\{[^\'"`,]*\}[^\'"`,]*)[\'"`]'),
            'format_method': re.compile(r'[\'"`]([^\'"`,]*\{\}[^\'"`,]*)[\'"`]\.format\s*\(([^)]+)\)'),
            'format_indexed': re.compile(r'[\'"`]([^\'"`,]*\{[0-9]+\}[^\'"`,]*)[\'"`]\.format\s*\(([^)]+)\)'),
            'format_named': re.compile(r'[\'"`]([^\'"`,]*\{[a-zA-Z_]\w*\}[^\'"`,]*)[\'"`]\.format\s*\(([^)]+)\)'),
            'percent_format': re.compile(r'[\'"`]([^\'"`,]*%[sdifr][^\'"`,]*)[\'"`]\s*%\s*\(([^)]+)\)'),
            'template_var': re.compile(r'\{(\w+)\}'),
            'template_indexed': re.compile(r'\{([0-9]+)\}'),
            'template_percent': re.compile(r'%[sdifr]'),
            
            # Environment variables
            'env_var': re.compile(r'os\.environ\.get\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'),
            'env_getenv': re.compile(r'os\.getenv\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'),
            
            # Config patterns
            'config_attr': re.compile(r'config\.(\w+)'),
            'settings_attr': re.compile(r'settings\.(\w+)'),
        }
        
        # Comprehensive Python authentication patterns
        self.auth_patterns = {
            AuthType.JWT: [
                r'jwt\.decode',
                r'PyJWT',
                r'python-jose',
                r'verify_jwt',
                r'JWTBearer',
                r'HTTPBearer',
                r'bearer_token',
                r'access_token',
                r'refresh_token',
            ],
            AuthType.OAUTH: [
                r'oauth',
                r'OAuth2PasswordBearer',
                r'OAuth2AuthorizationCodeBearer',
                r'authlib',
                r'python-social-auth',
                r'django-oauth-toolkit',
                r'flask-oauthlib',
            ],
            AuthType.SESSION: [
                r'session',
                r'SessionAuthentication',
                r'django\.contrib\.sessions',
                r'flask-session',
                r'secure_session',
            ],
            AuthType.API_KEY: [
                r'api_key',
                r'APIKeyHeader',
                r'APIKeyQuery',
                r'APIKeyCookie',
                r'X-API-Key',
                r'api-key',
            ],
            AuthType.BASIC: [
                r'HTTPBasic',
                r'BasicAuthentication',
                r'basic_auth',
                r'http_basic',
            ],
            AuthType.CUSTOM: [
                r'custom_auth',
                r'authenticate',
                r'login_required',
                r'permission_required',
                r'staff_member_required',
                r'user_passes_test',
            ]
        }
        
        # Modern Python security and middleware patterns
        self.security_patterns = [
            # CORS
            r'CORSMiddleware',
            r'flask-cors',
            r'django-cors-headers',
            
            # Rate limiting
            r'slowapi',
            r'flask-limiter',
            r'django-ratelimit',
            
            # Security headers
            r'SecurityHeadersMiddleware',
            r'django-security',
            r'flask-talisman',
            
            # Input validation
            r'pydantic',
            r'marshmallow',
            r'wtforms',
            r'django-rest-framework',
            
            # CSRF protection
            r'csrf',
            r'CsrfProtect',
            r'CSRFMiddleware',
        ]
        
        # Enterprise and microservice patterns
        self.enterprise_patterns = [
            # Service discovery
            r'consul',
            r'etcd',
            r'service_registry',
            
            # Monitoring
            r'prometheus_client',
            r'opentelemetry',
            r'jaeger',
            r'zipkin',
            
            # Health checks
            r'health_check',
            r'readiness_probe',
            r'liveness_probe',
            
            # Circuit breakers
            r'circuit_breaker',
            r'hystrix',
            r'pybreaker',
            
            # Message queues
            r'celery',
            r'rq',
            r'kombu',
            r'pika',
        ]
    
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """
        Enhanced Python route detection with f-string and .format() template resolution
        """
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self._is_python_file(file_path, content):
            return routes
        
        try:
            # Step 1: Extract Python variables and constants
            variables = self._extract_python_variables(content)
            
            # Step 2: Detect Python web framework
            framework_info = self._detect_python_framework(content)
            
            # Step 3: Extract route definitions with template resolution
            route_definitions = self._extract_python_route_definitions(content, variables, framework_info)
            
            # Step 4: Process each route definition
            for route_def in route_definitions:
                try:
                    # Create framework context for template resolution
                    context = FrameworkContext(
                        framework=self._get_framework_enum(framework_info.get('framework', 'fastapi')),
                        file_path=file_path,
                        file_content=content,
                        variables=variables,
                        configuration=framework_info
                    )
                    
                    # Resolve template if needed
                    if any(marker in route_def['path'] for marker in ['f"', "f'", '.format(', '%s', '%d']):
                        resolved = self.template_resolver.resolve_template(route_def['path'], context)
                        final_path = resolved.resolved_path
                        path_params = resolved.path_parameters
                        query_params = resolved.query_parameters
                        original_path = route_def['path']
                        template_metadata = resolved.metadata
                    else:
                        final_path = self._normalize_python_path(route_def['path'])
                        path_params = self._extract_python_path_params(final_path)
                        query_params = []
                        original_path = route_def['path']
                        template_metadata = {}
                    
                    # Convert HTTP method
                    http_method = self._convert_to_http_method(route_def['method'])
                    if not http_method:
                        continue
                    
                    # Check for duplicates
                    route_key = (http_method.value, final_path, file_path)
                    if route_key in self.seen_routes:
                        continue
                    self.seen_routes.add(route_key)
                    
                    # Create enhanced route info
                    route_info = self._create_enhanced_python_route_info(
                        method=http_method,
                        path=final_path,
                        original_path=original_path,
                        file_path=file_path,
                        line_number=route_def.get('line_number', 1),
                        path_params=path_params,
                        query_params=query_params,
                        variables=variables,
                        framework_info=framework_info,
                        route_def=route_def,
                        template_metadata=template_metadata,
                        content=content
                    )
                    
                    routes.append(route_info)
        
                except Exception as e:
                    print(f"Error processing Python route: {e}")
                    continue
            
        except Exception as e:
            print(f"Error processing Python routes in {file_path}: {e}")
        
        return routes
    
    def _is_python_file(self, file_path: str, content: str) -> bool:
        """Check if file is a Python web framework file"""
        if not file_path.endswith('.py'):
            return False
        
        # Check for web framework indicators
        web_indicators = [
            'from fastapi import',
            'import fastapi',
            'from flask import',
            'import flask',
            'from django',
            'import django',
            '@app.route',
            '@app.get',
            '@app.post',
            'FastAPI(',
            'Flask(',
            'path(',
            'url(',
            'add_api_route',
            'APIRouter'
        ]
        
        return any(indicator in content for indicator in web_indicators)
    
    def _extract_python_variables(self, content: str) -> Dict[str, str]:
        """Dynamic runtime variable extraction with comprehensive Python template literal support"""
        variables = {}
        
        # Step 1: Extract all variable declarations dynamically
        var_patterns = [
            # Standard variable assignments
            r'(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            # F-string declarations
            r'(\w+)\s*=\s*f[\'"`]([^\'"`,]+)[\'"`]',
            # Template literal declarations
            r'(\w+)\s*=\s*[\'"`]([^\'"`,]+)\{([^\'"`,]+)\}[^\'"`,]*[\'"`]',
            # Numeric and boolean assignments
            r'(\w+)\s*=\s*(\d+|True|False|None)',
            # Enhanced patterns for complex assignments
            r'(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]\s*\+\s*[\'"`]([^\'"`,]+)[\'"`]',
            r'(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]\s*\+\s*(\w+)',
            # Class attribute assignments
            r'self\.(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            # Module-level constants
            r'(\w+)\s*:\s*str\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
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
        
        # Step 2: Extract environment variables and settings
        env_patterns = [
            r'os\.environ\.get\s*\(\s*[\'"`]([A-Z_][A-Z0-9_]*)[\'"`]',
            r'settings\.([A-Z_][A-Z0-9_]*)',
            r'config\.([A-Z_][A-Z0-9_]*)',
            r'os\.environ\[[\'"`]([A-Z_][A-Z0-9_]*)[\'"`]\]',
        ]
        
        for pattern in env_patterns:
            matches = re.findall(pattern, content)
            for var_name in matches:
                variables[var_name] = f"${{{var_name}}}"
        
        # Step 3: Extract class and module level constants
        const_pattern = re.compile(r'class\s+\w+.*?:\s*([^}]+?)(?=\n\s*(?:class|def|$))', re.DOTALL)
        class_blocks = const_pattern.findall(content)
        for block in class_blocks:
            const_matches = self.python_patterns['const_assignment'].findall(block)
            for var_name, var_value in const_matches:
                variables[var_name] = var_value
        
        # Step 4: Extract import statements
        import_patterns = [
            r'from\s+(\w+)\s+import\s+(\w+)',
            r'import\s+(\w+)',
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    module, var_name = match
                    variables[var_name] = f"IMPORT:{module}"
                else:
                    module = match
                    variables[module] = f"IMPORT:{module}"
        
        # Step 5: Dynamic template literal resolution
        # Find all f-string and .format() patterns and resolve them recursively
        template_patterns = [
            r'\{([^}]+)\}',  # F-string variables
            r'\{(\w+)\}',    # Simple format variables
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
            template_pattern = r'\{([^}]+)\}'
            nested_matches = re.findall(template_pattern, value)
            
            if nested_matches:
                # Resolve nested templates
                for nested_var in nested_matches:
                    nested_var = nested_var.strip()
                    if nested_var in variables:
                        nested_value = self._resolve_nested_template(nested_var, variables, content, depth + 1, visited)
                        value = value.replace(f'{{{nested_var}}}', nested_value)
            
            return value
        finally:
            # Remove from visited set when done
            visited.discard(template_var)
    
    def _detect_python_framework(self, content: str) -> Dict[str, Any]:
        """Detect which Python web framework is being used"""
        framework_info = {
            'framework': 'fastapi',
            'confidence': 0.0,
            'patterns': []
        }
        
        for framework_name, framework_data in self.python_frameworks.items():
            confidence = 0.0
            matched_patterns = []
            
            # Check import patterns
            for import_pattern in framework_data['import_patterns']:
                if re.search(import_pattern, content, re.IGNORECASE):
                    confidence += 3.0
                    matched_patterns.append(f"import:{import_pattern}")
            
            # Check route patterns
            for route_pattern in framework_data['route_patterns']:
                matches = route_pattern.findall(content)
                if matches:
                    confidence += 2.0 * len(matches)
                    matched_patterns.append(f"route:{route_pattern.pattern}")
            
            # Check framework-specific patterns
            if 'method_decorators' in framework_data:
                for method_pattern in framework_data['method_decorators']:
                    matches = method_pattern.findall(content)
                    if matches:
                        confidence += 1.5 * len(matches)
                        matched_patterns.append(f"method:{method_pattern.pattern}")
            
            if confidence > framework_info['confidence']:
                framework_info = {
                    'framework': framework_name,
                    'confidence': confidence,
                    'patterns': matched_patterns
                }
        
        return framework_info
    
    def _extract_python_route_definitions(self, content: str, variables: Dict[str, str], framework_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract route definitions from Python web framework code"""
        routes = []
        lines = content.split('\n')
        framework = framework_info.get('framework', 'fastapi')
        
        if framework in self.python_frameworks:
            framework_data = self.python_frameworks[framework]
            
            # Extract routes using framework-specific patterns
            for pattern in framework_data['route_patterns']:
                for i, line in enumerate(lines):
                    match = pattern.search(line)
                    if match:
                        groups = match.groups()
                        
                        if len(groups) >= 2:
                            app_var = groups[0] if len(groups) > 2 else 'app'
                            method = groups[1] if 'method_decorators' in framework_data else 'GET'
                            path = groups[2] if len(groups) > 2 else groups[1]
                            
                            # For frameworks without explicit method in pattern
                            if framework == 'django':
                                method = self._extract_django_method(lines, i)
                            elif framework == 'flask':
                                method = self._extract_flask_method(lines, i)
                            
                            # Handle template strings
                            if any(template_marker in line for template_marker in ['f"', "f'", '.format(', '%']):
                                # Extract the full template expression
                                template_match = self._extract_template_expression(line)
                                if template_match:
                                    path = template_match
                            
                            routes.append({
                                'path': path,
                                'method': method.upper(),
                                'line_number': i + 1,
                                'app_var': app_var,
                                'framework': framework,
                                'raw_line': line.strip()
                            })
        
        return routes
    
    def _extract_template_expression(self, line: str) -> Optional[str]:
        """Extract template expression from Python code line"""
        # Extract f-strings
        fstring_match = self.python_patterns['fstring'].search(line)
        if fstring_match:
            return f'f"{fstring_match.group(1)}"'
        
        # Extract .format() calls
        format_match = self.python_patterns['format_method'].search(line)
        if format_match:
            return f'"{format_match.group(1)}".format({format_match.group(2)})'
        
        # Extract % formatting
        percent_match = self.python_patterns['percent_format'].search(line)
        if percent_match:
            return f'"{percent_match.group(1)}" % ({percent_match.group(2)})'
        
            return None
    
    def _extract_django_method(self, lines: List[str], line_index: int) -> str:
        """Extract HTTP method from Django view context"""
        # Check surrounding lines for view class methods
        for offset in range(-5, 6):
            check_index = line_index + offset
            if 0 <= check_index < len(lines):
                line = lines[check_index]
                method_match = re.search(r'def\s+(get|post|put|delete|patch|head|options)', line, re.IGNORECASE)
                if method_match:
                    return method_match.group(1).upper()
        
        return 'GET'  # Default for Django
    
    def _extract_flask_method(self, lines: List[str], line_index: int) -> str:
        """Extract HTTP method from Flask route context"""
        current_line = lines[line_index]
        
        # Check for methods parameter in @app.route
        method_match = re.search(r'methods\s*=\s*\[\s*[\'"`]([^\'"`]+)[\'"`]', current_line, re.IGNORECASE)
        if method_match:
            return method_match.group(1).upper()
        
        # Check surrounding lines
        for offset in [-2, -1, 1, 2]:
            check_index = line_index + offset
            if 0 <= check_index < len(lines):
                line = lines[check_index]
                method_match = re.search(r'methods\s*=\s*\[\s*[\'"`]([^\'"`]+)[\'"`]', line, re.IGNORECASE)
                if method_match:
                    return method_match.group(1).upper()
        
        return 'GET'  # Default for Flask
    
    def _normalize_python_path(self, path: str) -> str:
        """Normalize Python route path"""
        # Remove quotes and f-string prefix
        path = re.sub(r'^f?[\'"`]|[\'"`]$', '', path)
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Clean up multiple slashes
        path = re.sub(r'/+', '/', path)
        
        # Remove trailing slash unless root
        if path.endswith('/') and path != '/':
            path = path[:-1]
        
        return path
    
    def _extract_python_path_params(self, path: str) -> List[str]:
        """Extract path parameters from Python route path"""
        params = []
        
        # FastAPI/Django style: {param}
        path_params = re.findall(r'\{(\w+)\}', path)
        params.extend(path_params)
        
        # Flask style: <param>
        flask_params = re.findall(r'<(\w+)>', path)
        params.extend(flask_params)
        
        # Flask typed parameters: <int:param>
        flask_typed = re.findall(r'<\w+:(\w+)>', path)
        params.extend(flask_typed)
        
        # Django style: (?P<param>\w+)
        django_params = re.findall(r'\(\?P<(\w+)>[^)]+\)', path)
        params.extend(django_params)
        
        return list(set(params))  # Remove duplicates
    
    def _get_framework_enum(self, framework_name: str) -> Framework:
        """Convert framework name to Framework enum"""
        framework_mapping = {
            'fastapi': Framework.FASTAPI,
            'django': Framework.DJANGO,
            'flask': Framework.FLASK
        }
        
        return framework_mapping.get(framework_name, Framework.FASTAPI)
    
    def _convert_to_http_method(self, method_str: str) -> Optional[HTTPMethod]:
        """Convert string method to HTTPMethod enum"""
        method_mapping = {
            'GET': HTTPMethod.GET,
            'POST': HTTPMethod.POST,
            'PUT': HTTPMethod.PUT,
            'DELETE': HTTPMethod.DELETE,
            'PATCH': HTTPMethod.PATCH,
            'HEAD': HTTPMethod.HEAD,
            'OPTIONS': HTTPMethod.OPTIONS,
        }
        
        return method_mapping.get(method_str.upper())
    
    def _create_enhanced_python_route_info(self, method: HTTPMethod, path: str, original_path: str,
                                          file_path: str, line_number: int, path_params: List[str],
                                          query_params: List[str], variables: Dict[str, str],
                                          framework_info: Dict[str, Any], route_def: Dict[str, Any],
                                          template_metadata: Dict[str, Any], content: str) -> RouteInfo:
        """Create enhanced RouteInfo with Python-specific template resolution context"""
        
        # Extract authentication info
        auth_info = self._extract_python_auth_info(content, route_def)
        
        # Create route parameters
        route_parameters = []
        
        # Add path parameters
        for param in path_params:
            route_parameters.append(RouteParameter(
                name=param,
                type="string",
                required=True,
                location="path",
                description=f"Python path parameter: {param}"
            ))
        
        # Add query parameters
        for param in query_params:
            route_parameters.append(RouteParameter(
                name=param,
                type="string",
                required=False,
                location="query",
                description=f"Query parameter: {param}"
            ))
        
        # Enhanced metadata
        metadata = {
            'original_template': original_path if any(marker in original_path for marker in ['f"', "f'", '.format(', '%']) else None,
            'resolved_variables': {k: v for k, v in variables.items() if k in original_path},
            'path_parameters': path_params,
            'query_parameters': query_params,
            'template_resolution': any(marker in original_path for marker in ['f"', "f'", '.format(', '%']),
            'python_framework': framework_info.get('framework'),
            'framework_confidence': framework_info.get('confidence'),
            'app_variable': route_def.get('app_var'),
            'raw_definition': route_def.get('raw_line'),
            **template_metadata
        }
        
        # Create route info
        route_info = RouteInfo(
            method=method,
            path=path,
            file_path=file_path,
            line_number=line_number,
            framework=self._get_framework_enum(framework_info.get('framework', 'fastapi')),
            auth_type=auth_info.get('type', AuthType.UNKNOWN),
            auth_required=auth_info.get('required', False),
            parameters=route_parameters,
            metadata=metadata
        )
        
        # Set original path for prefix resolution
        if any(marker in original_path for marker in ['f"', "f'", '.format(', '%']):
            route_info.original_path = original_path
        
        # Risk assessment
        route_info.risk_level = self._assess_python_risk_level(path, method.value, route_info.auth_type, framework_info)
        route_info.risk_score = self._calculate_python_risk_score(route_info, content, route_def)
        
        return route_info
    
    def _extract_python_auth_info(self, content: str, route_def: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication information from Python content"""
        auth_info = {
            'type': AuthType.UNKNOWN,
            'required': False
        }
        
        # Check for Python auth patterns
        for auth_type, patterns in self.auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    auth_info['type'] = auth_type
                    auth_info['required'] = True
                    return auth_info
        
        return auth_info
    
    def _assess_python_risk_level(self, path: str, method: str, auth_type: AuthType, framework_info: Dict[str, Any]) -> RiskLevel:
        """Assess risk level for Python routes"""
        risk_score = 0
        
        # Method-based risk
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            risk_score += 2
        
        # Path-based risk
        high_risk_patterns = [
            r'/admin', r'/api/admin', r'/internal',
            r'/debug', r'/docs', r'/openapi',
            r'/delete', r'/upload', r'/config'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                risk_score += 3
                break
        
        # Authentication risk
        if auth_type == AuthType.UNKNOWN:
            risk_score += 4
        elif auth_type in [AuthType.BASIC, AuthType.API_KEY]:
            risk_score += 1
        
        # Framework-specific risks
        framework = framework_info.get('framework')
        if framework == 'flask':
            risk_score += 1  # Flask requires more manual security setup
        
        # Map score to risk level
        if risk_score >= 7:
            return RiskLevel.CRITICAL
        elif risk_score >= 5:
            return RiskLevel.HIGH
        elif risk_score >= 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_python_risk_score(self, route_info: RouteInfo, content: str, route_def: Dict[str, Any]) -> float:
        """Calculate detailed risk score for Python routes"""
        base_score = 0.0
        risk_factors = []
        
        # Method-based risk
        method_risks = {
            HTTPMethod.GET: 1.0,
            HTTPMethod.POST: 2.0,
            HTTPMethod.PUT: 2.5,
            HTTPMethod.DELETE: 3.0,
            HTTPMethod.PATCH: 2.0,
            HTTPMethod.HEAD: 0.5,
            HTTPMethod.OPTIONS: 0.5,
            HTTPMethod.ALL: 3.5      # Wildcard methods - high risk
        }
        base_score += method_risks.get(route_info.method, 1.0)
        
        if route_info.method in [HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE, HTTPMethod.ALL]:
            risk_factors.append(f"High-risk HTTP method: {route_info.method}")
        
        # Authentication risk
        if route_info.auth_type == AuthType.UNKNOWN:
            base_score += 3.0
            risk_factors.append("No authentication detected")
        
        # Parameter validation risk
        if route_info.parameters:
            param_count = len(route_info.parameters)
            base_score += 0.5 * param_count
            risk_factors.append("Route parameters")
        
        # Template resolution risk
        if route_info.metadata.get('template_resolution'):
            base_score += 1.0
            risk_factors.append("Dynamic route construction")
        
        # Framework-specific risks
        framework = route_info.metadata.get('python_framework')
        if framework == 'flask':
            base_score += 1.0
            risk_factors.append("Flask (requires manual security configuration)")
        elif framework == 'django':
            base_score += 0.5
            risk_factors.append("Django (good built-in security)")
        
        # Store risk factors
        route_info.risk_factors = risk_factors
        
        return min(base_score, 10.0)  # Cap at 10.0 