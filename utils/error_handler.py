#!/usr/bin/env python3
"""
Error handling utilities for EndPointHawk
Provides structured error handling with security-aware error responses.
"""

import json
import traceback
from typing import Dict, Any, Optional, Callable
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories"""
    VALIDATION = "validation"
    SECURITY = "security"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    SYSTEM = "system"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class ValidationException(Exception):
    """Exception for validation errors"""
    def __init__(self, message: str, field: str = None, value: str = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(self.message)


class SecurityException(Exception):
    """Exception for security-related errors"""
    def __init__(self, message: str, error_code: str = None, details: str = None):
        self.message = message
        self.error_code = error_code
        self.details = details
        super().__init__(self.message)


class AuthenticationException(Exception):
    """Exception for authentication errors"""
    def __init__(self, message: str, method: str = None, details: str = None):
        self.message = message
        self.method = method
        self.details = details
        super().__init__(self.message)


class AuthorizationException(Exception):
    """Exception for authorization errors"""
    def __init__(self, message: str, resource: str = None, action: str = None):
        self.message = message
        self.resource = resource
        self.action = action
        super().__init__(self.message)


class NetworkException(Exception):
    """Exception for network-related errors"""
    def __init__(self, message: str, url: str = None, status_code: int = None):
        self.message = message
        self.url = url
        self.status_code = status_code
        super().__init__(self.message)


class ConfigurationException(Exception):
    """Exception for configuration errors"""
    def __init__(self, message: str, config_key: str = None, config_value: str = None):
        self.message = message
        self.config_key = config_key
        self.config_value = config_value
        super().__init__(self.message)


class ErrorHandler:
    """
    Centralized error handler with security-aware error responses.
    
    Features:
    - Structured error categorization
    - Security-aware error information disclosure
    - Custom exception handling
    - Error response formatting
    - Audit trail integration
    """
    
    def __init__(self, security_logger=None):
        """
        Initialize error handler.
        
        Args:
            security_logger: Security logger instance for audit trail
        """
        self.security_logger = security_logger
        self.error_mapping = {
            ValidationException: ErrorCategory.VALIDATION,
            SecurityException: ErrorCategory.SECURITY,
            AuthenticationException: ErrorCategory.AUTHENTICATION,
            AuthorizationException: ErrorCategory.AUTHORIZATION,
            NetworkException: ErrorCategory.NETWORK,
            ConfigurationException: ErrorCategory.CONFIGURATION,
        }
    
    def categorize_error(self, exception: Exception) -> ErrorCategory:
        """
        Categorize an exception.
        
        Args:
            exception: Exception to categorize
            
        Returns:
            Error category
        """
        exception_type = type(exception)
        return self.error_mapping.get(exception_type, ErrorCategory.UNKNOWN)
    
    def determine_severity(self, exception: Exception) -> ErrorSeverity:
        """
        Determine error severity.
        
        Args:
            exception: Exception to analyze
            
        Returns:
            Error severity
        """
        if isinstance(exception, SecurityException):
            return ErrorSeverity.HIGH
        elif isinstance(exception, (AuthenticationException, AuthorizationException)):
            return ErrorSeverity.MEDIUM
        elif isinstance(exception, ValidationException):
            return ErrorSeverity.LOW
        elif isinstance(exception, NetworkException):
            return ErrorSeverity.MEDIUM
        elif isinstance(exception, ConfigurationException):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.UNKNOWN
    
    def format_error_response(self, exception: Exception, include_details: bool = False) -> Dict[str, Any]:
        """
        Format error response with appropriate information disclosure.
        
        Args:
            exception: Exception to format
            include_details: Whether to include detailed error information
            
        Returns:
            Formatted error response
        """
        category = self.categorize_error(exception)
        severity = self.determine_severity(exception)
        
        response = {
            'error': True,
            'category': category.value,
            'severity': severity.value,
            'message': str(exception)
        }
        
        # Add category-specific information
        if isinstance(exception, ValidationException):
            response['field'] = exception.field
            if include_details:
                response['value'] = exception.value
        elif isinstance(exception, SecurityException):
            response['error_code'] = exception.error_code
            if include_details:
                response['details'] = exception.details
        elif isinstance(exception, AuthenticationException):
            response['method'] = exception.method
            if include_details:
                response['details'] = exception.details
        elif isinstance(exception, AuthorizationException):
            response['resource'] = exception.resource
            response['action'] = exception.action
        elif isinstance(exception, NetworkException):
            response['status_code'] = exception.status_code
            if include_details:
                response['url'] = exception.url
        elif isinstance(exception, ConfigurationException):
            response['config_key'] = exception.config_key
            if include_details:
                response['config_value'] = exception.config_value
        
        # Add stack trace only in development mode
        if include_details and hasattr(exception, '__traceback__'):
            response['traceback'] = traceback.format_exc()
        
        return response
    
    def handle_exception(self, exception: Exception, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Handle an exception with full context.
        
        Args:
            exception: Exception to handle
            context: Additional context information
            
        Returns:
            Error response
        """
        # Log the error for audit trail
        if self.security_logger:
            self.security_logger.error(
                f"Exception occurred: {type(exception).__name__}: {str(exception)}",
                extra={'context': context}
            )
        
        # Determine if we should include details based on environment
        include_details = self._should_include_details()
        
        # Format error response
        response = self.format_error_response(exception, include_details)
        
        # Add context if provided
        if context:
            response['context'] = context
        
        return response
    
    def _should_include_details(self) -> bool:
        """
        Determine if detailed error information should be included.
        
        Returns:
            True if details should be included
        """
        # In production, we typically don't want to expose detailed error information
        # This can be controlled by environment variables
        import os
        return os.environ.get('ENDPOINTHAWK_ENV', 'production').lower() == 'development'
    
    def validate_input(self, value: Any, validator: Callable, field_name: str = None, 
                      error_message: str = None) -> Any:
        """
        Validate input with custom validator.
        
        Args:
            value: Value to validate
            validator: Validation function
            field_name: Name of the field being validated
            error_message: Custom error message
            
        Returns:
            Validated value
            
        Raises:
            ValidationException: If validation fails
        """
        try:
            if validator(value):
                return value
            else:
                raise ValidationException(
                    error_message or f"Validation failed for {field_name or 'input'}",
                    field=field_name,
                    value=str(value)
                )
        except Exception as e:
            if isinstance(e, ValidationException):
                raise
            else:
                raise ValidationException(
                    f"Validation error: {str(e)}",
                    field=field_name,
                    value=str(value)
                )
    
    def validate_path_safety(self, path: str) -> bool:
        """
        Validate that a path is safe (no path traversal).
        
        Args:
            path: Path to validate
            
        Returns:
            True if path is safe
        """
        import os
        
        # Check for path traversal attempts
        dangerous_patterns = [
            '..',
            '~',
            '/etc/',
            '/root/',
            '/var/',
            '/sys/',
            '/proc/',
            '//',
        ]
        
        normalized_path = os.path.normpath(path)
        
        for pattern in dangerous_patterns:
            if pattern in normalized_path:
                return False
        
        # Check if path is absolute and outside allowed directories
        if os.path.isabs(normalized_path):
            # Only allow paths in current working directory or subdirectories
            cwd = os.getcwd()
            if not normalized_path.startswith(cwd):
                return False
        
        return True
    
    def validate_file_size(self, file_path: str, max_size: int = None) -> bool:
        """
        Validate file size.
        
        Args:
            file_path: Path to file
            max_size: Maximum allowed size in bytes
            
        Returns:
            True if file size is acceptable
        """
        import os
        
        if not os.path.exists(file_path):
            raise ValidationException(f"File does not exist: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        if max_size and file_size > max_size:
            raise ValidationException(
                f"File size {file_size} exceeds maximum allowed size {max_size}",
                field="file_size",
                value=str(file_size)
            )
        
        return True
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL format and safety.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid and safe
        """
        import re
        
        # Basic URL pattern
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        
        if not re.match(url_pattern, url):
            raise ValidationException(
                f"Invalid URL format: {url}",
                field="url",
                value=url
            )
        
        # Check for potentially dangerous URLs
        dangerous_patterns = [
            'file://',
            'ftp://',
            'javascript:',
            'data:',
        ]
        
        for pattern in dangerous_patterns:
            if url.lower().startswith(pattern):
                raise ValidationException(
                    f"Dangerous URL protocol: {url}",
                    field="url",
                    value=url
                )
        
        return True
    
    def create_validation_error(self, message: str, field: str = None, value: str = None) -> ValidationException:
        """Create a validation error"""
        return ValidationException(message, field, value)
    
    def create_security_error(self, message: str, error_code: str = None, details: str = None) -> SecurityException:
        """Create a security error"""
        return SecurityException(message, error_code, details)
    
    def create_authentication_error(self, message: str, method: str = None, details: str = None) -> AuthenticationException:
        """Create an authentication error"""
        return AuthenticationException(message, method, details)
    
    def create_authorization_error(self, message: str, resource: str = None, action: str = None) -> AuthorizationException:
        """Create an authorization error"""
        return AuthorizationException(message, resource, action)
    
    def create_network_error(self, message: str, url: str = None, status_code: int = None) -> NetworkException:
        """Create a network error"""
        return NetworkException(message, url, status_code)
    
    def create_configuration_error(self, message: str, config_key: str = None, config_value: str = None) -> ConfigurationException:
        """Create a configuration error"""
        return ConfigurationException(message, config_key, config_value)


def get_error_handler(security_logger=None) -> ErrorHandler:
    """
    Get an error handler instance.
    
    Args:
        security_logger: Security logger instance
        
    Returns:
        ErrorHandler instance
    """
    return ErrorHandler(security_logger) 