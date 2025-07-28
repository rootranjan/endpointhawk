#!/usr/bin/env python3
"""
Security logging utilities for EndPointHawk
Provides secure logging with sensitive data sanitization and audit trail capabilities.
"""

import logging
import re
import json
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum


class LogLevel(Enum):
    """Log levels for security events"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SecurityLogLevel(Enum):
    """Security-specific log levels"""
    AUDIT = "AUDIT"
    SECURITY = "SECURITY"
    VIOLATION = "VIOLATION"
    ALERT = "ALERT"


class SecurityLogger:
    """
    Enhanced security logger with sensitive data sanitization and audit capabilities.
    
    Features:
    - Sensitive data redaction in log messages
    - Structured security event logging
    - Audit trail capabilities
    - Security event categorization
    - Compliance-ready logging
    """
    
    def __init__(self, name: str = "endpointhawk.security"):
        """
        Initialize security logger.
        
        Args:
            name: Logger name
        """
        self.logger = logging.getLogger(name)
        self._setup_sanitization_patterns()
        self._setup_security_handlers()
    
    def _setup_sanitization_patterns(self):
        """Setup patterns for sensitive data sanitization"""
        self.sensitive_patterns = [
            # Authentication patterns
            (r'password[=:]\s*\S+', r'password=***REDACTED***'),
            (r'token[=:]\s*\S+', r'token=***REDACTED***'),
            (r'secret[=:]\s*\S+', r'secret=***REDACTED***'),
            (r'key[=:]\s*\S+', r'key=***REDACTED***'),
            (r'auth[=:]\s*\S+', r'auth=***REDACTED***'),
            (r'Authorization:\s*\S+', r'Authorization: ***REDACTED***'),
            (r'Bearer\s+\S+', r'Bearer ***REDACTED***'),
            
            # API keys and tokens
            (r'api[_-]?key[=:]\s*\S+', r'api_key=***REDACTED***'),
            (r'access[_-]?token[=:]\s*\S+', r'access_token=***REDACTED***'),
            (r'refresh[_-]?token[=:]\s*\S+', r'refresh_token=***REDACTED***'),
            
            # Database credentials
            (r'db[_-]?password[=:]\s*\S+', r'db_password=***REDACTED***'),
            (r'database[_-]?password[=:]\s*\S+', r'database_password=***REDACTED***'),
            (r'connection[_-]?string[=:]\s*\S+', r'connection_string=***REDACTED***'),
            
            # File paths that might contain sensitive data
            (r'/etc/passwd', r'***SYSTEM_FILE***'),
            (r'/etc/shadow', r'***SYSTEM_FILE***'),
            (r'/root/', r'***ROOT_PATH***'),
            (r'/home/\w+/\.ssh/', r'***SSH_PATH***'),
            
            # Email addresses (partial redaction)
            (r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r'***@\2'),
            
            # IP addresses (for privacy)
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', r'***IP_ADDRESS***'),
            
            # Credit card patterns
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', r'***CREDIT_CARD***'),
            
            # Social security numbers
            (r'\b\d{3}-\d{2}-\d{4}\b', r'***SSN***'),
        ]
    
    def _setup_security_handlers(self):
        """Setup security-specific log handlers"""
        # Add custom security log level
        logging.addLevelName(25, "AUDIT")
        logging.addLevelName(35, "SECURITY")
        logging.addLevelName(45, "VIOLATION")
        logging.addLevelName(55, "ALERT")
    
    def _sanitize_message(self, message: str) -> str:
        """
        Sanitize log message to remove sensitive information.
        
        Args:
            message: Original log message
            
        Returns:
            Sanitized log message
        """
        if not message:
            return message
        
        sanitized = message
        for pattern, replacement in self.sensitive_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _log_security_event(self, level: str, message: str, event_data: Optional[Dict[str, Any]] = None):
        """
        Log a security event with structured data.
        
        Args:
            level: Log level
            message: Log message
            event_data: Additional event data
        """
        sanitized_message = self._sanitize_message(message)
        
        # Create structured log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': sanitized_message,
            'type': 'security_event'
        }
        
        if event_data:
            # Sanitize event data
            sanitized_data = {}
            for key, value in event_data.items():
                if isinstance(value, str):
                    sanitized_data[key] = self._sanitize_message(value)
                else:
                    sanitized_data[key] = value
            log_entry['event_data'] = sanitized_data
        
        # Log the structured entry
        if level == "AUDIT":
            self.logger.log(25, json.dumps(log_entry))
        elif level == "SECURITY":
            self.logger.log(35, json.dumps(log_entry))
        elif level == "VIOLATION":
            self.logger.log(45, json.dumps(log_entry))
        elif level == "ALERT":
            self.logger.log(55, json.dumps(log_entry))
        else:
            self.logger.log(getattr(logging, level.upper(), logging.INFO), json.dumps(log_entry))
    
    def debug(self, message: str, **kwargs):
        """Log debug message with sanitization"""
        self.logger.debug(self._sanitize_message(message), **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message with sanitization"""
        self.logger.info(self._sanitize_message(message), **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with sanitization"""
        self.logger.warning(self._sanitize_message(message), **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with sanitization"""
        self.logger.error(self._sanitize_message(message), **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with sanitization"""
        self.logger.critical(self._sanitize_message(message), **kwargs)
    
    def audit(self, message: str, event_data: Optional[Dict[str, Any]] = None):
        """Log audit event"""
        self._log_security_event("AUDIT", message, event_data)
    
    def security(self, message: str, event_data: Optional[Dict[str, Any]] = None):
        """Log security event"""
        self._log_security_event("SECURITY", message, event_data)
    
    def violation(self, message: str, event_data: Optional[Dict[str, Any]] = None):
        """Log security violation"""
        self._log_security_event("VIOLATION", message, event_data)
    
    def alert(self, message: str, event_data: Optional[Dict[str, Any]] = None):
        """Log security alert"""
        self._log_security_event("ALERT", message, event_data)
    
    def log_scan_request(self, repo_path: str, user_agent: str = None, ip_address: str = None):
        """Log scan request for audit trail"""
        event_data = {
            'action': 'scan_request',
            'repo_path': repo_path,
            'user_agent': user_agent,
            'ip_address': ip_address
        }
        self.audit(f"Scan request initiated for repository: {repo_path}", event_data)
    
    def log_path_access(self, file_path: str, operation: str = "read"):
        """Log file path access for security monitoring"""
        event_data = {
            'action': 'path_access',
            'file_path': file_path,
            'operation': operation
        }
        self.security(f"File path accessed: {file_path} ({operation})", event_data)
    
    def log_authentication_attempt(self, method: str, success: bool, details: str = None):
        """Log authentication attempt"""
        event_data = {
            'action': 'authentication_attempt',
            'method': method,
            'success': success,
            'details': details
        }
        level = "security" if success else "violation"
        message = f"Authentication attempt: {method} - {'SUCCESS' if success else 'FAILED'}"
        if details:
            message += f" - {details}"
        
        if success:
            self.security(message, event_data)
        else:
            self.violation(message, event_data)
    
    def log_security_finding(self, finding_type: str, severity: str, details: str):
        """Log security finding"""
        event_data = {
            'action': 'security_finding',
            'finding_type': finding_type,
            'severity': severity,
            'details': details
        }
        self.security(f"Security finding: {finding_type} ({severity}) - {details}", event_data)


def get_security_logger(name: str = "endpointhawk.security") -> SecurityLogger:
    """
    Get a security logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        SecurityLogger instance
    """
    return SecurityLogger(name) 