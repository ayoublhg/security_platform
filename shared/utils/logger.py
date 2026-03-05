#!/usr/bin/env python3
"""
Logging configuration for the Enterprise Security Platform
"""

import logging
import logging.handlers
import sys
import os
from datetime import datetime
import json
from typing import Dict, Any, Optional

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage()
        }
        
        # Add exception info if present
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra'):
            log_record.update(record.extra)
        
        return json.dumps(log_record)

def setup_logging(service_name: str = "security-platform", 
                  log_level: str = "INFO",
                  log_format: str = "json",
                  log_file: Optional[str] = None) -> None:
    """
    Setup logging configuration for the application
    
    Args:
        service_name: Name of the service for logging
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: 'json' for structured logging, 'text' for plain text
        log_file: Optional file path for log output
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Create formatter
    if log_format == 'json':
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        # Rotating file handler (10 MB per file, keep 5 backups)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Set specific levels for noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    # Add service context to all logs
    old_factory = logging.getLogRecordFactory()
    
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.service = service_name
        return record
    
    logging.setLogRecordFactory(record_factory)
    
    # Log startup
    root_logger.info(f"Logging configured for {service_name} at level {log_level}")

def get_logger(name: str, extra: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Get a logger with optional extra context
    
    Args:
        name: Logger name (usually __name__)
        extra: Additional context to include in all log messages
    
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    if extra:
        # Create a wrapper that adds extra context
        class ContextLogger:
            def __init__(self, logger, extra):
                self._logger = logger
                self._extra = extra
            
            def _add_extra(self, msg, kwargs):
                if 'extra' not in kwargs:
                    kwargs['extra'] = {}
                kwargs['extra'].update(self._extra)
                return msg, kwargs
            
            def debug(self, msg, *args, **kwargs):
                msg, kwargs = self._add_extra(msg, kwargs)
                self._logger.debug(msg, *args, **kwargs)
            
            def info(self, msg, *args, **kwargs):
                msg, kwargs = self._add_extra(msg, kwargs)
                self._logger.info(msg, *args, **kwargs)
            
            def warning(self, msg, *args, **kwargs):
                msg, kwargs = self._add_extra(msg, kwargs)
                self._logger.warning(msg, *args, **kwargs)
            
            def error(self, msg, *args, **kwargs):
                msg, kwargs = self._add_extra(msg, kwargs)
                self._logger.error(msg, *args, **kwargs)
            
            def critical(self, msg, *args, **kwargs):
                msg, kwargs = self._add_extra(msg, kwargs)
                self._logger.critical(msg, *args, **kwargs)
            
            def exception(self, msg, *args, **kwargs):
                msg, kwargs = self._add_extra(msg, kwargs)
                self._logger.exception(msg, *args, **kwargs)
        
        return ContextLogger(logger, extra)  # type: ignore
    
    return logger

class AuditLogger:
    """Specialized logger for audit events"""
    
    def __init__(self, service_name: str = "security-platform"):
        self.logger = logging.getLogger(f"{service_name}.audit")
    
    def log(self, action: str, user_id: str, tenant_id: str,
            resource_type: str, resource_id: str,
            status: str = "success",
            details: Optional[Dict] = None,
            ip_address: Optional[str] = None) -> None:
        """
        Log an audit event
        
        Args:
            action: Action performed (e.g., 'scan.created', 'finding.updated')
            user_id: User who performed the action
            tenant_id: Tenant context
            resource_type: Type of resource affected
            resource_id: ID of the resource
            status: 'success' or 'failure'
            details: Additional details about the action
            ip_address: Client IP address
        """
        audit_record = {
            'audit': True,
            'action': action,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'status': status,
            'ip_address': ip_address,
            'details': details or {}
        }
        
        self.logger.info("Audit event", extra=audit_record)