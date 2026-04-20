#!/usr/bin/env python3
"""
Validation utilities for the Enterprise Security Platform
"""

import re
import html
from typing import List, Optional, Any
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

# Regular expressions
TENANT_ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
URL_PATTERN = re.compile(
    r'^https?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
GITHUB_URL_PATTERN = re.compile(r'^https://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+/?$')
GITLAB_URL_PATTERN = re.compile(r'^https://gitlab\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+/?$')

VALID_SCAN_TYPES = {'sast', 'sca', 'secrets', 'container', 'iac', 'dast'}

def validate_tenant_id(tenant_id: str) -> bool:
    """
    Validate tenant ID format
    
    Args:
        tenant_id: Tenant ID to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not tenant_id or not isinstance(tenant_id, str):
        return False
    
    return bool(TENANT_ID_PATTERN.match(tenant_id))

def validate_repo_url(url: str, allowed_providers: Optional[List[str]] = None) -> bool:
    """
    Validate repository URL
    
    Args:
        url: Repository URL to validate
        allowed_providers: List of allowed providers (github, gitlab)
    
    Returns:
        True if valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    # Basic URL validation
    if not URL_PATTERN.match(url):
        return False
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except:
        return False
    
    # Check allowed providers
    if allowed_providers:
        provider = parsed.netloc.lower()
        if 'github.com' in provider and 'github' not in allowed_providers:
            return False
        if 'gitlab.com' in provider and 'gitlab' not in allowed_providers:
            return False
    
    # Specific provider validation
    if 'github.com' in parsed.netloc:
        return bool(GITHUB_URL_PATTERN.match(url))
    elif 'gitlab.com' in parsed.netloc:
        return bool(GITLAB_URL_PATTERN.match(url))
    
    # Generic git URL (allow any)
    return url.endswith('.git') or 'github' in parsed.netloc or 'gitlab' in parsed.netloc

def validate_email(email: str) -> bool:
    """
    Validate email address
    
    Args:
        email: Email address to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    return bool(EMAIL_PATTERN.match(email))

def validate_scan_types(scan_types: List[str]) -> bool:
    """
    Validate scan types
    
    Args:
        scan_types: List of scan types to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(scan_types, list):
        return False
    
    return all(st in VALID_SCAN_TYPES for st in scan_types)

def validate_severity(severity: str) -> bool:
    """
    Validate severity level
    
    Args:
        severity: Severity to validate
    
    Returns:
        True if valid, False otherwise
    """
    valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
    return severity.lower() in valid_severities

def validate_finding_status(status: str) -> bool:
    """
    Validate finding status
    
    Args:
        status: Status to validate
    
    Returns:
        True if valid, False otherwise
    """
    valid_statuses = {'open', 'in_progress', 'fixed', 'false_positive', 'accepted_risk'}
    return status in valid_statuses

def validate_port(port: int) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number to validate
    
    Returns:
        True if valid, False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address
    
    Args:
        ip: IP address to validate
    
    Returns:
        True if valid, False otherwise
    """
    ip_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    return bool(ip_pattern.match(ip))

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input (escape HTML, trim length)
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized text
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Trim length
    if len(text) > max_length:
        text = text[:max_length]
    
    # Escape HTML
    text = html.escape(text)
    
    return text

def validate_json_schema(data: dict, schema: dict) -> bool:
    """
    Validate JSON data against schema (simplified)
    
    Args:
        data: Data to validate
        schema: JSON schema
    
    Returns:
        True if valid, False otherwise
    """
    try:
        for key, expected_type in schema.items():
            if key not in data:
                return False
            
            value = data[key]
            
            # Check type
            if expected_type == 'string' and not isinstance(value, str):
                return False
            elif expected_type == 'number' and not isinstance(value, (int, float)):
                return False
            elif expected_type == 'integer' and not isinstance(value, int):
                return False
            elif expected_type == 'boolean' and not isinstance(value, bool):
                return False
            elif expected_type == 'array' and not isinstance(value, list):
                return False
            elif expected_type == 'object' and not isinstance(value, dict):
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"JSON schema validation error: {e}")
        return False

def validate_cve_id(cve_id: str) -> bool:
    """
    Validate CVE ID format
    
    Args:
        cve_id: CVE ID to validate
    
    Returns:
        True if valid, False otherwise
    """
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)
    return bool(cve_pattern.match(cve_id))

def validate_cwe_id(cwe_id: str) -> bool:
    """
    Validate CWE ID format
    
    Args:
        cwe_id: CWE ID to validate
    
    Returns:
        True if valid, False otherwise
    """
    cwe_pattern = re.compile(r'^CWE-\d{1,4}$', re.IGNORECASE)
    return bool(cwe_pattern.match(cwe_id))

def validate_date(date_str: str) -> bool:
    """
    Validate ISO date format
    
    Args:
        date_str: Date string to validate
    
    Returns:
        True if valid, False otherwise
    """
    from datetime import datetime
    
    try:
        datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return True
    except:
        return False