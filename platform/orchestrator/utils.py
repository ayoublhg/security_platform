#!/usr/bin/env python3
"""
Utility functions for orchestrator
"""

import hashlib
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import re

def generate_scan_id() -> str:
    """Generate unique scan ID"""
    return str(uuid.uuid4())

def generate_finding_id(scan_id: str, scanner: str, file_path: str, line: int) -> str:
    """Generate unique finding ID"""
    unique_str = f"{scan_id}:{scanner}:{file_path}:{line}"
    return hashlib.md5(unique_str.encode()).hexdigest()[:16]

def parse_repo_url(url: str) -> Dict[str, str]:
    """Parse repository URL to extract provider and repo name"""
    patterns = {
        'github': r'github\.com[:/]([^/]+)/([^/.]+)',
        'gitlab': r'gitlab\.com[:/]([^/]+)/([^/.]+)',
        'bitbucket': r'bitbucket\.org[:/]([^/]+)/([^/.]+)'
    }
    
    for provider, pattern in patterns.items():
        match = re.search(pattern, url)
        if match:
            return {
                'provider': provider,
                'owner': match.group(1),
                'repo': match.group(2)
            }
    
    return {
        'provider': 'unknown',
        'owner': 'unknown',
        'repo': 'unknown'
    }

def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string to max length"""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."

def safe_json_loads(data: str, default: Any = None) -> Any:
    """Safely load JSON string"""
    try:
        return json.loads(data)
    except:
        return default

def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask secret for display"""
    if len(secret) <= visible_chars:
        return "*" * len(secret)
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars)

def validate_tenant_id(tenant_id: str) -> bool:
    """Validate tenant ID format"""
    return bool(re.match(r'^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$', tenant_id))

def validate_repo_url(url: str) -> bool:
    """Validate repository URL"""
    return url.startswith(('https://github.com/', 'https://gitlab.com/'))