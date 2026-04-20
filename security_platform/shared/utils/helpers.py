#!/usr/bin/env python3
"""
Helper utilities for the Enterprise Security Platform
"""

import hashlib
import uuid
import re
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import json
import base64
from urllib.parse import urlparse

def generate_id(prefix: str = "") -> str:
    """
    Generate a unique ID
    
    Args:
        prefix: Optional prefix for the ID
    
    Returns:
        Unique ID string
    """
    unique = str(uuid.uuid4())
    if prefix:
        return f"{prefix}_{unique}"
    return unique

def generate_short_id(prefix: str = "") -> str:
    """
    Generate a short unique ID (first 8 chars of UUID)
    
    Args:
        prefix: Optional prefix for the ID
    
    Returns:
        Short unique ID string
    """
    unique = str(uuid.uuid4())[:8]
    if prefix:
        return f"{prefix}_{unique}"
    return unique

def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format
    
    Args:
        seconds: Duration in seconds
    
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to maximum length
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def parse_repo_url(url: str) -> Dict[str, str]:
    """
    Parse repository URL to extract components
    
    Args:
        url: Repository URL
    
    Returns:
        Dictionary with provider, owner, repo
    """
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
                'repo': match.group(2),
                'full_name': f"{match.group(1)}/{match.group(2)}"
            }
    
    # Try to parse with urlparse
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            return {
                'provider': parsed.netloc.split('.')[0],
                'owner': path_parts[0],
                'repo': path_parts[1].replace('.git', ''),
                'full_name': f"{path_parts[0]}/{path_parts[1]}".replace('.git', '')
            }
    except:
        pass
    
    return {
        'provider': 'unknown',
        'owner': 'unknown',
        'repo': 'unknown',
        'full_name': 'unknown/unknown'
    }

def mask_secret(secret: str, visible_chars: int = 4, mask_char: str = "*") -> str:
    """
    Mask a secret for display
    
    Args:
        secret: Secret to mask
        visible_chars: Number of characters to leave visible
        mask_char: Character to use for masking
    
    Returns:
        Masked secret
    """
    if not secret:
        return ""
    
    if len(secret) <= visible_chars:
        return mask_char * len(secret)
    
    visible = secret[:visible_chars]
    masked = mask_char * (len(secret) - visible_chars)
    return visible + masked

def calculate_hash(data: Any, algorithm: str = "sha256") -> str:
    """
    Calculate hash of data
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
    
    Returns:
        Hexadecimal hash string
    """
    if not isinstance(data, (str, bytes)):
        data = json.dumps(data, sort_keys=True)
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

def encode_json(data: Any) -> str:
    """
    Encode data as JSON string
    
    Args:
        data: Data to encode
    
    Returns:
        JSON string
    """
    return json.dumps(data, default=str, separators=(',', ':'))

def decode_json(json_str: str) -> Any:
    """
    Decode JSON string
    
    Args:
        json_str: JSON string
    
    Returns:
        Decoded data
    """
    return json.loads(json_str)

def base64_encode(data: str) -> str:
    """
    Encode string as base64
    
    Args:
        data: String to encode
    
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def base64_decode(data: str) -> str:
    """
    Decode base64 string
    
    Args:
        data: Base64 encoded string
    
    Returns:
        Decoded string
    """
    return base64.b64decode(data.encode('utf-8')).decode('utf-8')

def get_timestamp() -> str:
    """
    Get current timestamp in ISO format
    
    Returns:
        ISO format timestamp
    """
    return datetime.utcnow().isoformat() + "Z"

def parse_timestamp(timestamp: str) -> datetime:
    """
    Parse ISO timestamp
    
    Args:
        timestamp: ISO format timestamp
    
    Returns:
        Datetime object
    """
    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

def days_ago(days: int) -> str:
    """
    Get timestamp from X days ago
    
    Args:
        days: Number of days
    
    Returns:
        ISO timestamp
    """
    return (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"

def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Deep merge two dictionaries
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (overrides)
    
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

def chunk_list(lst: list, chunk_size: int) -> list:
    """
    Split a list into chunks
    
    Args:
        lst: List to split
        chunk_size: Size of each chunk
    
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def safe_get(data: dict, path: str, default: Any = None) -> Any:
    """
    Safely get nested dictionary value
    
    Args:
        data: Dictionary
        path: Dot notation path (e.g., 'a.b.c')
        default: Default value if not found
    
    Returns:
        Value or default
    """
    keys = path.split('.')
    value = data
    
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
            if value is None:
                return default
        else:
            return default
    
    return value

def normalize_severity(severity: str) -> str:
    """
    Normalize severity to standard levels
    
    Args:
        severity: Input severity
    
    Returns:
        Normalized severity
    """
    severity = severity.lower()
    
    mapping = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'moderate': 'medium',
        'low': 'low',
        'info': 'info',
        'informational': 'info',
        'none': 'info'
    }
    
    return mapping.get(severity, 'info')