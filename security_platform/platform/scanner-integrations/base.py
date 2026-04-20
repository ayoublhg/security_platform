#!/usr/bin/env python3
"""
Base Scanner Class - All scanners inherit from this
"""

import asyncio
import logging
import json
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import os
import tempfile

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.timeout = 300  # Default 5 minutes
        
    @abstractmethod
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Run the scanner on the repository
        Returns a list of findings
        """
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse scanner output into standard format"""
        pass
    
    async def _run_command(self, cmd: List[str], timeout: Optional[int] = None) -> str:
        """Run a shell command and return output"""
        timeout = timeout or self.timeout
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise TimeoutError(f"Scanner timed out after {timeout}s")
            
            if proc.returncode not in [0, 1]:  # 1 often means findings found
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Scanner failed with code {proc.returncode}: {error_msg}")
                return ""
            
            return stdout.decode()
            
        except Exception as e:
            logger.error(f"Error running command {' '.join(cmd)}: {e}")
            raise
    
    def _save_output(self, output: str, filename: str) -> str:
        """Save output to file and return path"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(output)
            return f.name
    
    def _map_severity(self, severity: str) -> str:
        """Map scanner-specific severity to standard levels"""
        mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFO': 'info',
            'WARNING': 'medium',
            'ERROR': 'high'
        }
        return mapping.get(severity.upper(), 'info')
    
    def _create_finding(self, **kwargs) -> Dict[str, Any]:
        """Create a standardized finding object"""
        finding = {
            'id': kwargs.get('id', ''),
            'title': kwargs.get('title', 'Unknown finding'),
            'description': kwargs.get('description', ''),
            'severity': self._map_severity(kwargs.get('severity', 'info')),
            'file': kwargs.get('file', ''),
            'line': kwargs.get('line', 0),
            'scanner': self.name.lower(),
            'type': kwargs.get('type', 'vulnerability'),
            'metadata': kwargs.get('metadata', {}),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add CVE if present
        if 'cve' in kwargs:
            finding['cve'] = kwargs['cve']
        
        # Add CWE if present
        if 'cwe' in kwargs:
            finding['cwe'] = kwargs['cwe']
        
        return finding