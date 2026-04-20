#!/usr/bin/env python3
"""
Checkov IaC Scanner Integration
"""

import json
import logging
import os
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class CheckovScanner(BaseScanner):
    """Checkov IaC scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "checkov"
        self.timeout = 300
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Checkov scan"""
        logger.info(f"Running Checkov scan on {repo_path}")
        
        output_file = os.path.join(repo_path, 'checkov-output.json')
        
        cmd = [
            "checkov",
            "-d", repo_path,
            "--output", "json",
            "--output-file-path", repo_path,
            "--quiet"
        ]
        
        try:
            await self._run_command(cmd)
            
            # Read output file
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = f.read()
                return self.parse_output(data)
            
            return []
            
        except Exception as e:
            logger.error(f"Checkov scan failed: {e}")
            return []
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Checkov JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            # Checkov output can be a list
            if isinstance(data, list):
                data = data[0] if data else {}
            
            for check in data.get('results', {}).get('failed_checks', []):
                finding = self._create_finding(
                    id=check.get('check_id', ''),
                    title=check.get('check_name', ''),
                    description=check.get('check_name', ''),
                    severity=check.get('severity', 'medium'),
                    file=check.get('file_path', ''),
                    line=check.get('file_line_range', [0])[0],
                    type='iac',
                    metadata={
                        'resource': check.get('resource', ''),
                        'guideline': check.get('guideline', ''),
                        'repo_id': check.get('repo_id', ''),
                        'file_abs_path': check.get('file_abs_path', ''),
                        'check_class': check.get('check_class', '')
                    }
                )
                findings.append(finding)
            
            # Also include skipped checks if needed
            for check in data.get('results', {}).get('skipped_checks', []):
                finding = self._create_finding(
                    id=check.get('check_id', ''),
                    title=f"[SKIPPED] {check.get('check_name', '')}",
                    description=f"Skipped: {check.get('suppress_comment', '')}",
                    severity='info',
                    file=check.get('file_path', ''),
                    line=check.get('file_line_range', [0])[0],
                    type='iac',
                    metadata={
                        'resource': check.get('resource', ''),
                        'status': 'skipped',
                        'reason': check.get('suppress_comment', '')
                    }
                )
                findings.append(finding)
            
            logger.info(f"Checkov found {len(findings)} IaC issues")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Checkov output: {e}")
            return []