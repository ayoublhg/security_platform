#!/usr/bin/env python3
"""
Gitleaks Secrets Scanner Integration
"""

import json
import logging
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class GitleaksScanner(BaseScanner):
    """Gitleaks secrets scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "gitleaks"
        self.timeout = 180
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Gitleaks scan"""
        logger.info(f"Running Gitleaks scan on {repo_path}")
        
        cmd = [
            "gitleaks", "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--no-git"
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Gitleaks JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            # Gitleaks output can be array or object
            if isinstance(data, dict):
                data = data.get('findings', [])
            
            for finding in data:
                finding_obj = self._create_finding(
                    id=finding.get('Fingerprint', ''),
                    title=f"Secret found: {finding.get('RuleID', 'unknown')}",
                    description=finding.get('Description', ''),
                    severity=finding.get('Severity', 'high'),
                    file=finding.get('File', ''),
                    line=finding.get('StartLine', 0),
                    type='secret',
                    metadata={
                        'secret_type': finding.get('RuleID', ''),
                        'entropy': finding.get('Entropy', 0),
                        'commit': finding.get('Commit', ''),
                        'author': finding.get('Author', ''),
                        'email': finding.get('Email', ''),
                        'date': finding.get('Date', ''),
                        'message': finding.get('Message', ''),
                        'tags': finding.get('Tags', [])
                    }
                )
                findings.append(finding_obj)
            
            logger.info(f"Gitleaks found {len(findings)} secrets")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gitleaks output: {e}")
            return []