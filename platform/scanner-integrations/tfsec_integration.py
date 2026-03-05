#!/usr/bin/env python3
"""
Tfsec IaC Scanner Integration
"""

import json
import logging
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class TfsecScanner(BaseScanner):
    """Tfsec Terraform scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "tfsec"
        self.timeout = 180
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run tfsec scan"""
        logger.info(f"Running tfsec scan on {repo_path}")
        
        cmd = [
            "tfsec",
            repo_path,
            "--format", "json",
            "--soft-fail"
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"Tfsec scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse tfsec JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for result in data.get('results', []):
                for finding in result.get('results', []):
                    finding_obj = self._create_finding(
                        id=finding.get('rule_id', ''),
                        title=finding.get('rule_description', ''),
                        description=finding.get('rule_description', ''),
                        severity=finding.get('severity', 'MEDIUM'),
                        file=finding.get('location', {}).get('filename', ''),
                        line=finding.get('location', {}).get('start_line', 0),
                        type='iac',
                        metadata={
                            'provider': finding.get('provider', ''),
                            'service': finding.get('service', ''),
                            'resource': finding.get('resource', ''),
                            'links': finding.get('links', []),
                            'impact': finding.get('impact', ''),
                            'resolution': finding.get('resolution', '')
                        }
                    )
                    findings.append(finding_obj)
            
            logger.info(f"Tfsec found {len(findings)} Terraform issues")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tfsec output: {e}")
            return []