#!/usr/bin/env python3
"""
Grype Container Scanner Integration
"""

import json
import logging
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class GrypeScanner(BaseScanner):
    """Grype container scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "grype"
        self.timeout = 300
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Grype scan"""
        logger.info(f"Running Grype scan on {repo_path}")
        
        cmd = [
            "grype",
            f"dir:{repo_path}",
            "-o", "json"
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"Grype scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Grype JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for match in data.get('matches', []):
                vuln = match.get('vulnerability', {})
                artifact = match.get('artifact', {})
                
                finding = self._create_finding(
                    id=vuln.get('id', ''),
                    title=vuln.get('description', ''),
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'Unknown'),
                    type='vulnerability',
                    metadata={
                        'package': artifact.get('name', ''),
                        'version': artifact.get('version', ''),
                        'type': artifact.get('type', ''),
                        'locations': artifact.get('locations', []),
                        'fix': vuln.get('fix', {}),
                        'cvss': vuln.get('cvss', []),
                        'cwe_ids': vuln.get('cweIds', [])
                    }
                )
                
                # Add CVE
                if vuln.get('id', '').startswith('CVE-'):
                    finding['cve'] = vuln['id']
                
                findings.append(finding)
            
            logger.info(f"Grype found {len(findings)} vulnerabilities")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Grype output: {e}")
            return []