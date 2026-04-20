#!/usr/bin/env python3
"""
Snyk SCA Scanner Integration
"""

import json
import logging
import os
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class SnykScanner(BaseScanner):
    """Snyk SCA scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "snyk"
        self.timeout = 300
        self.token = os.getenv('SNYK_TOKEN', '')
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Snyk scan"""
        logger.info(f"Running Snyk scan on {repo_path}")
        
        cmd = [
            "snyk", "test",
            "--json",
            "--severity-threshold=low",
            repo_path
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"Snyk scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Snyk JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for vuln in data.get('vulnerabilities', []):
                # Calculate CVSS score if available
                cvss = vuln.get('cvssScore', 0)
                if cvss >= 9.0:
                    severity = 'critical'
                elif cvss >= 7.0:
                    severity = 'high'
                elif cvss >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                finding = self._create_finding(
                    id=vuln.get('id', ''),
                    title=vuln.get('title', ''),
                    description=vuln.get('description', ''),
                    severity=severity,
                    type='sca',
                    metadata={
                        'package': vuln.get('packageName', ''),
                        'version': vuln.get('version', ''),
                        'fixed_in': vuln.get('fixedIn', []),
                        'cvss_score': cvss,
                        'cve': vuln.get('cve', ''),
                        'cwe': vuln.get('cwe', ''),
                        'exploit': vuln.get('exploit', 'Not Defined'),
                        'language': vuln.get('language', '')
                    }
                )
                
                # Add CVE as separate field
                if vuln.get('cve'):
                    finding['cve'] = vuln['cve']
                
                findings.append(finding)
            
            logger.info(f"Snyk found {len(findings)} vulnerabilities")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Snyk output: {e}")
            return []