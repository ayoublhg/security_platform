#!/usr/bin/env python3
"""
Trivy Container/Filesystem Scanner Integration
"""

import json
import logging
import os
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class TrivyScanner(BaseScanner):
    """Trivy container/filesystem scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "trivy"
        self.timeout = 300
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Trivy filesystem scan"""
        logger.info(f"Running Trivy scan on {repo_path}")
        
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--ignore-unfixed",
            repo_path
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Trivy JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for result in data.get('Results', []):
                target = result.get('Target', 'unknown')
                
                for vuln in result.get('Vulnerabilities', []):
                    finding = self._create_finding(
                        id=vuln.get('VulnerabilityID', ''),
                        title=vuln.get('Title', ''),
                        description=vuln.get('Description', ''),
                        severity=vuln.get('Severity', 'UNKNOWN'),
                        type='vulnerability',
                        metadata={
                            'package': vuln.get('PkgName', ''),
                            'installed_version': vuln.get('InstalledVersion', ''),
                            'fixed_version': vuln.get('FixedVersion', ''),
                            'target': target,
                            'layer': vuln.get('Layer', {}),
                            'cvss': vuln.get('CVSS', {}),
                            'cwe_ids': vuln.get('CweIDs', [])
                        }
                    )
                    
                    # Add CVE
                    if vuln.get('VulnerabilityID', '').startswith('CVE-'):
                        finding['cve'] = vuln['VulnerabilityID']
                    
                    findings.append(finding)
            
            logger.info(f"Trivy found {len(findings)} vulnerabilities")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
            return []