#!/usr/bin/env python3
"""
OWASP Dependency Check SCA Scanner Integration
"""

import json
import logging
import os
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class DependencyCheckScanner(BaseScanner):
    """OWASP Dependency Check SCA scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "dependency-check"
        self.timeout = 600  # 10 minutes
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Dependency Check scan"""
        logger.info(f"Running OWASP Dependency Check on {repo_path}")
        
        output_file = os.path.join(repo_path, 'dependency-check-report.json')
        
        cmd = [
            "dependency-check.sh",
            "--scan", repo_path,
            "--format", "JSON",
            "--out", output_file,
            "--prettyPrint",
            "--enableExperimental"
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
            logger.error(f"Dependency Check scan failed: {e}")
            return []
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Dependency Check JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for dependency in data.get('dependencies', []):
                for vuln in dependency.get('vulnerabilities', []):
                    # Map CVSS to severity
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
                        id=vuln.get('name', ''),
                        title=vuln.get('title', ''),
                        description=vuln.get('description', ''),
                        severity=severity,
                        type='sca',
                        metadata={
                            'package': dependency.get('fileName', ''),
                            'file_path': dependency.get('filePath', ''),
                            'cvss_score': cvss,
                            'cve': vuln.get('name', ''),
                            'cwe': vuln.get('cwe', []),
                            'references': vuln.get('references', [])
                        }
                    )
                    
                    # Add CVE
                    if vuln.get('name', '').startswith('CVE-'):
                        finding['cve'] = vuln['name']
                    
                    findings.append(finding)
            
            logger.info(f"Dependency Check found {len(findings)} vulnerabilities")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse Dependency Check output: {e}")
            return []