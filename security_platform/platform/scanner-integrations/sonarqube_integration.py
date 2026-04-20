#!/usr/bin/env python3
"""
SonarQube SAST Scanner Integration
"""

import json
import logging
import os
import tempfile
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class SonarQubeScanner(BaseScanner):
    """SonarQube SAST scanner"""
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        super().__init__()
        self.name = "sonarqube"
        self.timeout = 600  # 10 minutes
        self.host = host
        self.port = port
        self.token = os.getenv('SONAR_TOKEN', '')
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run SonarQube scan"""
        logger.info(f"Running SonarQube scan on {repo_path}")
        
        # Create sonar-project.properties
        props_path = os.path.join(repo_path, 'sonar-project.properties')
        with open(props_path, 'w') as f:
            f.write(f"""
sonar.projectKey=security-scan-{os.path.basename(repo_path)}
sonar.sources=.
sonar.host.url=http://{self.host}:{self.port}
sonar.login={self.token}
            """.strip())
        
        cmd = ["sonar-scanner"]
        
        try:
            output = await self._run_command(cmd)
            # SonarQube output needs to be parsed from API
            return await self._fetch_results()
        except Exception as e:
            logger.error(f"SonarQube scan failed: {e}")
            return []
    
    async def _fetch_results(self) -> List[Dict[str, Any]]:
        """Fetch results from SonarQube API"""
        import aiohttp
        
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get issues
                async with session.get(
                    f"http://{self.host}:{self.port}/api/issues/search",
                    params={
                        'componentKeys': f"security-scan-*",
                        'resolved': 'false',
                        'ps': 500
                    },
                    auth=aiohttp.BasicAuth(self.token, '')
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        for issue in data.get('issues', []):
                            finding = self._create_finding(
                                id=issue.get('key', ''),
                                title=issue.get('message', ''),
                                description=issue.get('message', ''),
                                severity=issue.get('severity', 'INFO'),
                                file=issue.get('component', '').split(':')[-1],
                                line=issue.get('line', 0),
                                type='sast',
                                metadata={
                                    'rule': issue.get('rule', ''),
                                    'type': issue.get('type', '')
                                }
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to fetch SonarQube results: {e}")
        
        return findings
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Not used for SonarQube"""
        return []