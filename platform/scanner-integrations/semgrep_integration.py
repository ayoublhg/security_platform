#!/usr/bin/env python3
"""
Semgrep SAST Scanner Integration
"""

import json
import logging
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "semgrep"
        self.timeout = 300
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Semgrep scan"""
        logger.info(f"Running Semgrep scan on {repo_path}")
        
        cmd = [
            "semgrep",
            "--config", "auto",
            "--json",
            "--quiet",
            repo_path
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Semgrep JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for result in data.get('results', []):
                finding = self._create_finding(
                    id=result.get('check_id', 'unknown'),
                    title=result.get('extra', {}).get('message', 'No message'),
                    description=result.get('extra', {}).get(
                        'metadata', {}
                    ).get('description', ''),
                    severity=result.get('extra', {}).get('severity', 'INFO'),
                    file=result.get('path', ''),
                    line=result.get('start', {}).get('line', 0),
                    type='sast',
                    metadata={
                        'cwe': result.get('extra', {}).get('metadata', {}).get('cwe', []),
                        'confidence': result.get('extra', {}).get(
                            'metadata', {}
                        ).get('confidence', 'MEDIUM'),
                        'references': result.get('extra', {}).get(
                            'metadata', {}
                        ).get('references', [])
                    }
                )
                findings.append(finding)
            
            logger.info(f"Semgrep found {len(findings)} findings")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []