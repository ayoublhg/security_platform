#!/usr/bin/env python3
"""
TruffleHog Secrets Scanner Integration
"""

import json
import logging
from typing import List, Dict, Any
from .base import BaseScanner

logger = logging.getLogger(__name__)

class TruffleHogScanner(BaseScanner):
    """TruffleHog secrets scanner"""
    
    def __init__(self):
        super().__init__()
        self.name = "trufflehog"
        self.timeout = 300
        
    async def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run TruffleHog scan"""
        logger.info(f"Running TruffleHog scan on {repo_path}")
        
        cmd = [
            "trufflehog",
            "filesystem",
            "--json",
            repo_path
        ]
        
        try:
            output = await self._run_command(cmd)
            if output:
                return self.parse_output(output)
            return []
        except Exception as e:
            logger.error(f"TruffleHog scan failed: {e}")
            return []
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse TruffleHog JSON output (each line is JSON)"""
        findings = []
        
        try:
            for line in output.strip().split('\n'):
                if not line:
                    continue
                
                try:
                    finding = json.loads(line)
                    
                    finding_obj = self._create_finding(
                        id=finding.get('SourceMetadata', {}).get(
                            'Data', {}
                        ).get('Filesystem', {}).get('file', 'unknown'),
                        title="Secret found via entropy detection",
                        description=finding.get('DetectorName', 'Unknown'),
                        severity='high',
                        file=finding.get('SourceMetadata', {}).get(
                            'Data', {}
                        ).get('Filesystem', {}).get('file', ''),
                        line=finding.get('SourceMetadata', {}).get(
                            'Data', {}
                        ).get('Filesystem', {}).get('line', 0),
                        type='secret',
                        metadata={
                            'detector': finding.get('DetectorName', ''),
                            'decoder': finding.get('DecoderName', ''),
                            'verified': finding.get('Verified', False),
                            'raw': finding.get('Raw', '')[:200],
                            'entropy': finding.get('Redacted', False)
                        }
                    )
                    findings.append(finding_obj)
                    
                except json.JSONDecodeError:
                    continue
            
            logger.info(f"TruffleHog found {len(findings)} secrets")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse TruffleHog output: {e}")
            return []