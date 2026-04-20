#!/usr/bin/env python3
"""
Scanner Manager - Orchestrates all security scanners
Handles parallel execution, timeouts, and result aggregation
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess
import json
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class ScannerManager:
    """Manages all security scanners and their execution"""
    
    def __init__(self):
        self.scanners = {
            'sast': self._run_semgrep,
            'sca': self._run_snyk,
            'secrets': self._run_gitleaks,
            'container': self._run_trivy,
            'iac': self._run_checkov
        }
        self.timeouts = {
            'sast': 300,      # 5 minutes
            'sca': 180,       # 3 minutes
            'secrets': 120,   # 2 minutes
            'container': 240, # 4 minutes
            'iac': 180        # 3 minutes
        }
        
    async def run_scans(self, repo_path: str, scan_types: List[str]) -> Dict[str, List[Dict]]:
        """
        Run multiple scanners in parallel
        Args:
            repo_path: Path to cloned repository
            scan_types: List of scan types to run
        Returns:
            Dictionary of findings by scanner type
        """
        logger.info(f"Running scans on {repo_path}: {scan_types}")
        
        tasks = []
        for scan_type in scan_types:
            if scan_type in self.scanners:
                task = asyncio.create_task(
                    self._run_with_timeout(
                        scan_type, 
                        self.scanners[scan_type], 
                        repo_path
                    )
                )
                tasks.append((scan_type, task))
        
        results = {}
        for scan_type, task in tasks:
            try:
                findings = await task
                results[scan_type] = findings
                logger.info(f"{scan_type} completed: {len(findings)} findings")
            except Exception as e:
                logger.error(f"{scan_type} failed: {e}")
                results[scan_type] = [{"error": str(e)}]
        
        return results
    
    async def _run_with_timeout(self, scan_type: str, scanner_func, repo_path: str):
        """Run scanner with timeout"""
        timeout = self.timeouts.get(scan_type, 300)
        try:
            return await asyncio.wait_for(
                scanner_func(repo_path),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            raise Exception(f"{scan_type} scanner timed out after {timeout}s")
    
    async def _run_semgrep(self, repo_path: str) -> List[Dict]:
        """Run Semgrep SAST scanner"""
        try:
            cmd = [
                "semgrep", "--config", "auto",
                "--json", "-o", "/tmp/semgrep-output.json",
                repo_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode not in [0, 1]:  # 1 means findings found
                logger.error(f"Semgrep failed: {stderr.decode()}")
                return []
            
            # Read output file
            if os.path.exists("/tmp/semgrep-output.json"):
                with open("/tmp/semgrep-output.json", "r") as f:
                    data = json.load(f)
                
                findings = []
                for result in data.get('results', []):
                    finding = {
                        'id': result.get('check_id', 'unknown'),
                        'title': result.get('extra', {}).get('message', 'No message'),
                        'severity': self._map_severity(
                            result.get('extra', {}).get('severity', 'INFO')
                        ),
                        'file': result.get('path', 'unknown'),
                        'line': result.get('start', {}).get('line', 0),
                        'description': result.get('extra', {}).get(
                            'metadata', {}
                        ).get('description', ''),
                        'cwe': result.get('extra', {}).get('metadata', {}).get('cwe', []),
                        'scanner': 'semgrep',
                        'type': 'sast'
                    }
                    findings.append(finding)
                
                os.unlink("/tmp/semgrep-output.json")
                return findings
            
            return []
            
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return []
    
    async def _run_snyk(self, repo_path: str) -> List[Dict]:
        """Run Snyk SCA scanner"""
        try:
            cmd = [
                "snyk", "test", "--json",
                "--severity-threshold=low",
                repo_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode not in [0, 1]:
                logger.error(f"Snyk failed: {stderr.decode()}")
                return []
            
            if stdout:
                data = json.loads(stdout)
                findings = []
                
                for vuln in data.get('vulnerabilities', []):
                    finding = {
                        'id': vuln.get('id', 'unknown'),
                        'title': vuln.get('title', 'No title'),
                        'severity': vuln.get('severity', 'medium').lower(),
                        'package': vuln.get('packageName', 'unknown'),
                        'version': vuln.get('version', 'unknown'),
                        'fixed_in': vuln.get('fixedIn', []),
                        'cvss_score': vuln.get('cvssScore', 0),
                        'cve': vuln.get('cve', ''),
                        'cwe': vuln.get('cwe', ''),
                        'description': vuln.get('description', ''),
                        'scanner': 'snyk',
                        'type': 'sca'
                    }
                    findings.append(finding)
                
                return findings
            
            return []
            
        except Exception as e:
            logger.error(f"Error running Snyk: {e}")
            return []
    
    async def _run_gitleaks(self, repo_path: str) -> List[Dict]:
        """Run Gitleaks secrets scanner"""
        try:
            cmd = [
                "gitleaks", "detect",
                "--source", repo_path,
                "--report-format", "json",
                "--report-path", "/tmp/gitleaks-report.json",
                "--no-git"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await proc.communicate()
            
            # Read report file
            if os.path.exists("/tmp/gitleaks-report.json"):
                with open("/tmp/gitleaks-report.json", "r") as f:
                    data = json.load(f)
                
                findings = []
                if isinstance(data, list):
                    for finding in data:
                        f = {
                            'id': finding.get('Finding', 'unknown'),
                            'title': f"Secret: {finding.get('RuleID', 'unknown')}",
                            'severity': finding.get('Severity', 'high').lower(),
                            'file': finding.get('File', 'unknown'),
                            'line': finding.get('StartLine', 0),
                            'secret_type': finding.get('Description', 'unknown'),
                            'entropy': finding.get('Entropy', 0),
                            'commit': finding.get('Commit', ''),
                            'scanner': 'gitleaks',
                            'type': 'secret'
                        }
                        findings.append(f)
                
                os.unlink("/tmp/gitleaks-report.json")
                return findings
            
            return []
            
        except Exception as e:
            logger.error(f"Error running Gitleaks: {e}")
            return []
    
    async def _run_trivy(self, repo_path: str) -> List[Dict]:
        """Run Trivy container/filesystem scanner"""
        try:
            cmd = [
                "trivy", "fs",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--output", "/tmp/trivy-report.json",
                repo_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await proc.communicate()
            
            if os.path.exists("/tmp/trivy-report.json"):
                with open("/tmp/trivy-report.json", "r") as f:
                    data = json.load(f)
                
                findings = []
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        finding = {
                            'id': vuln.get('VulnerabilityID', 'unknown'),
                            'title': vuln.get('Title', 'No title'),
                            'severity': vuln.get('Severity', 'unknown').lower(),
                            'package': vuln.get('PkgName', 'unknown'),
                            'installed_version': vuln.get('InstalledVersion', 'unknown'),
                            'fixed_version': vuln.get('FixedVersion', ''),
                            'description': vuln.get('Description', ''),
                            'cvss': vuln.get('CVSS', {}),
                            'scanner': 'trivy',
                            'type': 'vulnerability'
                        }
                        findings.append(finding)
                
                os.unlink("/tmp/trivy-report.json")
                return findings
            
            return []
            
        except Exception as e:
            logger.error(f"Error running Trivy: {e}")
            return []
    
    async def _run_checkov(self, repo_path: str) -> List[Dict]:
        """Run Checkov IaC scanner"""
        try:
            cmd = [
                "checkov", "-d", repo_path,
                "--output", "json",
                "--output-file-path", "/tmp",
                "--quiet"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await proc.communicate()
            
            # Checkov creates results.json in current directory
            if os.path.exists("/tmp/results.json"):
                with open("/tmp/results.json", "r") as f:
                    data = json.load(f)
                
                findings = []
                for check in data.get('results', {}).get('failed_checks', []):
                    finding = {
                        'id': check.get('check_id', 'unknown'),
                        'title': check.get('check_name', 'No title'),
                        'severity': check.get('severity', 'medium').lower(),
                        'file': check.get('file_path', 'unknown'),
                        'line': check.get('file_line_range', [0])[0],
                        'resource': check.get('resource', 'unknown'),
                        'guideline': check.get('guideline', ''),
                        'description': check.get('check_name', ''),
                        'scanner': 'checkov',
                        'type': 'iac'
                    }
                    findings.append(finding)
                
                os.unlink("/tmp/results.json")
                return findings
            
            return []
            
        except Exception as e:
            logger.error(f"Error running Checkov: {e}")
            return []
    
    def _map_severity(self, severity: str) -> str:
        """Map various severity formats to standard levels"""
        mapping = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low',
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return mapping.get(severity.upper(), 'info')