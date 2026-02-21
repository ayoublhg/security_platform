#!/usr/bin/env python3
"""
Enterprise Security Orchestrator
Handles multi-tenant, parallel scanning with resource management
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import aioredis
import asyncpg
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, validator
import logging
import json
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Security Orchestrator", version="2.0.0")

# ============= Data Models =============

class ScanType(str, Enum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    CONTAINER = "container"
    IAC = "iac"
    DAST = "dast"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class TenantConfig(BaseModel):
    tenant_id: str
    name: str
    max_concurrent_scans: int = 5
    scan_timeout_minutes: int = 30
    allowed_scanners: List[ScanType]
    webhook_url: Optional[str]
    slack_channel: Optional[str]
    jira_project: Optional[str]
    compliance_frameworks: List[str] = []

class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    scan_types: List[ScanType]
    tenant_id: str
    depth: str = "standard"  # quick, standard, deep
    callback_url: Optional[str]

    @validator('repo_url')
    def validate_url(cls, v):
        if not v.startswith(('https://github.com/', 'https://gitlab.com/')):
            raise ValueError('Only GitHub/GitLab URLs supported')
        return v

class ScanResult(BaseModel):
    scan_id: str
    tenant_id: str
    repo_url: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str  # running, completed, failed
    findings: Dict[ScanType, List[Dict]]
    summary: Dict[str, int]
    metadata: Dict

# ============= Orchestrator Engine =============

class SecurityOrchestrator:
    """Enterprise-grade orchestrator with resource management"""
    
    def __init__(self):
        self.tenants: Dict[str, TenantConfig] = {}
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_queue = asyncio.Queue()
        self.resource_semaphores: Dict[str, asyncio.Semaphore] = {}
        
        # Initialize connections
        self.redis = None
        self.pool = None
        
    async def initialize(self):
        """Setup database connections"""
        self.redis = await aioredis.from_url(
            "redis://localhost:6379",
            encoding="utf-8",
            decode_responses=True
        )
        
        self.pool = await asyncpg.create_pool(
            user="postgres",
            password="secure_password",
            database="security_platform",
            host="localhost",
            min_size=10,
            max_size=20
        )
        
        # Load tenants from database
        await self.load_tenants()
        
    async def load_tenants(self):
        """Load tenant configurations"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM tenants WHERE active = true")
            for row in rows:
                config = TenantConfig(
                    tenant_id=row['tenant_id'],
                    name=row['name'],
                    max_concurrent_scans=row['max_concurrent'],
                    allowed_scanners=row['allowed_scanners'],
                    webhook_url=row['webhook_url'],
                    slack_channel=row['slack_channel'],
                    jira_project=row['jira_project'],
                    compliance_frameworks=row['compliance_frameworks']
                )
                self.register_tenant(config)
    
    def register_tenant(self, config: TenantConfig):
        """Register a new tenant with resource limits"""
        self.tenants[config.tenant_id] = config
        self.resource_semaphores[config.tenant_id] = asyncio.Semaphore(
            config.max_concurrent_scans
        )
        logger.info(f"Registered tenant: {config.name} ({config.tenant_id})")
    
    async def submit_scan(self, request: ScanRequest) -> str:
        """Submit a new scan request"""
        # Validate tenant
        if request.tenant_id not in self.tenants:
            raise ValueError(f"Unknown tenant: {request.tenant_id}")
        
        tenant = self.tenants[request.tenant_id]
        
        # Validate scanner permissions
        for scan_type in request.scan_types:
            if scan_type not in tenant.allowed_scanners:
                raise ValueError(f"Scanner {scan_type} not allowed for tenant")
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan = ScanResult(
            scan_id=scan_id,
            tenant_id=request.tenant_id,
            repo_url=request.repo_url,
            start_time=datetime.utcnow(),
            status="queued",
            findings={},
            summary={},
            metadata={
                "branch": request.branch,
                "depth": request.depth,
                "callback_url": request.callback_url
            }
        )
        
        self.active_scans[scan_id] = scan
        await self.scan_queue.put((scan_id, request))
        
        # Store in Redis for real-time updates
        await self.redis.setex(
            f"scan:{scan_id}",
            3600,  # 1 hour TTL
            scan.json()
        )
        
        logger.info(f"Scan {scan_id} queued for tenant {request.tenant_id}")
        return scan_id
    
    async def worker(self):
        """Background worker that processes scans"""
        while True:
            scan_id, request = await self.scan_queue.get()
            tenant_id = request.tenant_id
            
            # Acquire semaphore for tenant
            async with self.resource_semaphores[tenant_id]:
                try:
                    await self.execute_scan(scan_id, request)
                except Exception as e:
                    logger.error(f"Scan {scan_id} failed: {str(e)}")
                    await self.handle_scan_failure(scan_id, str(e))
                finally:
                    self.scan_queue.task_done()
    
    async def execute_scan(self, scan_id: str, request: ScanRequest):
        """Execute all requested scans in parallel"""
        logger.info(f"Starting scan {scan_id}")
        
        # Update status
        self.active_scans[scan_id].status = "running"
        await self.redis.set(f"scan:{scan_id}:status", "running")
        
        # Clone repository
        repo_path = await self.clone_repository(request.repo_url, request.branch)
        
        # Execute scans in parallel
        tasks = []
        for scan_type in request.scan_types:
            task = asyncio.create_task(
                self.run_scanner(scan_type, repo_path, scan_id, request.depth)
            )
            tasks.append(task)
        
        # Wait for all scans to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        findings = {}
        for scan_type, result in zip(request.scan_types, results):
            if isinstance(result, Exception):
                findings[scan_type] = [{"error": str(result)}]
            else:
                findings[scan_type] = result
        
        # Calculate summary
        summary = self.calculate_summary(findings)
        
        # Update scan record
        scan = self.active_scans[scan_id]
        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.findings = findings
        scan.summary = summary
        
        # Store results
        await self.store_results(scan)
        
        # Trigger callbacks
        await self.trigger_webhooks(scan)
        
        logger.info(f"Scan {scan_id} completed. Findings: {summary}")
    
    async def run_scanner(self, scan_type: ScanType, repo_path: str, 
                          scan_id: str, depth: str) -> List[Dict]:
        """Run specific scanner with timeout"""
        
        # Scanner configurations
        scanners = {
            ScanType.SAST: {
                "cmd": ["semgrep", "--config", "auto", "--json", repo_path],
                "timeout": 300,  # 5 minutes
                "parser": self.parse_semgrep_results
            },
            ScanType.SCA: {
                "cmd": ["snyk", "test", "--json", repo_path],
                "timeout": 180,
                "parser": self.parse_snyk_results
            },
            ScanType.SECRETS: {
                "cmd": ["gitleaks", "detect", "--source", repo_path, "--report-format", "json"],
                "timeout": 120,
                "parser": self.parse_gitleaks_results
            },
            ScanType.CONTAINER: {
                "cmd": ["trivy", "fs", "--format", "json", repo_path],
                "timeout": 240,
                "parser": self.parse_trivy_results
            },
            ScanType.IAC: {
                "cmd": ["checkov", "-f", repo_path, "--output", "json"],
                "timeout": 180,
                "parser": self.parse_checkov_results
            }
        }
        
        config = scanners.get(scan_type)
        if not config:
            return []
        
        try:
            # Run scanner with timeout
            proc = await asyncio.create_subprocess_exec(
                *config["cmd"],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=config["timeout"]
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise TimeoutError(f"Scanner {scan_type} timed out")
            
            if proc.returncode != 0 and proc.returncode != 1:  # Some scanners return 1 for findings
                logger.error(f"Scanner {scan_type} failed: {stderr.decode()}")
                return []
            
            # Parse results
            results = config["parser"](stdout.decode())
            
            # Add metadata
            for result in results:
                result["scanner"] = scan_type.value
                result["scan_id"] = scan_id
                result["timestamp"] = datetime.utcnow().isoformat()
            
            return results
            
        except Exception as e:
            logger.error(f"Error running {scan_type}: {str(e)}")
            return []
    
    # ============= Result Parsers =============
    
    def parse_semgrep_results(self, output: str) -> List[Dict]:
        """Parse Semgrep JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for result in data.get('results', []):
                finding = {
                    "id": result.get('check_id'),
                    "title": result.get('extra', {}).get('message'),
                    "severity": self.map_severity(result.get('extra', {}).get('severity')),
                    "file": result.get('path'),
                    "line": result.get('start', {}).get('line'),
                    "description": result.get('extra', {}).get('metadata', {}).get('description'),
                    "cwe": result.get('extra', {}).get('metadata', {}).get('cwe'),
                    "confidence": result.get('extra', {}).get('metadata', {}).get('confidence', 'MEDIUM')
                }
                findings.append(finding)
            
            return findings
        except:
            return []
    
    def parse_snyk_results(self, output: str) -> List[Dict]:
        """Parse Snyk JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for vuln in data.get('vulnerabilities', []):
                finding = {
                    "id": vuln.get('id'),
                    "title": vuln.get('title'),
                    "severity": vuln.get('severity', 'medium').lower(),
                    "package": vuln.get('packageName'),
                    "version": vuln.get('version'),
                    "fixed_in": vuln.get('fixedIn', []),
                    "cvss_score": vuln.get('cvssScore'),
                    "cve": vuln.get('cve'),
                    "cwe": vuln.get('cwe'),
                    "description": vuln.get('description')
                }
                findings.append(finding)
            
            return findings
        except:
            return []
    
    def parse_gitleaks_results(self, output: str) -> List[Dict]:
        """Parse Gitleaks JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for finding in data:
                processed = {
                    "id": finding.get('Finding', 'unknown'),
                    "title": f"Secret found: {finding.get('Description', 'Unknown')}",
                    "severity": finding.get('Severity', 'high').lower(),
                    "file": finding.get('File'),
                    "line": finding.get('StartLine'),
                    "secret_type": finding.get('RuleID'),
                    "entropy": finding.get('Entropy'),
                    "commit": finding.get('Commit')
                }
                findings.append(processed)
            
            return findings
        except:
            return []
    
    def parse_trivy_results(self, output: str) -> List[Dict]:
        """Parse Trivy JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    finding = {
                        "id": vuln.get('VulnerabilityID'),
                        "title": vuln.get('Title'),
                        "severity": vuln.get('Severity', 'unknown').lower(),
                        "package": vuln.get('PkgName'),
                        "installed_version": vuln.get('InstalledVersion'),
                        "fixed_version": vuln.get('FixedVersion'),
                        "cvss": vuln.get('CVSS'),
                        "description": vuln.get('Description')
                    }
                    findings.append(finding)
            
            return findings
        except:
            return []
    
    def parse_checkov_results(self, output: str) -> List[Dict]:
        """Parse Checkov JSON output"""
        try:
            data = json.loads(output)
            findings = []
            
            for check in data.get('results', {}).get('failed_checks', []):
                finding = {
                    "id": check.get('check_id'),
                    "title": check.get('check_name'),
                    "severity": check.get('severity', 'medium').lower(),
                    "file": check.get('file_path'),
                    "line": check.get('file_line_range', [0])[0],
                    "resource": check.get('resource'),
                    "guideline": check.get('guideline'),
                    "description": check.get('check_name')
                }
                findings.append(finding)
            
            return findings
        except:
            return []
    
    def map_severity(self, severity: str) -> str:
        """Normalize severity levels"""
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
    
    def calculate_summary(self, findings: Dict[ScanType, List[Dict]]) -> Dict[str, int]:
        """Calculate summary statistics"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        }
        
        for scan_type, scan_findings in findings.items():
            for finding in scan_findings:
                severity = finding.get('severity', 'info').lower()
                if severity in summary:
                    summary[severity] += 1
                summary['total'] += 1
        
        return summary
    
    async def clone_repository(self, repo_url: str, branch: str) -> str:
        """Clone repository to temporary directory"""
        import tempfile
        import os
        
        repo_path = tempfile.mkdtemp()
        
        proc = await asyncio.create_subprocess_exec(
            'git', 'clone', '--branch', branch, '--depth', '1',
            repo_url, repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await proc.wait()
        
        if proc.returncode != 0:
            raise Exception(f"Failed to clone repository: {repo_url}")
        
        return repo_path
    
    async def store_results(self, scan: ScanResult):
        """Store scan results in database"""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scans (
                    scan_id, tenant_id, repo_url, start_time, end_time,
                    status, findings, summary, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """,
                scan.scan_id, scan.tenant_id, scan.repo_url,
                scan.start_time, scan.end_time, scan.status,
                json.dumps(scan.findings), json.dumps(scan.summary),
                json.dumps(scan.metadata)
            )
    
    async def trigger_webhooks(self, scan: ScanResult):
        """Trigger webhooks for completed scan"""
        tenant = self.tenants.get(scan.tenant_id)
        if not tenant:
            return
        
        # Send to webhook if configured
        if tenant.webhook_url:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                try:
                    await session.post(
                        tenant.webhook_url,
                        json=scan.dict(),
                        timeout=aiohttp.ClientTimeout(total=5)
                    )
                except:
                    logger.error(f"Failed to send webhook for scan {scan.scan_id}")
        
        # Send to Slack if configured
        if tenant.slack_channel:
            await self.send_slack_notification(scan, tenant)
    
    async def send_slack_notification(self, scan: ScanResult, tenant: TenantConfig):
        """Send Slack notification"""
        import aiohttp
        
        critical_count = scan.summary.get('critical', 0)
        high_count = scan.summary.get('high', 0)
        
        color = "good"
        if critical_count > 0:
            color = "danger"
        elif high_count > 0:
            color = "warning"
        
        message = {
            "channel": tenant.slack_channel,
            "attachments": [{
                "color": color,
                "title": f"Security Scan Complete: {scan.repo_url}",
                "fields": [
                    {
                        "title": "Critical",
                        "value": str(critical_count),
                        "short": True
                    },
                    {
                        "title": "High",
                        "value": str(high_count),
                        "short": True
                    },
                    {
                        "title": "Medium",
                        "value": str(scan.summary.get('medium', 0)),
                        "short": True
                    },
                    {
                        "title": "Low",
                        "value": str(scan.summary.get('low', 0)),
                        "short": True
                    }
                ],
                "footer": f"Scan ID: {scan.scan_id}",
                "ts": int(scan.end_time.timestamp())
            }]
        }
        
        async with aiohttp.ClientSession() as session:
            webhook_url = f"https://hooks.slack.com/services/{os.getenv('SLACK_TOKEN')}"
            await session.post(webhook_url, json=message)
    
    async def handle_scan_failure(self, scan_id: str, error: str):
        """Handle scan failures"""
        scan = self.active_scans.get(scan_id)
        if scan:
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            scan.metadata['error'] = error
            await self.store_results(scan)

# ============= FastAPI Routes =============

orchestrator = SecurityOrchestrator()

@app.on_event("startup")
async def startup():
    await orchestrator.initialize()
    asyncio.create_task(orchestrator.worker())

@app.post("/api/v1/scans", response_model=Dict[str, str])
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Submit a new scan"""
    try:
        scan_id = await orchestrator.submit_scan(request)
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Scan submitted successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan results"""
    # Check Redis first
    cached = await orchestrator.redis.get(f"scan:{scan_id}")
    if cached:
        return json.loads(cached)
    
    # Check database
    async with orchestrator.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM scans WHERE scan_id = $1",
            scan_id
        )
        if row:
            return dict(row)
    
    raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/v1/tenants/{tenant_id}/metrics")
async def get_tenant_metrics(tenant_id: str):
    """Get security metrics for tenant"""
    async with orchestrator.pool.acquire() as conn:
        # Get scan history
        rows = await conn.fetch(
            """
            SELECT 
                DATE(start_time) as date,
                SUM((summary->>'critical')::int) as critical,
                SUM((summary->>'high')::int) as high,
                COUNT(*) as total_scans
            FROM scans
            WHERE tenant_id = $1
                AND start_time > NOW() - INTERVAL '30 days'
            GROUP BY DATE(start_time)
            ORDER BY date DESC
            """,
            tenant_id
        )
        
        # Get trend analysis
        trends = []
        for row in rows:
            trends.append({
                "date": row['date'],
                "critical": row['critical'] or 0,
                "high": row['high'] or 0,
                "scans": row['total_scans']
            })
        
        # Calculate MTTR (Mean Time to Remediate)
        mttr = await conn.fetchval(
            """
            SELECT AVG(EXTRACT(EPOCH FROM (remediated_at - found_at))/3600)
            FROM findings
            WHERE tenant_id = $1
                AND remediated_at IS NOT NULL
            """,
            tenant_id
        )
        
        return {
            "tenant_id": tenant_id,
            "trends": trends,
            "mttr_hours": round(mttr, 2) if mttr else None,
            "total_findings_30d": sum(t['critical'] + t['high'] for t in trends)
        }

@app.post("/api/v1/tenants")
async def register_tenant(config: TenantConfig):
    """Register a new tenant"""
    try:
        orchestrator.register_tenant(config)
        
        # Store in database
        async with orchestrator.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO tenants (
                    tenant_id, name, max_concurrent, allowed_scanners,
                    webhook_url, slack_channel, jira_project,
                    compliance_frameworks, active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    max_concurrent = EXCLUDED.max_concurrent,
                    allowed_scanners = EXCLUDED.allowed_scanners,
                    active = EXCLUDED.active
                """,
                config.tenant_id, config.name, config.max_concurrent_scans,
                [s.value for s in config.allowed_scanners],
                config.webhook_url, config.slack_channel, config.jira_project,
                config.compliance_frameworks, True
            )
        
        return {"status": "success", "message": f"Tenant {config.name} registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)