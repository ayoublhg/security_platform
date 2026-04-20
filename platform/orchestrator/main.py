#!/usr/bin/env python3
"""
Enterprise Security Orchestrator
Handles multi-tenant, parallel scanning with resource management
"""

import asyncio
import uuid
import tempfile
import subprocess
import shutil
import time
from datetime import datetime
from typing import Dict, List, Optional
import redis.asyncio as redis
import asyncpg
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, validator
import logging
import json
import os
from enum import Enum

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

# Metrics
scans_total = Counter('scans_total', '', ['status', 'tenant_id', 'scan_type'])
findings_total = Counter('findings_total', '', ['severity', 'scanner', 'tenant_id'])
scan_duration_seconds = Histogram('scan_duration_seconds', '', ['scan_type', 'tenant_id'], buckets=(30, 60, 120, 300, 600, 900, 1800, 3600))
active_scans = Gauge('active_scans', '', ['tenant_id'])
api_requests_total = Counter('api_requests_total', '', ['method', 'endpoint', 'status_code'])
api_request_duration_seconds = Histogram('api_request_duration_seconds', '', ['method', 'endpoint'], buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10))
tenant_scans_total = Counter('tenant_scans_total', '', ['tenant_id'])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

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
    webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None
    jira_project: Optional[str] = None
    compliance_frameworks: List[str] = []

    class Config:
        use_enum_values = True

class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    scan_types: List[ScanType]
    tenant_id: str
    depth: str = "standard"
    callback_url: Optional[str] = None

    @validator('repo_url')
    def validate_url(cls, v):
        if not v.startswith(('https://github.com/', 'https://gitlab.com/')):
            raise ValueError('Only GitHub/GitLab URLs supported')
        return v

    class Config:
        use_enum_values = True

class ScanResult(BaseModel):
    scan_id: str
    tenant_id: str
    repo_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str
    findings: Dict[str, List[Dict]] = {}
    summary: Dict[str, int] = {}
    metadata: Dict = {}

@app.middleware("http")
async def metrics_middleware(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    api_requests_total.labels(method=request.method, endpoint=request.url.path, status_code=response.status_code).inc()
    api_request_duration_seconds.labels(method=request.method, endpoint=request.url.path).observe(duration)
    return response

class SecurityOrchestrator:
    def __init__(self):
        self.tenants: Dict[str, TenantConfig] = {}
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_queue = asyncio.Queue()
        self.resource_semaphores: Dict[str, asyncio.Semaphore] = {}
        self.redis = None
        self.pool = None
        
    async def initialize(self):
        self.redis = await redis.from_url("redis://redis:6379", decode_responses=True)
        self.pool = await asyncpg.create_pool(
            user=os.getenv('POSTGRES_USER', 'postgres'),
            password=os.getenv('POSTGRES_PASSWORD', 'secure_password'),
            database=os.getenv('POSTGRES_DB', 'security_platform'),
            host="postgres",
            min_size=5,
            max_size=20
        )
        logger.info("✅ Orchestrator connected to PostgreSQL and Redis")
        await self.load_tenants()
        
    async def load_tenants(self):
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch("SELECT * FROM tenants WHERE active = true")
                for row in rows:
                    config = TenantConfig(
                        tenant_id=row['tenant_id'],
                        name=row['name'],
                        max_concurrent_scans=row['max_concurrent'],
                        allowed_scanners=[ScanType(s) for s in row['allowed_scanners']],
                        webhook_url=row.get('webhook_url'),
                        slack_channel=row.get('slack_channel'),
                        jira_project=row.get('jira_project'),
                        compliance_frameworks=row.get('compliance_frameworks', [])
                    )
                    self.register_tenant(config)
        except Exception as e:
            logger.warning(f"No tenants loaded yet: {e}")
    
    def register_tenant(self, config: TenantConfig):
        self.tenants[config.tenant_id] = config
        self.resource_semaphores[config.tenant_id] = asyncio.Semaphore(config.max_concurrent_scans)
        logger.info(f"Registered tenant: {config.name} ({config.tenant_id})")
    
    async def submit_scan(self, request: ScanRequest) -> str:
        if request.tenant_id not in self.tenants:
            default_config = TenantConfig(
                tenant_id=request.tenant_id,
                name=f"Tenant-{request.tenant_id}",
                allowed_scanners=[ScanType.SAST, ScanType.SCA, ScanType.SECRETS, ScanType.CONTAINER, ScanType.IAC]
            )
            self.register_tenant(default_config)
        
        scan_id = str(uuid.uuid4())
        scan = ScanResult(
            scan_id=scan_id,
            tenant_id=request.tenant_id,
            repo_url=request.repo_url,
            start_time=datetime.utcnow(),
            status="queued",
            metadata={"branch": request.branch, "depth": request.depth, "callback_url": request.callback_url}
        )
        
        self.active_scans[scan_id] = scan
        await self.scan_queue.put((scan_id, request))
        await self.redis.setex(f"scan:{scan_id}", 3600, scan.json())
        
        for scan_type in request.scan_types:
            scans_total.labels(status="queued", tenant_id=request.tenant_id, scan_type=scan_type.value).inc()
        
        tenant_scans_total.labels(tenant_id=request.tenant_id).inc()
        logger.info(f"Scan {scan_id} queued for tenant {request.tenant_id}")
        return scan_id
    
    async def worker(self):
        while True:
            scan_id, request = await self.scan_queue.get()
            async with self.resource_semaphores[request.tenant_id]:
                try:
                    await self.execute_scan(scan_id, request)
                except Exception as e:
                    logger.error(f"Scan {scan_id} failed: {str(e)}")
                finally:
                    self.scan_queue.task_done()
    
    async def save_findings(self, scan_id: str, tenant_id: str, findings: List[Dict]):
        if not findings:
            logger.info("No findings to save")
            return
        
        async with self.pool.acquire() as conn:
            saved_count = 0
            for finding in findings:
                try:
                    await conn.execute("""
                        INSERT INTO findings (
                            finding_id, scan_id, tenant_id, title, description,
                            severity, scanner_name, finding_type, file_path, line_start,
                            status, detected_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'open', NOW())
                        ON CONFLICT (finding_id) DO NOTHING
                    """,
                        str(uuid.uuid4()), scan_id, tenant_id,
                        finding.get('title', '')[:500],
                        finding.get('description', '')[:1000],
                        finding.get('severity', 'medium'),
                        finding.get('scanner', 'unknown'),
                        finding.get('type', 'vulnerability'),
                        finding.get('file', '')[:500],
                        finding.get('line', 0)
                    )
                    saved_count += 1
                except Exception as e:
                    logger.error(f"Failed to save finding: {e}")
            logger.info(f"💾 Saved {saved_count} findings to database")
    
    async def scan_with_trivy(self, repo_path: str, findings: List, summary: Dict, tenant_id: str):
        """Scan with Trivy for container and filesystem vulnerabilities"""
        logger.info("   🐳 Running Trivy filesystem scan...")
        try:
            result = subprocess.run(
                ["trivy", "fs", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM,LOW", repo_path],
                capture_output=True, text=True, timeout=300, encoding='utf-8', errors='ignore'
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for target in data.get('Results', []):
                    for vuln in target.get('Vulnerabilities', []):
                        severity = vuln.get('Severity', 'medium').lower()
                        findings.append({
                            'title': f"Trivy: {vuln.get('VulnerabilityID', 'Unknown')} - {vuln.get('Title', '')[:100]}",
                            'description': vuln.get('Description', '')[:500],
                            'severity': severity,
                            'scanner': 'trivy',
                            'type': 'container',
                            'file': target.get('Target', ''),
                            'line': 0
                        })
                        summary[severity] = summary.get(severity, 0) + 1
                        findings_total.labels(severity=severity, scanner='trivy', tenant_id=tenant_id).inc()
            logger.info(f"   🐳 Trivy: {len([f for f in findings if f.get('scanner') == 'trivy'])} findings")
        except Exception as e:
            logger.error(f"Trivy error: {e}")
    
    async def scan_with_checkov(self, repo_path: str, findings: List, summary: Dict, tenant_id: str):
        """Scan with Checkov for IaC misconfigurations"""
        logger.info("   🏗️ Running Checkov IaC scan...")
        try:
            result = subprocess.run(
                ["checkov", "-d", repo_path, "--output", "json", "--quiet"],
                capture_output=True, text=True, timeout=300, encoding='utf-8', errors='ignore'
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for check in data.get('results', {}).get('failed_checks', []):
                    severity = check.get('severity', 'medium').lower()
                    findings.append({
                        'title': f"Checkov: {check.get('check_name', 'Unknown')}",
                        'description': check.get('check_description', '')[:500],
                        'severity': severity,
                        'scanner': 'checkov',
                        'type': 'iac',
                        'file': check.get('file_path', ''),
                        'line': check.get('file_line_range', [0, 0])[0] if check.get('file_line_range') else 0
                    })
                    summary[severity] = summary.get(severity, 0) + 1
                    findings_total.labels(severity=severity, scanner='checkov', tenant_id=tenant_id).inc()
            logger.info(f"   🏗️ Checkov: {len([f for f in findings if f.get('scanner') == 'checkov'])} findings")
        except Exception as e:
            logger.error(f"Checkov error: {e}")
    
    async def scan_with_dependency_check(self, repo_path: str, findings: List, summary: Dict, tenant_id: str):
        """Scan with OWASP Dependency Check for vulnerable dependencies"""
        logger.info("   📦 Running OWASP Dependency Check...")
        try:
            result = subprocess.run(
                ["dependency-check", "--scan", repo_path, "--format", "JSON", "--pretty"],
                capture_output=True, text=True, timeout=600, encoding='utf-8', errors='ignore'
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for dep in data.get('dependencies', []):
                    for vuln in dep.get('vulnerabilities', []):
                        severity = vuln.get('severity', 'medium').lower()
                        findings.append({
                            'title': f"OWASP DC: {vuln.get('name', 'Unknown')}",
                            'description': vuln.get('description', '')[:500],
                            'severity': severity,
                            'scanner': 'dependency-check',
                            'type': 'sca',
                            'file': dep.get('filePath', '').split('/')[-1],
                            'line': 0
                        })
                        summary[severity] = summary.get(severity, 0) + 1
                        findings_total.labels(severity=severity, scanner='dependency-check', tenant_id=tenant_id).inc()
            logger.info(f"   📦 OWASP DC: {len([f for f in findings if f.get('scanner') == 'dependency-check'])} findings")
        except Exception as e:
            logger.error(f"Dependency check error: {e}")
    
    async def execute_scan(self, scan_id: str, request: ScanRequest):
        logger.info(f"Starting scan {scan_id}")
        start_time = time.time()
        
        self.active_scans[scan_id].status = "running"
        await self.redis.set(f"scan:{scan_id}:status", "running")
        
        active_scans.labels(tenant_id=request.tenant_id).inc()
        
        findings = []
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        repo_path = None
        
        try:
            repo_path = tempfile.mkdtemp()
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", request.repo_url, repo_path],
                capture_output=True, text=True, timeout=120
            )
            if clone_result.returncode != 0:
                raise Exception(f"Failed to clone: {clone_result.stderr}")
            logger.info(f"📁 Repository cloned to {repo_path}")
            
            # SAST with Semgrep
            if ScanType.SAST in request.scan_types:
                try:
                    result = subprocess.run(
                        ["semgrep", "--config", "auto", "--json", repo_path],
                        capture_output=True, text=True, timeout=300, encoding='utf-8', errors='ignore'
                    )
                    if result.stdout:
                        data = json.loads(result.stdout)
                        for r in data.get('results', []):
                            severity_raw = r.get('extra', {}).get('severity', 'medium').lower()
                            severity_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
                            severity = severity_map.get(severity_raw, severity_raw)
                            if severity not in ['critical', 'high', 'medium', 'low', 'info']:
                                severity = 'medium'
                            
                            findings.append({
                                'title': r.get('check_id', 'Unknown')[:200],
                                'description': r.get('extra', {}).get('message', '')[:500],
                                'severity': severity,
                                'scanner': 'semgrep',
                                'type': 'sast',
                                'file': r.get('path', '')[:200],
                                'line': r.get('start', {}).get('line', 0)
                            })
                            summary[severity] = summary.get(severity, 0) + 1
                            findings_total.labels(severity=severity, scanner='semgrep', tenant_id=request.tenant_id).inc()
                    logger.info(f"   🔍 Semgrep: {len([f for f in findings if f.get('scanner') == 'semgrep'])} findings")
                except Exception as e:
                    logger.error(f"Semgrep error: {e}")
            
            # Secrets with Gitleaks
            if ScanType.SECRETS in request.scan_types:
                try:
                    result = subprocess.run(
                        ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-git"],
                        capture_output=True, text=True, timeout=300, encoding='utf-8', errors='ignore'
                    )
                    if result.stdout:
                        data = json.loads(result.stdout)
                        items = data if isinstance(data, list) else data.get('findings', [])
                        for f in items:
                            findings.append({
                                'title': f"Secret: {f.get('RuleID', 'unknown')}"[:200],
                                'description': f.get('Description', '')[:500],
                                'severity': 'critical',
                                'scanner': 'gitleaks',
                                'type': 'secret',
                                'file': f.get('File', '')[:200],
                                'line': f.get('StartLine', 0)
                            })
                            summary['critical'] += 1
                            findings_total.labels(severity='critical', scanner='gitleaks', tenant_id=request.tenant_id).inc()
                    logger.info(f"   🔐 Gitleaks: {len([f for f in findings if f.get('scanner') == 'gitleaks'])} findings")
                except Exception as e:
                    logger.error(f"Gitleaks error: {e}")
            
            # Container with Trivy
            if ScanType.CONTAINER in request.scan_types:
                await self.scan_with_trivy(repo_path, findings, summary, request.tenant_id)
            
            # IaC with Checkov
            if ScanType.IAC in request.scan_types:
                await self.scan_with_checkov(repo_path, findings, summary, request.tenant_id)
            
            # SCA with OWASP Dependency Check
            if ScanType.SCA in request.scan_types:
                await self.scan_with_dependency_check(repo_path, findings, summary, request.tenant_id)
            
            summary['total'] = len(findings)
            
            await self.save_findings(scan_id, request.tenant_id, findings)
            
            for scan_type in request.scan_types:
                scans_total.labels(status="completed", tenant_id=request.tenant_id, scan_type=scan_type.value).inc()
            
            total_duration = time.time() - start_time
            for scan_type in request.scan_types:
                scan_duration_seconds.labels(scan_type=scan_type.value, tenant_id=request.tenant_id).observe(total_duration)
            
            scan = self.active_scans[scan_id]
            scan.status = "completed"
            scan.end_time = datetime.utcnow()
            scan.findings = {}
            scan.summary = summary
            
            await self.store_results(scan)
            logger.info(f"✅ Scan {scan_id} completed with {summary['total']} findings")
            
        except Exception as e:
            logger.error(f"❌ Scan error: {e}")
            scan = self.active_scans.get(scan_id)
            if scan:
                scan.status = "failed"
                scan.end_time = datetime.utcnow()
                scan.metadata['error'] = str(e)
                await self.store_results(scan)
        finally:
            active_scans.labels(tenant_id=request.tenant_id).dec()
            if repo_path:
                shutil.rmtree(repo_path, ignore_errors=True)
    
    async def store_results(self, scan: ScanResult):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO scans (scan_id, tenant_id, repo_url, start_time, end_time, status, findings, summary, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (scan_id) DO UPDATE SET
                    status = EXCLUDED.status, end_time = EXCLUDED.end_time,
                    findings = EXCLUDED.findings, summary = EXCLUDED.summary
            """, scan.scan_id, scan.tenant_id, scan.repo_url,
                scan.start_time, scan.end_time, scan.status,
                json.dumps(scan.findings), json.dumps(scan.summary), json.dumps(scan.metadata))

orchestrator = SecurityOrchestrator()

@app.on_event("startup")
async def startup():
    await orchestrator.initialize()
    asyncio.create_task(orchestrator.worker())

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/v1/scans", response_model=Dict[str, str])
async def create_scan(request: ScanRequest):
    try:
        scan_id = await orchestrator.submit_scan(request)
        return {"scan_id": scan_id, "status": "queued", "message": "Scan submitted successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str):
    cached = await orchestrator.redis.get(f"scan:{scan_id}")
    if cached:
        return json.loads(cached)
    async with orchestrator.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM scans WHERE scan_id = $1", scan_id)
        if row:
            return dict(row)
    raise HTTPException(status_code=404, detail="Scan not found")

@app.post("/api/v1/tenants")
async def register_tenant(config: TenantConfig):
    try:
        orchestrator.register_tenant(config)
        async with orchestrator.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO tenants (tenant_id, name, max_concurrent, allowed_scanners,
                    webhook_url, slack_channel, jira_project, compliance_frameworks, active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    name = EXCLUDED.name, max_concurrent = EXCLUDED.max_concurrent,
                    allowed_scanners = EXCLUDED.allowed_scanners, active = EXCLUDED.active
            """, config.tenant_id, config.name, config.max_concurrent_scans,
                [s.value for s in config.allowed_scanners],
                config.webhook_url, config.slack_channel, config.jira_project,
                config.compliance_frameworks, True)
        return {"status": "success", "message": f"Tenant {config.name} registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)