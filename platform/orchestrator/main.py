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


# ============ PROMETHEUS METRICS ============
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

# Définir les métriques
scans_total = Counter(
    'scans_total', 
    'Total number of security scans', 
    ['status', 'tenant_id', 'scan_type']
)

findings_total = Counter(
    'findings_total', 
    'Total number of findings by severity', 
    ['severity', 'scanner', 'tenant_id']
)

scan_duration_seconds = Histogram(
    'scan_duration_seconds', 
    'Duration of security scans in seconds',
    ['scan_type', 'tenant_id'],
    buckets=(30, 60, 120, 300, 600, 900, 1800, 3600)
)

active_scans = Gauge(
    'active_scans', 
    'Number of currently active scans',
    ['tenant_id']
)

api_requests_total = Counter(
    'api_requests_total',
    'Total number of API requests',
    ['method', 'endpoint', 'status_code']
)

api_request_duration_seconds = Histogram(
    'api_request_duration_seconds',
    'Duration of API requests in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10)
)

tenant_scans_total = Counter(
    'tenant_scans_total',
    'Total scans per tenant',
    ['tenant_id']
)

# ============ FIN PROMETHEUS ============

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FIXED: Removed title and version parameters
app = FastAPI()

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
    webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None
    jira_project: Optional[str] = None
    compliance_frameworks: List[str] = []

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

# ============= Middleware pour les métriques API =============

@app.middleware("http")
async def metrics_middleware(request, call_next):
    """Middleware pour collecter les métriques des requêtes API"""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    api_requests_total.labels(
        method=request.method,
        endpoint=request.url.path,
        status_code=response.status_code
    ).inc()
    
    api_request_duration_seconds.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)
    
    return response

# ============= Orchestrator Engine =============

class SecurityOrchestrator:
    """Enterprise-grade orchestrator with resource management"""
    
    def __init__(self):
        self.tenants: Dict[str, TenantConfig] = {}
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_queue = asyncio.Queue()
        self.resource_semaphores: Dict[str, asyncio.Semaphore] = {}
        
        self.redis = None
        self.pool = None
        
    async def initialize(self):
        """Setup database connections"""
        self.redis = await redis.from_url(
            "redis://redis:6379",
            decode_responses=True
        )
        
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
        """Load tenant configurations"""
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch("SELECT * FROM tenants WHERE active = true")
                for row in rows:
                    config = TenantConfig(
                        tenant_id=row['tenant_id'],
                        name=row['name'],
                        max_concurrent_scans=row['max_concurrent'],
                        allowed_scanners=[ScanType(s) for s in row['allowed_scanners']],
                        webhook_url=row['webhook_url'],
                        slack_channel=row['slack_channel'],
                        jira_project=row['jira_project'],
                        compliance_frameworks=row['compliance_frameworks']
                    )
                    self.register_tenant(config)
        except Exception as e:
            logger.warning(f"No tenants loaded yet: {e}")
    
    def register_tenant(self, config: TenantConfig):
        """Register a new tenant with resource limits"""
        self.tenants[config.tenant_id] = config
        self.resource_semaphores[config.tenant_id] = asyncio.Semaphore(
            config.max_concurrent_scans
        )
        logger.info(f"Registered tenant: {config.name} ({config.tenant_id})")
    
    async def submit_scan(self, request: ScanRequest) -> str:
        """Submit a new scan request"""
        if request.tenant_id not in self.tenants:
            default_config = TenantConfig(
                tenant_id=request.tenant_id,
                name=f"Tenant-{request.tenant_id}",
                allowed_scanners=[ScanType.SAST, ScanType.SCA, ScanType.SECRETS]
            )
            self.register_tenant(default_config)
        
        tenant = self.tenants[request.tenant_id]
        
        for scan_type in request.scan_types:
            if scan_type not in tenant.allowed_scanners:
                raise ValueError(f"Scanner {scan_type} not allowed for tenant")
        
        scan_id = str(uuid.uuid4())
        
        scan = ScanResult(
            scan_id=scan_id,
            tenant_id=request.tenant_id,
            repo_url=request.repo_url,
            start_time=datetime.utcnow(),
            status="queued",
            metadata={
                "branch": request.branch,
                "depth": request.depth,
                "callback_url": request.callback_url
            }
        )
        
        self.active_scans[scan_id] = scan
        await self.scan_queue.put((scan_id, request))
        await self.redis.setex(f"scan:{scan_id}", 3600, scan.json())
        
        for scan_type in request.scan_types:
            scans_total.labels(
                status="queued",
                tenant_id=request.tenant_id,
                scan_type=scan_type.value
            ).inc()
        
        tenant_scans_total.labels(tenant_id=request.tenant_id).inc()
        
        logger.info(f"Scan {scan_id} queued for tenant {request.tenant_id}")
        return scan_id
    
    async def worker(self):
        """Background worker that processes scans"""
        while True:
            scan_id, request = await self.scan_queue.get()
            tenant_id = request.tenant_id
            
            async with self.resource_semaphores[tenant_id]:
                try:
                    await self.execute_scan(scan_id, request)
                except Exception as e:
                    logger.error(f"Scan {scan_id} failed: {str(e)}")
                    await self.handle_scan_failure(scan_id, str(e))
                finally:
                    self.scan_queue.task_done()
    
    async def save_findings(self, scan_id: str, tenant_id: str, findings: List[Dict]):
        """Save individual findings to database"""
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
                        str(uuid.uuid4()), 
                        scan_id, 
                        tenant_id,
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
    
    async def execute_scan(self, scan_id: str, request: ScanRequest):
        """Execute all requested scans in parallel"""
        logger.info(f"Starting scan {scan_id}")
        start_time = time.time()
        
        self.active_scans[scan_id].status = "running"
        await self.redis.set(f"scan:{scan_id}:status", "running")
        
        active_scans.labels(tenant_id=request.tenant_id).inc()
        
        findings = []
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        repo_path = None
        
        try:
            # Cloner le dépôt
            repo_path = tempfile.mkdtemp()
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", request.repo_url, repo_path],
                capture_output=True, text=True, timeout=120
            )
            if clone_result.returncode != 0:
                raise Exception(f"Failed to clone: {clone_result.stderr}")
            logger.info(f"📁 Repository cloned to {repo_path}")
            
            # Scanner avec Semgrep (SAST)
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
                            findings_total.labels(
                                severity=severity,
                                scanner='semgrep',
                                tenant_id=request.tenant_id
                            ).inc()
                    logger.info(f"   🔍 Semgrep: {len([f for f in findings if f.get('scanner') == 'semgrep'])} findings")
                except Exception as e:
                    logger.error(f"Semgrep error: {e}")
            
            # Scanner avec Gitleaks (Secrets)
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
                            findings_total.labels(
                                severity='critical',
                                scanner='gitleaks',
                                tenant_id=request.tenant_id
                            ).inc()
                    logger.info(f"   🔐 Gitleaks: {len([f for f in findings if f.get('scanner') == 'gitleaks'])} findings")
                except Exception as e:
                    logger.error(f"Gitleaks error: {e}")
            
            summary['total'] = len(findings)
            
            # SAVE FINDINGS TO DATABASE
            await self.save_findings(scan_id, request.tenant_id, findings)
            
            for scan_type in request.scan_types:
                scans_total.labels(
                    status="completed",
                    tenant_id=request.tenant_id,
                    scan_type=scan_type.value
                ).inc()
            
            total_duration = time.time() - start_time
            for scan_type in request.scan_types:
                scan_duration_seconds.labels(
                    scan_type=scan_type.value,
                    tenant_id=request.tenant_id
                ).observe(total_duration)
            
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
            
            for scan_type in request.scan_types:
                scans_total.labels(
                    status="failed",
                    tenant_id=request.tenant_id,
                    scan_type=scan_type.value
                ).inc()
        
        finally:
            active_scans.labels(tenant_id=request.tenant_id).dec()
            if repo_path:
                shutil.rmtree(repo_path, ignore_errors=True)
    
    async def store_results(self, scan: ScanResult):
        """Store scan results in database"""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scans (
                    scan_id, tenant_id, repo_url, start_time, end_time,
                    status, findings, summary, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (scan_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    end_time = EXCLUDED.end_time,
                    findings = EXCLUDED.findings,
                    summary = EXCLUDED.summary
                """,
                scan.scan_id, scan.tenant_id, scan.repo_url,
                scan.start_time, scan.end_time, scan.status,
                json.dumps(scan.findings), json.dumps(scan.summary),
                json.dumps(scan.metadata)
            )
    
    async def handle_scan_failure(self, scan_id: str, error: str):
        """Handle scan failures"""
        scan = self.active_scans.get(scan_id)
        if scan:
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            scan.metadata['error'] = error
            await self.store_results(scan)
            
            if scan.metadata.get('scan_types'):
                for scan_type in scan.metadata['scan_types']:
                    scans_total.labels(
                        status="failed",
                        tenant_id=scan.tenant_id,
                        scan_type=scan_type
                    ).inc()
            
            active_scans.labels(tenant_id=scan.tenant_id).dec()

# ============= FastAPI Routes =============

orchestrator = SecurityOrchestrator()

@app.on_event("startup")
async def startup():
    await orchestrator.initialize()
    asyncio.create_task(orchestrator.worker())

@app.get("/")
async def root():
    return {
        "service": "Security Orchestrator",
        "version": "2.0.0",
        "status": "running",
        "tenants": len(orchestrator.tenants)
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/metrics")
async def metrics():
    """Endpoint Prometheus pour récupérer les métriques"""
    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST
    )

@app.post("/api/v1/scans", response_model=Dict[str, str])
async def create_scan(request: ScanRequest):
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
    cached = await orchestrator.redis.get(f"scan:{scan_id}")
    if cached:
        return json.loads(cached)
    
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
        rows = await conn.fetch(
            """
            SELECT 
                DATE(start_time) as date,
                COALESCE(SUM((summary->>'critical')::int), 0) as critical,
                COALESCE(SUM((summary->>'high')::int), 0) as high,
                COUNT(*) as total_scans
            FROM scans
            WHERE tenant_id = $1
                AND start_time > NOW() - INTERVAL '30 days'
            GROUP BY DATE(start_time)
            ORDER BY date DESC
            """,
            tenant_id
        )
        
        trends = []
        for row in rows:
            trends.append({
                "date": row['date'].isoformat() if row['date'] else None,
                "critical": row['critical'] or 0,
                "high": row['high'] or 0,
                "scans": row['total_scans']
            })
        
        return {
            "tenant_id": tenant_id,
            "trends": trends,
            "total_findings_30d": sum(t['critical'] + t['high'] for t in trends)
        }

@app.post("/api/v1/tenants")
async def register_tenant(config: TenantConfig):
    """Register a new tenant"""
    try:
        orchestrator.register_tenant(config)
        
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