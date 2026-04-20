#!/usr/bin/env python3
"""
Database query utilities
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import asyncpg

logger = logging.getLogger(__name__)

class DatabaseQueries:
    """Common database queries"""
    
    def __init__(self, pool):
        self.pool = pool
    
    # ============ Tenant Queries ============
    
    async def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        """Get tenant by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM tenants WHERE tenant_id = $1",
                tenant_id
            )
            return dict(row) if row else None
    
    async def list_tenants(self, active_only: bool = True) -> List[Dict]:
        """List all tenants"""
        query = "SELECT * FROM tenants"
        if active_only:
            query += " WHERE active = true"
        query += " ORDER BY name"
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query)
            return [dict(row) for row in rows]
    
    async def create_tenant(self, data: Dict) -> Dict:
        """Create new tenant"""
        tenant_id = data.get('tenant_id')
        name = data.get('name', f"Tenant-{tenant_id}")
        
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO tenants (
                    tenant_id, name, description, max_concurrent_scans,
                    allowed_scanners, webhook_url, slack_channel,
                    jira_project, github_repos, compliance_frameworks,
                    active, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
                RETURNING *
            """,
                tenant_id,
                name,
                data.get('description'),
                data.get('max_concurrent_scans', 5),
                json.dumps(data.get('allowed_scanners', [])),
                data.get('webhook_url'),
                data.get('slack_channel'),
                data.get('jira_project'),
                json.dumps(data.get('github_repos', [])),
                json.dumps(data.get('compliance_frameworks', [])),
                True
            )
            return dict(row)
    
    # ============ Scan Queries ============
    
    async def create_scan(self, data: Dict) -> Dict:
        """Create new scan"""
        scan_id = data.get('scan_id')
        
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO scans (
                    scan_id, tenant_id, repo_url, branch, scan_types,
                    depth, status, start_time, metadata, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
                RETURNING *
            """,
                scan_id,
                data['tenant_id'],
                data['repo_url'],
                data.get('branch', 'main'),
                json.dumps(data.get('scan_types', [])),
                data.get('depth', 'standard'),
                'queued',
                datetime.utcnow(),
                json.dumps(data.get('metadata', {}))
            )
            return dict(row)
    
    async def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scans WHERE scan_id = $1",
                scan_id
            )
            return dict(row) if row else None
    
    async def list_scans(self, tenant_id: Optional[str] = None, 
                          limit: int = 100, offset: int = 0) -> List[Dict]:
        """List scans with optional tenant filter"""
        query = "SELECT * FROM scans"
        params = []
        
        if tenant_id:
            query += " WHERE tenant_id = $1"
            params.append(tenant_id)
        
        query += " ORDER BY created_at DESC LIMIT $" + str(len(params) + 1)
        query += " OFFSET $" + str(len(params) + 2)
        params.extend([limit, offset])
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    async def update_scan_status(self, scan_id: str, status: str,
                                   findings: Optional[Dict] = None,
                                   summary: Optional[Dict] = None) -> bool:
        """Update scan status and results"""
        query = "UPDATE scans SET status = $1, updated_at = NOW()"
        params = [status, scan_id]
        
        if findings:
            query += ", findings = $" + str(len(params) + 1)
            params.insert(-1, json.dumps(findings))
        
        if summary:
            query += ", summary = $" + str(len(params) + 1)
            params.insert(-1, json.dumps(summary))
        
        if status in ['completed', 'failed']:
            query += ", end_time = NOW()"
        
        query += " WHERE scan_id = $" + str(len(params))
        
        async with self.pool.acquire() as conn:
            result = await conn.execute(query, *params)
            return result == "UPDATE 1"
    
    # ============ Finding Queries ============
    
    async def create_finding(self, data: Dict) -> Dict:
        """Create new finding"""
        finding_id = data.get('finding_id')
        
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO findings (
                    finding_id, scan_id, tenant_id, title, description,
                    severity, scanner, finding_type, file_path, line_number,
                    code_snippet, cvss_score, epss_score, exploit_available,
                    cisa_kev, ransomware_related, cve, cwe, metadata,
                    status, found_at, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                         $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW())
                RETURNING *
            """,
                finding_id,
                data['scan_id'],
                data['tenant_id'],
                data['title'],
                data.get('description', ''),
                data.get('severity', 'medium'),
                data.get('scanner', ''),
                data.get('finding_type', ''),
                data.get('file_path', ''),
                data.get('line_number', 0),
                data.get('code_snippet', ''),
                data.get('cvss_score', 0.0),
                data.get('epss_score', 0.0),
                data.get('exploit_available', False),
                data.get('cisa_kev', False),
                data.get('ransomware_related', False),
                data.get('cve', ''),
                data.get('cwe', ''),
                json.dumps(data.get('metadata', {})),
                'open',
                data.get('found_at', datetime.utcnow())
            )
            return dict(row)
    
    async def get_finding(self, finding_id: str) -> Optional[Dict]:
        """Get finding by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM findings WHERE finding_id = $1",
                finding_id
            )
            return dict(row) if row else None
    
    async def list_findings(self, tenant_id: Optional[str] = None,
                             scan_id: Optional[str] = None,
                             severity: Optional[str] = None,
                             status: Optional[str] = None,
                             finding_type: Optional[str] = None,
                             limit: int = 100,
                             offset: int = 0) -> List[Dict]:
        """List findings with filters"""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        param_index = 1
        
        if tenant_id:
            query += f" AND tenant_id = ${param_index}"
            params.append(tenant_id)
            param_index += 1
        
        if scan_id:
            query += f" AND scan_id = ${param_index}"
            params.append(scan_id)
            param_index += 1
        
        if severity:
            query += f" AND severity = ${param_index}"
            params.append(severity)
            param_index += 1
        
        if status:
            query += f" AND status = ${param_index}"
            params.append(status)
            param_index += 1
        
        if finding_type:
            query += f" AND finding_type = ${param_index}"
            params.append(finding_type)
            param_index += 1
        
        query += f" ORDER BY severity DESC, created_at DESC LIMIT ${param_index} OFFSET ${param_index + 1}"
        params.extend([limit, offset])
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    async def update_finding_status(self, finding_id: str, status: str,
                                      remediation_data: Optional[Dict] = None) -> bool:
        """Update finding status"""
        query = "UPDATE findings SET status = $1, updated_at = NOW()"
        params = [status, finding_id]
        
        if status == 'fixed':
            query += ", remediated_at = NOW()"
        
        if remediation_data:
            query += ", metadata = metadata || $" + str(len(params) + 1)
            params.insert(-1, json.dumps(remediation_data))
        
        query += " WHERE finding_id = $" + str(len(params))
        
        async with self.pool.acquire() as conn:
            result = await conn.execute(query, *params)
            return result == "UPDATE 1"
    
    async def get_finding_stats(self, tenant_id: Optional[str] = None) -> Dict:
        """Get finding statistics"""
        query = """
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low,
                COUNT(*) FILTER (WHERE status = 'open') as open,
                COUNT(*) FILTER (WHERE status = 'fixed') as fixed,
                COUNT(*) FILTER (WHERE exploit_available = true) as exploitable,
                COUNT(*) FILTER (WHERE cisa_kev = true) as cisa_kev,
                COUNT(*) FILTER (WHERE ransomware_related = true) as ransomware
            FROM findings
        """
        params = []
        
        if tenant_id:
            query += " WHERE tenant_id = $1"
            params.append(tenant_id)
        
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(query, *params)
            return dict(row) if row else {}
    
    # ============ Analytics Queries ============
    
    async def get_trend_data(self, tenant_id: Optional[str] = None,
                               days: int = 30) -> List[Dict]:
        """Get trend data for charts"""
        query = """
            SELECT 
                DATE(found_at) as date,
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low
            FROM findings
            WHERE found_at > NOW() - $1::interval
        """
        params = [f"{days} days"]
        
        if tenant_id:
            query += " AND tenant_id = $2"
            params.append(tenant_id)
        
        query += " GROUP BY DATE(found_at) ORDER BY date DESC"
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    async def get_scanner_performance(self, tenant_id: Optional[str] = None,
                                        days: int = 30) -> List[Dict]:
        """Get scanner performance metrics"""
        query = """
            SELECT 
                scanner,
                COUNT(*) as total_scans,
                AVG(EXTRACT(EPOCH FROM (end_time - start_time))) as avg_duration,
                COUNT(*) FILTER (WHERE status = 'completed') as successful,
                COUNT(*) FILTER (WHERE status = 'failed') as failed
            FROM scans
            WHERE start_time > NOW() - $1::interval
        """
        params = [f"{days} days"]
        
        if tenant_id:
            query += " AND tenant_id = $2"
            params.append(tenant_id)
        
        query += " GROUP BY scanner"
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    async def get_compliance_summary(self, tenant_id: str) -> Dict:
        """Get compliance summary for tenant"""
        query = """
            SELECT 
                framework,
                compliance_score,
                total_findings,
                critical_findings,
                high_findings,
                generated_at
            FROM compliance_reports
            WHERE tenant_id = $1
            ORDER BY generated_at DESC
            LIMIT 1
        """
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, tenant_id)
            return {
                'latest': [dict(row) for row in rows],
                'history': await self._get_compliance_history(tenant_id, conn)
            }
    
    async def _get_compliance_history(self, tenant_id: str, conn) -> List[Dict]:
        """Get compliance score history"""
        rows = await conn.fetch("""
            SELECT 
                DATE(generated_at) as date,
                framework,
                compliance_score
            FROM compliance_reports
            WHERE tenant_id = $1
                AND generated_at > NOW() - INTERVAL '90 days'
            ORDER BY generated_at DESC
        """, tenant_id)
        
        return [dict(row) for row in rows]
    
    # ============ MTTR Calculations ============
    
    async def calculate_mttr(self, tenant_id: Optional[str] = None) -> float:
        """Calculate Mean Time to Remediate in hours"""
        query = """
            SELECT AVG(EXTRACT(EPOCH FROM (remediated_at - found_at))/3600) as mttr
            FROM findings
            WHERE remediated_at IS NOT NULL
        """
        params = []
        
        if tenant_id:
            query += " AND tenant_id = $1"
            params.append(tenant_id)
        
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(query, *params)
            return float(result) if result else 0.0
    
    async def calculate_mttr_by_severity(self, tenant_id: Optional[str] = None) -> Dict:
        """Calculate MTTR by severity"""
        query = """
            SELECT 
                severity,
                AVG(EXTRACT(EPOCH FROM (remediated_at - found_at))/3600) as mttr
            FROM findings
            WHERE remediated_at IS NOT NULL
        """
        params = []
        
        if tenant_id:
            query += " AND tenant_id = $1"
            params.append(tenant_id)
        
        query += " GROUP BY severity"
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return {row['severity']: float(row['mttr']) for row in rows}