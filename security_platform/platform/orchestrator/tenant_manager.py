#!/usr/bin/env python3
"""
Tenant Manager - Handles multi-tenant isolation and configuration
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncpg
import json

logger = logging.getLogger(__name__)

class TenantManager:
    """Manages tenant configurations and isolation"""
    
    def __init__(self, db_pool):
        self.db_pool = db_pool
        self.cache = {}  # Simple memory cache
        
    async def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        """Get tenant configuration"""
        # Check cache first
        if tenant_id in self.cache:
            return self.cache[tenant_id]
        
        # Query database
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM tenants WHERE tenant_id = $1 AND active = true",
                tenant_id
            )
            
            if row:
                tenant = dict(row)
                self.cache[tenant_id] = tenant
                return tenant
        
        return None
    
    async def create_tenant(self, tenant_data: Dict) -> Dict:
        """Create a new tenant"""
        tenant_id = tenant_data.get('tenant_id')
        name = tenant_data.get('name', f"Tenant-{tenant_id}")
        max_concurrent = tenant_data.get('max_concurrent_scans', 5)
        allowed_scanners = tenant_data.get('allowed_scanners', 
                                          ['sast', 'sca', 'secrets'])
        webhook_url = tenant_data.get('webhook_url')
        slack_channel = tenant_data.get('slack_channel')
        jira_project = tenant_data.get('jira_project')
        compliance_frameworks = tenant_data.get('compliance_frameworks', [])
        
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO tenants (
                    tenant_id, name, max_concurrent, allowed_scanners,
                    webhook_url, slack_channel, jira_project,
                    compliance_frameworks, active, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    max_concurrent = EXCLUDED.max_concurrent,
                    allowed_scanners = EXCLUDED.allowed_scanners,
                    active = EXCLUDED.active
                """,
                tenant_id, name, max_concurrent, 
                json.dumps(allowed_scanners),
                webhook_url, slack_channel, jira_project,
                json.dumps(compliance_frameworks),
                True, datetime.utcnow()
            )
        
        # Update cache
        tenant = {
            'tenant_id': tenant_id,
            'name': name,
            'max_concurrent': max_concurrent,
            'allowed_scanners': allowed_scanners,
            'webhook_url': webhook_url,
            'slack_channel': slack_channel,
            'jira_project': jira_project,
            'compliance_frameworks': compliance_frameworks
        }
        self.cache[tenant_id] = tenant
        
        logger.info(f"Created tenant: {tenant_id}")
        return tenant
    
    async def update_tenant(self, tenant_id: str, updates: Dict) -> Optional[Dict]:
        """Update tenant configuration"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return None
        
        # Build update query dynamically
        set_clauses = []
        values = []
        idx = 1
        
        for key, value in updates.items():
            if key in ['name', 'max_concurrent', 'webhook_url', 
                      'slack_channel', 'jira_project', 'active']:
                set_clauses.append(f"{key} = ${idx}")
                values.append(value)
                idx += 1
            elif key in ['allowed_scanners', 'compliance_frameworks']:
                set_clauses.append(f"{key} = ${idx}")
                values.append(json.dumps(value))
                idx += 1
        
        if not set_clauses:
            return tenant
        
        values.append(tenant_id)
        query = f"""
            UPDATE tenants 
            SET {', '.join(set_clauses)}, updated_at = NOW()
            WHERE tenant_id = ${idx}
            RETURNING *
        """
        
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(query, *values)
            if row:
                updated = dict(row)
                self.cache[tenant_id] = updated
                return updated
        
        return None
    
    async def delete_tenant(self, tenant_id: str) -> bool:
        """Soft delete a tenant"""
        async with self.db_pool.acquire() as conn:
            result = await conn.execute("""
                UPDATE tenants 
                SET active = false, updated_at = NOW()
                WHERE tenant_id = $1
            """, tenant_id)
            
            if result:
                # Remove from cache
                self.cache.pop(tenant_id, None)
                return True
        
        return False
    
    async def list_tenants(self, include_inactive: bool = False) -> List[Dict]:
        """List all tenants"""
        query = "SELECT * FROM tenants"
        if not include_inactive:
            query += " WHERE active = true"
        
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(query)
            return [dict(row) for row in rows]
    
    async def get_tenant_stats(self, tenant_id: str) -> Dict:
        """Get tenant statistics"""
        async with self.db_pool.acquire() as conn:
            # Scan stats
            scan_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_scans,
                    COUNT(*) FILTER (WHERE status = 'completed') as completed_scans,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
                    AVG(EXTRACT(EPOCH FROM (end_time - start_time))) as avg_duration
                FROM scans
                WHERE tenant_id = $1
                    AND start_time > NOW() - INTERVAL '30 days'
            """, tenant_id)
            
            # Finding stats
            finding_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_findings,
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) FILTER (WHERE status = 'open') as open_findings
                FROM findings
                WHERE tenant_id = $1
            """, tenant_id)
            
            # Compliance stats
            compliance_stats = await conn.fetch("""
                SELECT 
                    framework,
                    compliance_score,
                    report_date
                FROM compliance_reports
                WHERE tenant_id = $1
                ORDER BY report_date DESC
                LIMIT 5
            """, tenant_id)
        
        return {
            'tenant_id': tenant_id,
            'scans': dict(scan_stats) if scan_stats else {},
            'findings': dict(finding_stats) if finding_stats else {},
            'compliance': [dict(row) for row in compliance_stats]
        }
    
    async def check_quota(self, tenant_id: str) -> bool:
        """Check if tenant has reached concurrent scan limit"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False
        
        max_concurrent = tenant.get('max_concurrent', 5)
        
        async with self.db_pool.acquire() as conn:
            active = await conn.fetchval("""
                SELECT COUNT(*)
                FROM scans
                WHERE tenant_id = $1
                    AND status = 'running'
            """, tenant_id)
            
            return active < max_concurrent
    
    def clear_cache(self):
        """Clear tenant cache"""
        self.cache.clear()
        logger.info("Tenant cache cleared")