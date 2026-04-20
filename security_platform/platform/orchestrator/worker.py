#!/usr/bin/env python3
"""
Worker - Background worker that processes scans from queue
"""

import asyncio
import logging
from typing import Dict, Optional
from datetime import datetime
import asyncpg
import aioredis

from .scanner_manager import ScannerManager
from .tenant_manager import TenantManager
from .queue_manager import QueueManager

logger = logging.getLogger(__name__)

class ScanWorker:
    """Background worker that processes queued scans"""
    
    def __init__(self, db_pool, redis_client):
        self.db_pool = db_pool
        self.redis = redis_client
        self.scanner_manager = ScannerManager()
        self.tenant_manager = TenantManager(db_pool)
        self.queue_manager = QueueManager(redis_client)
        self.running = False
        self.active_scans = {}
        
    async def start(self):
        """Start the worker"""
        self.running = True
        logger.info("Scan worker started")
        
        # Recover queues from Redis
        await self.queue_manager.recover_from_redis()
        
        # Start worker loop
        asyncio.create_task(self._worker_loop())
        
    async def stop(self):
        """Stop the worker"""
        self.running = False
        logger.info("Scan worker stopped")
        
    async def _worker_loop(self):
        """Main worker loop"""
        while self.running:
            try:
                # Get next scan from queue
                scan_data = await self.queue_manager.dequeue()
                
                if scan_data:
                    # Process scan
                    asyncio.create_task(self._process_scan(scan_data))
                else:
                    # No scans, wait a bit
                    await asyncio.sleep(1)
                    
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(5)
    
    async def _process_scan(self, scan_data: Dict):
        """Process a single scan"""
        scan_id = scan_data['scan_id']
        tenant_id = scan_data['tenant_id']
        
        logger.info(f"Processing scan {scan_id} for tenant {tenant_id}")
        
        try:
            # Update scan status
            await self._update_scan_status(scan_id, 'running')
            
            # Get scan details from database
            scan = await self._get_scan_details(scan_id)
            if not scan:
                raise Exception(f"Scan {scan_id} not found")
            
            # Clone repository
            repo_path = await self._clone_repository(
                scan['repo_url'],
                scan['metadata'].get('branch', 'main')
            )
            
            # Run scanners
            scan_types = scan['metadata'].get('scan_types', ['sast'])
            findings = await self.scanner_manager.run_scans(repo_path, scan_types)
            
            # Calculate summary
            summary = self._calculate_summary(findings)
            
            # Store results
            await self._store_results(scan_id, findings, summary)
            
            # Trigger notifications
            await self._send_notifications(tenant_id, scan_id, findings, summary)
            
            # Auto-remediate if possible
            await self._trigger_remediation(tenant_id, findings)
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            await self._handle_failure(scan_id, str(e))
            
            # Requeue if retryable
            if self._is_retryable(e):
                await self.queue_manager.requeue_failed(scan_data)
    
    async def _clone_repository(self, repo_url: str, branch: str) -> str:
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
    
    async def _update_scan_status(self, scan_id: str, status: str):
        """Update scan status in database"""
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status = $1, updated_at = NOW() WHERE scan_id = $2",
                status, scan_id
            )
        
        # Update Redis cache
        await self.redis.setex(
            f"scan:{scan_id}:status",
            3600,
            status
        )
    
    async def _get_scan_details(self, scan_id: str) -> Optional[Dict]:
        """Get scan details from database"""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scans WHERE scan_id = $1",
                scan_id
            )
            return dict(row) if row else None
    
    async def _store_results(self, scan_id: str, findings: Dict, summary: Dict):
        """Store scan results in database"""
        async with self.db_pool.acquire() as conn:
            # Update scan record
            await conn.execute("""
                UPDATE scans 
                SET findings = $1, summary = $2, status = 'completed', 
                    end_time = NOW(), updated_at = NOW()
                WHERE scan_id = $3
            """, json.dumps(findings), json.dumps(summary), scan_id)
            
            # Store individual findings
            for scanner_type, scanner_findings in findings.items():
                for finding in scanner_findings:
                    await conn.execute("""
                        INSERT INTO findings (
                            finding_id, scan_id, tenant_id, title, severity,
                            scanner, file_path, line_number, description,
                            metadata, status, found_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
                    """,
                        finding.get('id', f"{scanner_type}-{len(findings)}"),
                        scan_id,
                        finding.get('tenant_id', 'default'),
                        finding.get('title', 'No title'),
                        finding.get('severity', 'info'),
                        finding.get('scanner', scanner_type),
                        finding.get('file', ''),
                        finding.get('line', 0),
                        finding.get('description', ''),
                        json.dumps(finding),
                        'open'
                    )
    
    async def _send_notifications(self, tenant_id: str, scan_id: str,
                                  findings: Dict, summary: Dict):
        """Send notifications via webhooks, Slack, etc."""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return
        
        # Send to webhook if configured
        if tenant.get('webhook_url'):
            import aiohttp
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(
                        tenant['webhook_url'],
                        json={
                            'scan_id': scan_id,
                            'findings': summary,
                            'tenant_id': tenant_id
                        },
                        timeout=5
                    )
            except Exception as e:
                logger.error(f"Failed to send webhook: {e}")
        
        # Send to Slack if configured
        if tenant.get('slack_channel'):
            await self._send_slack_notification(
                tenant['slack_channel'],
                scan_id,
                summary
            )
    
    async def _send_slack_notification(self, channel: str, scan_id: str, summary: Dict):
        """Send Slack notification"""
        # This would require Slack webhook URL
        pass
    
    async def _trigger_remediation(self, tenant_id: str, findings: Dict):
        """Trigger auto-remediation for critical findings"""
        critical_findings = []
        for scanner, scanner_findings in findings.items():
            for finding in scanner_findings:
                if finding.get('severity') == 'critical':
                    critical_findings.append(finding)
        
        if critical_findings:
            # Call remediation service
            import aiohttp
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(
                        "http://auto-remediation:8003/api/remediate",
                        json={
                            'tenant_id': tenant_id,
                            'findings': critical_findings
                        },
                        timeout=10
                    )
            except Exception as e:
                logger.error(f"Failed to trigger remediation: {e}")
    
    async def _handle_failure(self, scan_id: str, error: str):
        """Handle scan failure"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE scans 
                SET status = 'failed', end_time = NOW(), 
                    metadata = metadata || $1
                WHERE scan_id = $2
            """, json.dumps({'error': error}), scan_id)
    
    def _calculate_summary(self, findings: Dict) -> Dict:
        """Calculate summary statistics"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        }
        
        for scanner, scanner_findings in findings.items():
            for finding in scanner_findings:
                severity = finding.get('severity', 'info').lower()
                if severity in summary:
                    summary[severity] += 1
                summary['total'] += 1
        
        return summary
    
    def _is_retryable(self, error: Exception) -> bool:
        """Check if error is retryable"""
        non_retryable = [
            'not found',
            'invalid',
            'permission denied',
            'unauthorized'
        ]
        error_str = str(error).lower()
        return not any(msg in error_str for msg in non_retryable)