#!/usr/bin/env python3
"""
Approval Workflow for Auto-Remediation
Manages approval process for sensitive fixes
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import asyncpg
import aioredis

logger = logging.getLogger(__name__)

class ApprovalWorkflow:
    """Manages approval workflow for auto-remediation"""
    
    def __init__(self, db_pool, redis_client):
        self.db_pool = db_pool
        self.redis = redis_client
        self.approval_timeout = 86400  # 24 hours
        self.required_approvers = {
            'critical': ['security-lead', 'engineering-manager'],
            'high': ['security-engineer'],
            'medium': [],
            'low': []
        }
        
    async def create_approval_request(self, finding_id: str, fix_details: Dict) -> Dict:
        """Create an approval request for a fix"""
        severity = fix_details.get('severity', 'medium')
        required_approvers = self.required_approvers.get(severity, [])
        
        request_id = f"apr_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{finding_id[:8]}"
        
        request = {
            'request_id': request_id,
            'finding_id': finding_id,
            'severity': severity,
            'fix_details': fix_details,
            'required_approvers': required_approvers,
            'approvals': {},
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(seconds=self.approval_timeout)).isoformat(),
            'comments': []
        }
        
        # Store in database
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO approval_requests (
                    request_id, finding_id, severity, fix_details,
                    required_approvers, status, created_at, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
                request_id,
                finding_id,
                severity,
                json.dumps(fix_details),
                json.dumps(required_approvers),
                'pending',
                datetime.now(),
                datetime.fromisoformat(request['expires_at'])
            )
        
        # Cache in Redis
        await self.redis.setex(
            f"approval:{request_id}",
            self.approval_timeout,
            json.dumps(request)
        )
        
        logger.info(f"Created approval request {request_id} for finding {finding_id}")
        return request
    
    async def approve(self, request_id: str, approver: str, 
                       comment: Optional[str] = None) -> bool:
        """Approve a remediation request"""
        request = await self.get_request(request_id)
        if not request:
            logger.error(f"Approval request {request_id} not found")
            return False
        
        if request['status'] != 'pending':
            logger.warning(f"Request {request_id} is already {request['status']}")
            return False
        
        if datetime.now().isoformat() > request['expires_at']:
            await self._update_status(request_id, 'expired')
            logger.warning(f"Request {request_id} has expired")
            return False
        
        # Record approval
        request['approvals'][approver] = {
            'approved_at': datetime.now().isoformat(),
            'comment': comment
        }
        
        if comment:
            request['comments'].append({
                'user': approver,
                'comment': comment,
                'timestamp': datetime.now().isoformat()
            })
        
        # Check if all required approvals received
        required = set(request['required_approvers'])
        received = set(request['approvals'].keys())
        
        if required.issubset(received):
            request['status'] = 'approved'
            await self._execute_approved_fix(request)
        else:
            request['status'] = 'partially_approved'
        
        # Update storage
        await self._update_request(request)
        
        logger.info(f"Request {request_id} approved by {approver}")
        return True
    
    async def reject(self, request_id: str, approver: str,
                      reason: str) -> bool:
        """Reject a remediation request"""
        request = await self.get_request(request_id)
        if not request:
            return False
        
        request['status'] = 'rejected'
        request['comments'].append({
            'user': approver,
            'comment': f"REJECTED: {reason}",
            'timestamp': datetime.now().isoformat()
        })
        
        await self._update_request(request)
        
        logger.info(f"Request {request_id} rejected by {approver}: {reason}")
        return True
    
    async def add_comment(self, request_id: str, user: str,
                           comment: str) -> bool:
        """Add a comment to an approval request"""
        request = await self.get_request(request_id)
        if not request:
            return False
        
        request['comments'].append({
            'user': user,
            'comment': comment,
            'timestamp': datetime.now().isoformat()
        })
        
        await self._update_request(request)
        return True
    
    async def get_request(self, request_id: str) -> Optional[Dict]:
        """Get approval request details"""
        # Try Redis first
        cached = await self.redis.get(f"approval:{request_id}")
        if cached:
            return json.loads(cached)
        
        # Try database
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM approval_requests WHERE request_id = $1",
                request_id
            )
            if row:
                return dict(row)
        
        return None
    
    async def get_pending_requests(self, approver: Optional[str] = None) -> List[Dict]:
        """Get pending approval requests"""
        async with self.db_pool.acquire() as conn:
            if approver:
                # Get requests where approver is required and hasn't approved yet
                rows = await conn.fetch("""
                    SELECT * FROM approval_requests 
                    WHERE status = 'pending' 
                    AND required_approvers::jsonb ? $1
                    AND NOT approvals::jsonb ? $1
                    ORDER BY created_at DESC
                """, approver)
            else:
                rows = await conn.fetch("""
                    SELECT * FROM approval_requests 
                    WHERE status IN ('pending', 'partially_approved')
                    ORDER BY created_at DESC
                """)
            
            return [dict(row) for row in rows]
    
    async def check_expired(self):
        """Check for and handle expired requests"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE approval_requests
                SET status = 'expired'
                WHERE status = 'pending' 
                AND expires_at < NOW()
            """)
    
    async def _execute_approved_fix(self, request: Dict):
        """Execute the approved fix"""
        fix_details = request['fix_details']
        
        # Call remediation engine
        from .remediation_engine import AutoRemediationEngine
        engine = AutoRemediationEngine()
        
        result = await engine.execute_fix(
            request['finding_id'],
            fix_details
        )
        
        # Store result
        request['execution_result'] = result
        request['executed_at'] = datetime.now().isoformat()
        
        logger.info(f"Executed fix for request {request['request_id']}")
    
    async def _update_request(self, request: Dict):
        """Update request in both Redis and database"""
        # Update Redis
        ttl = await self.redis.ttl(f"approval:{request['request_id']}")
        if ttl > 0:
            await self.redis.setex(
                f"approval:{request['request_id']}",
                ttl,
                json.dumps(request)
            )
        
        # Update database
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE approval_requests
                SET status = $1,
                    approvals = $2,
                    comments = $3,
                    updated_at = NOW()
                WHERE request_id = $4
            """,
                request['status'],
                json.dumps(request['approvals']),
                json.dumps(request.get('comments', [])),
                request['request_id']
            )
    
    async def _update_status(self, request_id: str, status: str):
        """Update request status"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE approval_requests
                SET status = $1, updated_at = NOW()
                WHERE request_id = $2
            """, status, request_id)
            
            # Update Redis if exists
            cached = await self.redis.get(f"approval:{request_id}")
            if cached:
                request = json.loads(cached)
                request['status'] = status
                ttl = await self.redis.ttl(f"approval:{request_id}")
                if ttl > 0:
                    await self.redis.setex(
                        f"approval:{request_id}",
                        ttl,
                        json.dumps(request)
                    )