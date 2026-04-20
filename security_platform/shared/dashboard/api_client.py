#!/usr/bin/env python3
"""
API Client for Dashboard to communicate with backend services
"""

import aiohttp
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class APIClient:
    """Client for backend API communication"""
    
    def __init__(self, base_url: str = "http://api-gateway:8080"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.auth_token: Optional[str] = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _ensure_session(self):
        """Ensure session exists"""
        if not self.session:
            self.session = aiohttp.ClientSession()
    
    async def _request(self, method: str, endpoint: str, 
                        data: Optional[Dict] = None,
                        params: Optional[Dict] = None) -> Any:
        """Make HTTP request"""
        await self._ensure_session()
        
        url = f"{self.base_url}{endpoint}"
        headers = {}
        
        if self.auth_token:
            headers['Authorization'] = f"Bearer {self.auth_token}"
        
        try:
            async with self.session.request(
                method, url, json=data, params=params, headers=headers
            ) as response:
                if response.status == 204:
                    return None
                
                try:
                    result = await response.json()
                except:
                    result = await response.text()
                
                if response.status >= 400:
                    logger.error(f"API error {response.status}: {result}")
                    raise Exception(f"API error: {result}")
                
                return result
                
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {e}")
            raise
    
    # ============ Authentication ============
    
    async def login(self, api_key: str, tenant_id: str = "default") -> Dict:
        """Login to API"""
        result = await self._request('POST', '/api/v1/auth/login', {
            'api_key': api_key,
            'tenant_id': tenant_id,
            'user_id': 'dashboard'
        })
        
        if result and 'token' in result:
            self.auth_token = result['token']
        
        return result
    
    # ============ Scan endpoints ============
    
    async def create_scan(self, repo_url: str, scan_types: List[str],
                           branch: str = "main", depth: str = "standard") -> Dict:
        """Create a new scan"""
        return await self._request('POST', '/api/v1/scans', {
            'repo_url': repo_url,
            'branch': branch,
            'scan_types': scan_types,
            'depth': depth
        })
    
    async def get_scan(self, scan_id: str) -> Dict:
        """Get scan details"""
        return await self._request('GET', f'/api/v1/scans/{scan_id}')
    
    async def list_scans(self, limit: int = 100, offset: int = 0,
                          status: Optional[str] = None) -> List[Dict]:
        """List scans"""
        params = {'limit': limit, 'offset': offset}
        if status:
            params['status'] = status
        
        return await self._request('GET', '/api/v1/scans', params=params)
    
    async def get_scan_results(self, scan_id: str) -> Dict:
        """Get scan results with findings"""
        return await self._request('GET', f'/api/v1/scans/{scan_id}/results')
    
    async def cancel_scan(self, scan_id: str) -> Dict:
        """Cancel running scan"""
        return await self._request('POST', f'/api/v1/scans/{scan_id}/cancel')
    
    # ============ Finding endpoints ============
    
    async def list_findings(self, scan_id: Optional[str] = None,
                             severity: Optional[str] = None,
                             status: Optional[str] = None,
                             finding_type: Optional[str] = None,
                             limit: int = 100,
                             offset: int = 0) -> List[Dict]:
        """List findings with filters"""
        params = {'limit': limit, 'offset': offset}
        if scan_id:
            params['scan_id'] = scan_id
        if severity:
            params['severity'] = severity
        if status:
            params['status'] = status
        if finding_type:
            params['type'] = finding_type
        
        return await self._request('GET', '/api/v1/findings', params=params)
    
    async def get_finding(self, finding_id: str) -> Dict:
        """Get finding details"""
        return await self._request('GET', f'/api/v1/findings/{finding_id}')
    
    async def update_finding(self, finding_id: str, status: str,
                              comment: Optional[str] = None) -> Dict:
        """Update finding status"""
        data = {'status': status}
        if comment:
            data['comment'] = comment
        
        return await self._request('PATCH', f'/api/v1/findings/{finding_id}', data)
    
    async def remediate_finding(self, finding_id: str, strategy: str = "auto") -> Dict:
        """Trigger remediation for finding"""
        return await self._request('POST', f'/api/v1/findings/{finding_id}/remediate', {
            'strategy': strategy
        })
    
    async def get_finding_stats(self) -> Dict:
        """Get finding statistics"""
        return await self._request('GET', '/api/v1/findings/stats')
    
    # ============ Tenant endpoints ============
    
    async def get_tenant(self, tenant_id: str) -> Dict:
        """Get tenant details"""
        return await self._request('GET', f'/api/v1/tenants/{tenant_id}')
    
    async def get_tenant_stats(self, tenant_id: str) -> Dict:
        """Get tenant statistics"""
        return await self._request('GET', f'/api/v1/tenants/{tenant_id}/stats')
    
    # ============ Report endpoints ============
    
    async def generate_compliance_report(self, framework: str,
                                           format: str = "json") -> Dict:
        """Generate compliance report"""
        return await self._request('POST', '/api/v1/reports/compliance', {
            'framework': framework,
            'format': format
        })
    
    async def get_compliance_report(self, report_id: str) -> Dict:
        """Get compliance report"""
        return await self._request('GET', f'/api/v1/reports/compliance/{report_id}')
    
    async def generate_findings_report(self, format: str = "json") -> Dict:
        """Generate findings report"""
        return await self._request('GET', '/api/v1/reports/findings',
                                     params={'format': format})
    
    # ============ Dashboard specific endpoints ============
    
    async def get_dashboard_overview(self) -> Dict:
        """Get dashboard overview data"""
        return await self._request('GET', '/api/v1/dashboard/overview')
    
    async def get_trend_data(self, days: int = 30) -> List[Dict]:
        """Get trend data for charts"""
        return await self._request('GET', '/api/v1/analytics/trend',
                                     params={'days': days})
    
    async def get_compliance_summary(self) -> Dict:
        """Get compliance summary"""
        return await self._request('GET', '/api/v1/analytics/compliance')
    
    async def get_remediation_queue(self) -> List[Dict]:
        """Get pending remediation queue"""
        return await self._request('GET', '/api/v1/analytics/remediation-queue')
    
    async def get_recent_activity(self, limit: int = 20) -> List[Dict]:
        """Get recent activity"""
        return await self._request('GET', '/api/v1/analytics/recent-activity',
                                     params={'limit': limit})

# Create singleton instance
api_client = APIClient()