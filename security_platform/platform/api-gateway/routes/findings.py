#!/usr/bin/env python3
"""
Findings API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Query
from typing import List, Dict, Optional
import aiohttp
from datetime import datetime

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

async def get_orchestrator_url():
    return "http://orchestrator:8000"

@router.get("")
async def list_findings(
    request: Request,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = Query(None, regex="^(open|fixed|false_positive|accepted_risk)$"),
    limit: int = 100,
    offset: int = 0
):
    """List findings with filters"""
    try:
        tenant_id = request.state.user['tenant_id']
        
        params = {
            'tenant_id': tenant_id,
            'limit': limit,
            'offset': offset
        }
        if scan_id:
            params['scan_id'] = scan_id
        if severity:
            params['severity'] = severity
        if status:
            params['status'] = status
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/findings",
                params=params
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{finding_id}")
async def get_finding(finding_id: str, request: Request):
    """Get finding details"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/findings/{finding_id}"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/{finding_id}")
async def update_finding(finding_id: str, request: Request):
    """Update finding (status, notes, etc.)"""
    try:
        data = await request.json()
        
        async with aiohttp.ClientSession() as session:
            async with session.patch(
                f"{await get_orchestrator_url()}/api/v1/findings/{finding_id}",
                json=data
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{finding_id}/remediate")
async def remediate_finding(finding_id: str, request: Request):
    """Trigger remediation for a finding"""
    try:
        data = await request.json() if await request.body() else {}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://auto-remediation:8003/api/remediate/{finding_id}",
                json=data
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_finding_stats(request: Request):
    """Get finding statistics"""
    try:
        tenant_id = request.state.user['tenant_id']
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/findings/stats?tenant_id={tenant_id}"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))