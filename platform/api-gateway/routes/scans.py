#!/usr/bin/env python3
"""
Scans API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List, Dict, Optional
import aiohttp
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

async def get_orchestrator_url():
    return "http://orchestrator:8000"

@router.post("")
async def create_scan(request: Request):
    """Create a new scan"""
    try:
        data = await request.json()
        tenant_id = request.state.user['tenant_id']
        
        # Add tenant_id to data
        data['tenant_id'] = tenant_id
        
        # Call orchestrator
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{await get_orchestrator_url()}/api/v1/scans",
                json=data
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    """Get scan details"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/scans/{scan_id}"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("")
async def list_scans(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None
):
    """List scans"""
    try:
        tenant_id = request.state.user['tenant_id']
        
        params = {
            'tenant_id': tenant_id,
            'limit': limit,
            'offset': offset
        }
        if status:
            params['status'] = status
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/scans",
                params=params
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, request: Request):
    """Delete a scan"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(
                f"{await get_orchestrator_url()}/api/v1/scans/{scan_id}"
            ) as resp:
                if resp.status == 204:
                    return {"status": "deleted"}
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: str, request: Request):
    """Get scan results with findings"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/scans/{scan_id}/results"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request):
    """Cancel a running scan"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{await get_orchestrator_url()}/api/v1/scans/{scan_id}/cancel"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))