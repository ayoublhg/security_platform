#!/usr/bin/env python3
"""
Tenants API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List, Dict, Optional
import aiohttp

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])

async def get_orchestrator_url():
    return "http://orchestrator:8000"

@router.post("")
async def create_tenant(request: Request):
    """Create a new tenant"""
    # Only admin can create tenants
    if request.state.user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        data = await request.json()
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{await get_orchestrator_url()}/api/v1/tenants",
                json=data
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{tenant_id}")
async def get_tenant(tenant_id: str, request: Request):
    """Get tenant details"""
    # Users can only access their own tenant unless admin
    if request.state.user['role'] != 'admin' and request.state.user['tenant_id'] != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/tenants/{tenant_id}"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("")
async def list_tenants(request: Request):
    """List all tenants"""
    # Only admin can list all tenants
    if request.state.user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/tenants"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{tenant_id}")
async def update_tenant(tenant_id: str, request: Request):
    """Update tenant configuration"""
    # Only admin can update tenants
    if request.state.user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        data = await request.json()
        
        async with aiohttp.ClientSession() as session:
            async with session.put(
                f"{await get_orchestrator_url()}/api/v1/tenants/{tenant_id}",
                json=data
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{tenant_id}")
async def delete_tenant(tenant_id: str, request: Request):
    """Delete a tenant"""
    # Only admin can delete tenants
    if request.state.user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(
                f"{await get_orchestrator_url()}/api/v1/tenants/{tenant_id}"
            ) as resp:
                if resp.status == 204:
                    return {"status": "deleted"}
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{tenant_id}/stats")
async def get_tenant_stats(tenant_id: str, request: Request):
    """Get tenant statistics"""
    # Users can only access their own tenant unless admin
    if request.state.user['role'] != 'admin' and request.state.user['tenant_id'] != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_orchestrator_url()}/api/v1/tenants/{tenant_id}/stats"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))