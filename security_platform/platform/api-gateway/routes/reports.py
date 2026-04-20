#!/usr/bin/env python3
"""
Reports API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from typing import List, Dict, Optional
import aiohttp
from datetime import datetime

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

async def get_compliance_url():
    return "http://compliance-mapper:8002"

@router.post("/compliance")
async def generate_compliance_report(request: Request):
    """Generate compliance report"""
    try:
        data = await request.json()
        tenant_id = request.state.user['tenant_id']
        
        # Add tenant_id to data
        data['tenant_id'] = tenant_id
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{await get_compliance_url()}/api/v1/compliance/report",
                json=data
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/compliance/{report_id}")
async def get_compliance_report(report_id: str, request: Request):
    """Get compliance report"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_compliance_url()}/api/v1/compliance/report/{report_id}"
            ) as resp:
                result = await resp.json()
                return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/compliance/frameworks")
async def list_frameworks(request: Request):
    """List available compliance frameworks"""
    return {
        "frameworks": [
            "SOC2",
            "PCI-DSS",
            "HIPAA",
            "ISO27001",
            "NIST-800-53"
        ]
    }

@router.get("/findings")
async def generate_findings_report(request: Request):
    """Generate findings report"""
    try:
        tenant_id = request.state.user['tenant_id']
        format = request.query_params.get('format', 'json')
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{await get_compliance_url()}/api/v1/findings/report",
                params={'tenant_id': tenant_id, 'format': format}
            ) as resp:
                if format == 'pdf':
                    # Return PDF file
                    pdf_data = await resp.read()
                    return Response(
                        content=pdf_data,
                        media_type='application/pdf',
                        headers={
                            'Content-Disposition': f'attachment; filename="findings-report-{datetime.now().date()}.pdf"'
                        }
                    )
                else:
                    result = await resp.json()
                    return result
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))