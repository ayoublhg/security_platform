#!/usr/bin/env python3
"""
Kubernetes Operator for Security Scans
Watches SecurityScan CRDs and orchestrates scans
"""

import kopf
import kubernetes
import aiohttp
import asyncio
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Platform API endpoint
PLATFORM_API = "http://security-platform:8000"

@kopf.on.create('security.platform.io', 'v1', 'securityscans')
async def scan_created(spec, name, namespace, logger, **kwargs):
    """Handle creation of new SecurityScan CRD"""
    
    logger.info(f"SecurityScan {name} created in {namespace}")
    
    # Extract configuration
    repo_url = spec.get('repository')
    branch = spec.get('branch', 'main')
    scan_types = spec.get('scanTypes', ['sast', 'sca', 'secrets'])
    
    # Get tenant ID from namespace labels
    core_v1 = kubernetes.client.CoreV1Api()
    ns = core_v1.read_namespace(namespace)
    tenant_id = ns.metadata.labels.get('tenant-id', 'default')
    
    # Submit scan to platform
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{PLATFORM_API}/api/v1/scans",
            json={
                "repo_url": repo_url,
                "branch": branch,
                "scan_types": scan_types,
                "tenant_id": tenant_id,
                "callback_url": f"http://operator:8080/callback"
            }
        ) as resp:
            result = await resp.json()
            
    # Update status
    return {
        "phase": "scanning",
        "platformScanId": result['scan_id'],
        "startTime": datetime.utcnow().isoformat()
    }

@kopf.on.update('security.platform.io', 'v1', 'securityscans')
async def scan_updated(spec, status, name, namespace, logger, **kwargs):
    """Handle updates to scan configuration"""
    
    # Check if schedule changed
    if 'schedule' in spec:
        # Update cron job
        await update_cron_job(name, namespace, spec)
    
    return {"phase": "updated"}

@kopf.on.delete('security.platform.io', 'v1', 'securityscans')
async def scan_deleted(spec, name, namespace, logger, **kwargs):
    """Cleanup when scan is deleted"""
    logger.info(f"SecurityScan {name} deleted")
    
    # Cancel any running scans
    async with aiohttp.ClientSession() as session:
        await session.delete(
            f"{PLATFORM_API}/api/v1/scans/{name}"
        )

@kopf.timer('security.platform.io', 'v1', 'securityscans', interval=60.0)
async def scan_status(spec, status, name, namespace, logger, **kwargs):
    """Periodically update status"""
    
    if not status or 'platformScanId' not in status:
        return
    
    # Get latest scan status from platform
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{PLATFORM_API}/api/v1/scans/{status['platformScanId']}"
        ) as resp:
            if resp.status == 200:
                scan_data = await resp.json()
                
                return {
                    "phase": scan_data['status'],
                    "lastScanTime": scan_data['end_time'] or scan_data['start_time'],
                    "summary": scan_data['summary']
                }

async def update_cron_job(name, namespace, spec):
    """Update or create cron job for scheduled scans"""
    
    batch_v1 = kubernetes.client.BatchV1Api()
    
    cron_job = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {
            "name": f"scan-{name}",
            "namespace": namespace
        },
        "spec": {
            "schedule": spec['schedule'],
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "scanner",
                                "image": "security-platform/scanner:latest",
                                "env": [
                                    {
                                        "name": "REPO_URL",
                                        "value": spec['repository']
                                    },
                                    {
                                        "name": "SCAN_TYPES",
                                        "value": ",".join(spec.get('scanTypes', []))
                                    }
                                ]
                            }],
                            "restartPolicy": "Never"
                        }
                    }
                }
            }
        }
    }
    
    try:
        batch_v1.create_namespaced_cron_job(namespace, cron_job)
    except:
        batch_v1.patch_namespaced_cron_job(f"scan-{name}", namespace, cron_job)

if __name__ == "__main__":
    # Run the operator
    kopf.run()