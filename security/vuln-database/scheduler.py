#!/usr/bin/env python3
"""
Update Scheduler for Vulnerability Databases
Manages periodic updates of all data sources
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import json

from .nvd_fetcher import NVDFetcher
from .epss_fetcher import EPSSFetcher
from .exploit_db import ExploitDB
from .cisa_kev import CISACatalog
from .ransomware_tracker import RansomwareTracker

logger = logging.getLogger(__name__)

class UpdateScheduler:
    """Schedules and manages database updates"""
    
    def __init__(self):
        self.nvd = NVDFetcher()
        self.epss = EPSSFetcher()
        self.exploit_db = ExploitDB()
        self.cisa = CISACatalog()
        self.ransomware = RansomwareTracker()
        
        self.update_jobs = [
            {
                'name': 'nvd_daily',
                'interval': 86400,  # 24 hours
                'func': self._update_nvd
            },
            {
                'name': 'epss_daily',
                'interval': 86400,
                'func': self._update_epss
            },
            {
                'name': 'cisa_kev',
                'interval': 86400,
                'func': self._update_cisa
            },
            {
                'name': 'ransomware',
                'interval': 43200,  # 12 hours
                'func': self._update_ransomware
            },
            {
                'name': 'exploit_db',
                'interval': 86400,
                'func': self._update_exploit_db
            }
        ]
        
        self.running = False
        self.last_run = {}
        self.stats = {}
        
    async def start(self):
        """Start the scheduler"""
        self.running = True
        logger.info("Update scheduler started")
        
        # Run initial updates
        await self.run_all_updates()
        
        # Start scheduler loop
        asyncio.create_task(self._scheduler_loop())
    
    async def stop(self):
        """Stop the scheduler"""
        self.running = False
        logger.info("Update scheduler stopped")
    
    async def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            now = datetime.now()
            
            for job in self.update_jobs:
                name = job['name']
                last = self.last_run.get(name)
                
                if not last or (now - last).total_seconds() > job['interval']:
                    try:
                        logger.info(f"Running scheduled update: {name}")
                        result = await job['func']()
                        self.last_run[name] = now
                        self.stats[name] = {
                            'last_run': now.isoformat(),
                            'result': result,
                            'status': 'success'
                        }
                    except Exception as e:
                        logger.error(f"Update {name} failed: {e}")
                        self.stats[name] = {
                            'last_run': now.isoformat(),
                            'error': str(e),
                            'status': 'failed'
                        }
            
            await asyncio.sleep(3600)  # Check every hour
    
    async def run_all_updates(self) -> Dict[str, any]:
        """Run all updates immediately"""
        results = {}
        
        for job in self.update_jobs:
            try:
                result = await job['func']()
                results[job['name']] = {
                    'status': 'success',
                    'result': result
                }
            except Exception as e:
                results[job['name']] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        return results
    
    async def _update_nvd(self) -> Dict:
        """Update NVD database"""
        added = await self.nvd.fetch_recent(days=7)
        return {
            'added': added,
            'total': (await self.nvd.get_stats())['total_cves']
        }
    
    async def _update_epss(self) -> Dict:
        """Update EPSS scores"""
        # Try bulk download first
        count = await self.epss.fetch_bulk()
        if count == 0:
            count = await self.epss.fetch_recent()
        
        return {
            'updated': count,
            'stats': await self.epss.get_stats()
        }
    
    async def _update_cisa(self) -> Dict:
        """Update CISA KEV catalog"""
        count = await self.cisa.fetch_catalog()
        return {
            'updated': count,
            'stats': await self.cisa.get_stats()
        }
    
    async def _update_ransomware(self) -> Dict:
        """Update ransomware CVEs"""
        results = await self.ransomware.fetch_all()
        return {
            'sources': results,
            'stats': await self.ransomware.get_stats()
        }
    
    async def _update_exploit_db(self) -> Dict:
        """Update exploit database (placeholder)"""
        # Exploit DB updates are on-demand via checks
        return {
            'status': 'skipped',
            'stats': await self.exploit_db.get_stats()
        }
    
    async def get_status(self) -> Dict:
        """Get scheduler status"""
        return {
            'running': self.running,
            'last_runs': {k: v.isoformat() if v else None for k, v in self.last_run.items()},
            'stats': self.stats,
            'jobs': [
                {
                    'name': j['name'],
                    'interval_hours': j['interval'] / 3600
                }
                for j in self.update_jobs
            ]
        }