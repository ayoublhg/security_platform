#!/usr/bin/env python3
"""
Planificateur de scans automatiques
"""

import asyncio
import aiohttp
import logging
from datetime import datetime, time
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import json
import os

logger = logging.getLogger(__name__)

class ScanScheduler:
    """Planifie et exécute des scans automatiques"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.api_url = "http://api-gateway:8080/api/v1"
        self.tenant_id = "default"
        self.jobs = {}
        
        # Charger les configurations
        self.load_scheduled_scans()
    
    def load_scheduled_scans(self):
        """Charger les scans planifiés depuis la base de données"""
        # Configurations par défaut
        self.scheduled_scans = [
            {
                "id": "daily_scan",
                "name": "Scan Quotidien",
                "repo_url": "https://github.com/juice-shop/juice-shop.git",
                "scan_types": ["sast", "secrets"],
                "schedule_type": "daily",
                "schedule_time": "02:00",  # 2h du matin
                "enabled": True
            },
            {
                "id": "weekly_scan",
                "name": "Scan Hebdomadaire",
                "repo_url": "https://github.com/OWASP/WebGoat.git",
                "scan_types": ["sast", "secrets", "container"],
                "schedule_type": "weekly",
                "schedule_day": "monday",
                "schedule_time": "03:00",
                "enabled": True
            }
        ]
    
    async def execute_scan(self, scan_config):
        """Exécuter un scan planifié"""
        logger.info(f"📅 Exécution du scan planifié: {scan_config['name']}")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.api_url}/scans",
                    json={
                        "repo_url": scan_config['repo_url'],
                        "scan_types": scan_config['scan_types'],
                        "tenant_id": self.tenant_id
                    },
                    headers={"Content-Type": "application/json"}
                ) as resp:
                    result = await resp.json()
                    logger.info(f"✅ Scan planifié démarré: {result.get('scan_id')}")
                    return result
            except Exception as e:
                logger.error(f"❌ Erreur scan planifié: {e}")
                return None
    
    def setup_jobs(self):
        """Configurer les jobs planifiés"""
        for scan in self.scheduled_scans:
            if not scan.get('enabled', True):
                continue
            
            job_id = scan['id']
            
            if scan['schedule_type'] == 'daily':
                # Scan quotidien à une heure spécifique
                hour, minute = map(int, scan['schedule_time'].split(':'))
                trigger = CronTrigger(hour=hour, minute=minute)
                
            elif scan['schedule_type'] == 'weekly':
                # Scan hebdomadaire
                hour, minute = map(int, scan['schedule_time'].split(':'))
                day_map = {
                    'monday': 0, 'tuesday': 1, 'wednesday': 2,
                    'thursday': 3, 'friday': 4, 'saturday': 5, 'sunday': 6
                }
                day = day_map.get(scan['schedule_day'].lower(), 0)
                trigger = CronTrigger(day_of_week=day, hour=hour, minute=minute)
                
            elif scan['schedule_type'] == 'interval':
                # Scan à intervalle régulier
                trigger = IntervalTrigger(hours=scan.get('interval_hours', 24))
            
            else:
                continue
            
            self.scheduler.add_job(
                self.execute_scan,
                trigger=trigger,
                args=[scan],
                id=job_id,
                replace_existing=True
            )
            
            logger.info(f"📅 Scan planifié ajouté: {scan['name']} - {trigger}")
    
    def start(self):
        """Démarrer le planificateur"""
        self.setup_jobs()
        self.scheduler.start()
        logger.info("🚀 Scan Scheduler démarré")
    
    def stop(self):
        """Arrêter le planificateur"""
        self.scheduler.shutdown()
        logger.info("🛑 Scan Scheduler arrêté")
    
    def add_scheduled_scan(self, scan_config):
        """Ajouter un nouveau scan planifié"""
        self.scheduled_scans.append(scan_config)
        self.setup_jobs()
        logger.info(f"➕ Nouveau scan planifié ajouté: {scan_config['name']}")
    
    def remove_scheduled_scan(self, scan_id):
        """Supprimer un scan planifié"""
        self.scheduled_scans = [s for s in self.scheduled_scans if s['id'] != scan_id]
        self.scheduler.remove_job(scan_id)
        logger.info(f"➖ Scan planifié supprimé: {scan_id}")
    
    def get_scheduled_scans(self):
        """Récupérer la liste des scans planifiés"""
        return self.scheduled_scans