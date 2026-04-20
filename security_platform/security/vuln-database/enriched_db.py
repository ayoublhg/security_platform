#!/usr/bin/env python3
"""
Enterprise Vulnerability Database with Enrichment from Multiple Sources
"""

from fastapi import FastAPI, HTTPException
import aiohttp
import asyncio
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass, asdict
import redis.asyncio as redis
import os
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vulnerability Database", version="1.0.0")

@dataclass
class EnrichedVulnerability:
    """Enhanced vulnerability data model"""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    epss_score: float
    exploit_available: bool
    exploit_type: Optional[str] = None
    ransomware_associated: bool = False
    cisa_kev: bool = False
    patch_available: bool = False
    
    def to_dict(self):
        data = asdict(self)
        return data

class EnrichedVulnerabilityDatabase:
    """Advanced vulnerability database with multiple enrichment sources"""
    
    def __init__(self):
        self.cache = None
        self.db_path = 'vulnerability_db.sqlite'
        self.init_database()
        
    async def initialize(self):
        """Initialize Redis connection"""
        self.cache = await redis.from_url(
            "redis://redis:6379",
            decode_responses=True
        )
        logger.info("✅ Vuln Database connected to Redis")
        
    def init_database(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                data JSON,
                epss_score REAL,
                exploit_available BOOLEAN,
                cisa_kev BOOLEAN,
                last_updated TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def enrich_vulnerability(self, cve_id: str) -> EnrichedVulnerability:
        """Enrich a single vulnerability with data from all sources"""
        
        # Check cache first
        if self.cache:
            cached = await self.cache.get(f"vuln:{cve_id}")
            if cached:
                return EnrichedVulnerability(**json.loads(cached))
        
        # Mock data for now
        enriched = EnrichedVulnerability(
            cve_id=cve_id,
            cvss_score=7.5,
            severity="HIGH",
            description=f"Sample vulnerability {cve_id}",
            epss_score=0.85,
            exploit_available=True,
            cisa_kev=True
        )
        
        # Cache for 1 hour
        if self.cache:
            await self.cache.setex(
                f"vuln:{cve_id}",
                3600,
                json.dumps(enriched.to_dict())
            )
        
        return enriched
    
    def get_priority_score(self, vuln: EnrichedVulnerability) -> float:
        """Calculate priority score for remediation"""
        score = vuln.cvss_score
        score += vuln.epss_score * 10
        if vuln.exploit_available:
            score += 3.0
        if vuln.cisa_kev:
            score += 5.0
        return min(score, 20.0)

# Initialize database
vuln_db = EnrichedVulnerabilityDatabase()

@app.on_event("startup")
async def startup():
    await vuln_db.initialize()

@app.get("/")
async def root():
    return {
        "service": "Vulnerability Database",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/api/v1/vuln/{cve_id}")
async def get_vulnerability(cve_id: str):
    """Get enriched vulnerability data"""
    try:
        vuln = await vuln_db.enrich_vulnerability(cve_id)
        return vuln.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/priority/{cve_id}")
async def get_priority(cve_id: str):
    """Get priority score for a vulnerability"""
    try:
        vuln = await vuln_db.enrich_vulnerability(cve_id)
        score = vuln_db.get_priority_score(vuln)
        return {
            "cve_id": cve_id,
            "priority_score": score,
            "priority_level": "CRITICAL" if score >= 15 else "HIGH" if score >= 10 else "MEDIUM"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)