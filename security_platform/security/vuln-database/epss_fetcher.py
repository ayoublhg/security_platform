#!/usr/bin/env python3
"""
EPSS (Exploit Prediction Scoring System) Fetcher
Downloads and processes EPSS scores from FIRST.org
"""

import aiohttp
import asyncio
import json
import sqlite3
import logging
import csv
import io
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import gzip

logger = logging.getLogger(__name__)

class EPSSFetcher:
    """Fetches and manages EPSS scores"""
    
    def __init__(self, db_path: str = "data/epss.sqlite"):
        self.db_path = db_path
        self.base_url = "https://api.first.org/data/v1/epss"
        self.init_database()
        
    def init_database(self):
        """Initialize database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL,
                percentile REAL,
                date DATE,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS epss_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                records_updated INTEGER,
                status TEXT
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_date ON epss_scores(date)")
        
        conn.commit()
        conn.close()
        
        logger.info("EPSS database initialized")
    
    async def fetch_recent(self, days: int = 7) -> int:
        """Fetch recent EPSS scores"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'date': (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
                }
                
                async with session.get(self.base_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return await self._process_batch(data)
                    else:
                        logger.error(f"EPSS API error: {resp.status}")
                        return 0
                        
        except Exception as e:
            logger.error(f"Failed to fetch EPSS: {e}")
            return 0
    
    async def fetch_bulk(self, days: int = 30) -> int:
        """Fetch bulk EPSS data (CSV download)"""
        try:
            # Download latest EPSS CSV
            csv_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(csv_url) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        
                        # Decompress gzip
                        with gzip.open(io.BytesIO(data), 'rt') as f:
                            reader = csv.reader(f)
                            
                            # Skip header
                            next(reader)
                            
                            count = 0
                            conn = sqlite3.connect(self.db_path)
                            cursor = conn.cursor()
                            
                            for row in reader:
                                if len(row) >= 3:
                                    cve_id = row[0].strip()
                                    epss = float(row[1]) if row[1] else 0.0
                                    percentile = float(row[2]) if row[2] else 0.0
                                    
                                    cursor.execute("""
                                        INSERT OR REPLACE INTO epss_scores
                                        (cve_id, epss_score, percentile, date)
                                        VALUES (?, ?, ?, ?)
                                    """, (cve_id, epss, percentile, datetime.now().date().isoformat()))
                                    
                                    count += 1
                                    
                                    if count % 10000 == 0:
                                        conn.commit()
                                        logger.info(f"Processed {count} EPSS records")
                            
                            conn.commit()
                            conn.close()
                            
                            # Record update
                            await self._record_update(count, 'success')
                            
                            logger.info(f"Loaded {count} EPSS scores")
                            return count
                    else:
                        logger.error(f"Failed to download EPSS CSV: {resp.status}")
                        return 0
                        
        except Exception as e:
            logger.error(f"Failed to fetch EPSS bulk: {e}")
            return 0
    
    async def _process_batch(self, data: Dict) -> int:
        """Process API batch response"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        for item in data.get('data', []):
            cve_id = item.get('cve')
            epss = float(item.get('epss', 0))
            percentile = float(item.get('percentile', 0))
            
            cursor.execute("""
                INSERT OR REPLACE INTO epss_scores
                (cve_id, epss_score, percentile, date)
                VALUES (?, ?, ?, ?)
            """, (cve_id, epss, percentile, datetime.now().date().isoformat()))
            
            count += 1
        
        conn.commit()
        conn.close()
        
        await self._record_update(count, 'success')
        return count
    
    async def _record_update(self, count: int, status: str):
        """Record update in history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO epss_updates (records_updated, status)
            VALUES (?, ?)
        """, (count, status))
        
        conn.commit()
        conn.close()
    
    async def get_score(self, cve_id: str) -> Optional[Dict]:
        """Get EPSS score for a CVE"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT epss_score, percentile, date
            FROM epss_scores
            WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'cve_id': cve_id,
                'epss_score': row[0],
                'percentile': row[1],
                'date': row[2]
            }
        return None
    
    async def get_scores_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Get EPSS scores for multiple CVEs"""
        if not cve_ids:
            return {}
        
        placeholders = ','.join(['?'] * len(cve_ids))
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(f"""
            SELECT cve_id, epss_score, percentile, date
            FROM epss_scores
            WHERE cve_id IN ({placeholders})
        """, cve_ids)
        
        results = {}
        for row in cursor.fetchall():
            results[row[0]] = {
                'epss_score': row[1],
                'percentile': row[2],
                'date': row[3]
            }
        
        conn.close()
        return results
    
    async def get_stats(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM epss_scores")
        total = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT 
                AVG(epss_score) as avg_score,
                MAX(epss_score) as max_score,
                MIN(epss_score) as min_score
            FROM epss_scores
        """)
        stats = cursor.fetchone()
        
        cursor.execute("""
            SELECT COUNT(*) FROM epss_updates
            WHERE update_date > datetime('now', '-7 days')
        """)
        recent_updates = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_scores': total,
            'avg_score': stats[0] if stats else 0,
            'max_score': stats[1] if stats else 0,
            'min_score': stats[2] if stats else 0,
            'recent_updates': recent_updates
        }