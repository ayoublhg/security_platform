#!/usr/bin/env python3
"""
Ransomware Vulnerability Tracker
Tracks CVEs associated with ransomware campaigns
"""

import aiohttp
import asyncio
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
import os

logger = logging.getLogger(__name__)

class RansomwareTracker:
    """Tracks CVEs used in ransomware attacks"""
    
    def __init__(self, db_path: str = "data/ransomware.sqlite"):
        self.db_path = db_path
        self.sources = [
            {
                'name': 'ransomware_db',
                'url': 'https://raw.githubusercontent.com/ransomwaretracker/ransomware-tracker/master/data/cves.json'
            },
            {
                'name': 'blacklotus',
                'url': 'https://raw.githubusercontent.com/blacklotus/ransomware-poc/main/cves.json'
            },
            {
                'name': 'sophos',
                'url': 'https://raw.githubusercontent.com/sophos/ransomware-poc/main/cves.json'
            }
        ]
        self.init_database()
        
    def init_database(self):
        """Initialize database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_cves (
                cve_id TEXT PRIMARY KEY,
                ransomware_family TEXT,
                source TEXT,
                first_seen DATE,
                last_seen DATE,
                description TEXT,
                reference_url TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_families (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                family_name TEXT UNIQUE,
                first_seen DATE,
                last_seen DATE,
                total_cves INTEGER,
                active BOOLEAN
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ransomware_family ON ransomware_cves(ransomware_family)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ransomware_first_seen ON ransomware_cves(first_seen)")
        
        conn.commit()
        conn.close()
        
        logger.info("Ransomware tracker database initialized")
    
    async def fetch_all(self) -> Dict[str, int]:
        """Fetch from all sources"""
        results = {}
        
        async with aiohttp.ClientSession() as session:
            for source in self.sources:
                try:
                    count = await self._fetch_source(session, source)
                    results[source['name']] = count
                    await asyncio.sleep(1)  # Rate limiting
                except Exception as e:
                    logger.error(f"Failed to fetch {source['name']}: {e}")
                    results[source['name']] = 0
        
        return results
    
    async def _fetch_source(self, session: aiohttp.ClientSession, source: Dict) -> int:
        """Fetch from a single source"""
        try:
            async with session.get(source['url']) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return await self._process_source(source['name'], data)
                else:
                    logger.warning(f"{source['name']} returned {resp.status}")
                    return 0
        except Exception as e:
            logger.error(f"Error fetching {source['name']}: {e}")
            return 0
    
    async def _process_source(self, source_name: str, data: Dict) -> int:
        """Process data from a source"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        families = set()
        
        # Handle different data formats
        if isinstance(data, dict):
            cves = data.get('cves', [])
            ransomware_family = data.get('family', 'unknown')
            
            for cve in cves:
                cursor.execute("""
                    INSERT OR REPLACE INTO ransomware_cves
                    (cve_id, ransomware_family, source, first_seen, last_seen)
                    VALUES (?, ?, ?, date('now'), date('now'))
                """, (cve, ransomware_family, source_name))
                
                families.add(ransomware_family)
                count += 1
                
        elif isinstance(data, list):
            for item in data:
                cve = item.get('cve') if isinstance(item, dict) else item
                family = item.get('family', 'unknown') if isinstance(item, dict) else 'unknown'
                
                cursor.execute("""
                    INSERT OR REPLACE INTO ransomware_cves
                    (cve_id, ransomware_family, source, first_seen, last_seen)
                    VALUES (?, ?, ?, date('now'), date('now'))
                """, (cve, family, source_name))
                
                families.add(family)
                count += 1
        
        # Update families
        for family in families:
            cursor.execute("""
                INSERT OR REPLACE INTO ransomware_families
                (family_name, first_seen, last_seen, total_cves, active)
                VALUES (?, date('now'), date('now'), 
                    (SELECT COUNT(*) FROM ransomware_cves WHERE ransomware_family = ?),
                    1)
            """, (family, family))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Processed {count} ransomware CVEs from {source_name}")
        return count
    
    async def is_ransomware_related(self, cve_id: str) -> bool:
        """Check if CVE is related to ransomware"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT ransomware_family FROM ransomware_cves WHERE cve_id = ?",
            (cve_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    async def get_ransomware_details(self, cve_id: str) -> Optional[Dict]:
        """Get ransomware details for a CVE"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM ransomware_cves WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'cve_id': row[0],
                'ransomware_family': row[1],
                'source': row[2],
                'first_seen': row[3],
                'last_seen': row[4]
            }
        return None
    
    async def get_family_stats(self, family: Optional[str] = None) -> Dict:
        """Get statistics by ransomware family"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if family:
            cursor.execute("""
                SELECT COUNT(*) FROM ransomware_cves
                WHERE ransomware_family = ?
            """, (family,))
            total = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT first_seen, last_seen FROM ransomware_families
                WHERE family_name = ?
            """, (family,))
            dates = cursor.fetchone()
            
            result = {
                'family': family,
                'total_cves': total,
                'first_seen': dates[0] if dates else None,
                'last_seen': dates[1] if dates else None
            }
        else:
            cursor.execute("""
                SELECT 
                    ransomware_family,
                    COUNT(*) as cve_count,
                    MIN(first_seen) as first_seen,
                    MAX(last_seen) as last_seen
                FROM ransomware_cves
                GROUP BY ransomware_family
                ORDER BY cve_count DESC
            """)
            
            result = {
                'families': []
            }
            for row in cursor.fetchall():
                result['families'].append({
                    'family': row[0],
                    'cve_count': row[1],
                    'first_seen': row[2],
                    'last_seen': row[3]
                })
        
        conn.close()
        return result
    
    async def get_stats(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM ransomware_cves")
        total_cves = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT ransomware_family) FROM ransomware_cves")
        total_families = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT ransomware_family, COUNT(*) as count
            FROM ransomware_cves
            GROUP BY ransomware_family
            ORDER BY count DESC
            LIMIT 5
        """)
        top_families = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_cves': total_cves,
            'total_families': total_families,
            'top_families': top_families
        }