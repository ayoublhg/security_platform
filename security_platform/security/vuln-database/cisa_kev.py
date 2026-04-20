#!/usr/bin/env python3
"""
CISA Known Exploited Vulnerabilities (KEV) Catalog
Fetches and manages the CISA KEV list
"""

import aiohttp
import asyncio
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import os

logger = logging.getLogger(__name__)

class CISACatalog:
    """CISA Known Exploited Vulnerabilities catalog"""
    
    def __init__(self, db_path: str = "data/cisa_kev.sqlite"):
        self.db_path = db_path
        self.catalog_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.init_database()
        
    def init_database(self):
        """Initialize database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kev_catalog (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added DATE,
                short_description TEXT,
                required_action TEXT,
                due_date DATE,
                notes TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kev_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                records_added INTEGER,
                records_updated INTEGER,
                status TEXT
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kev_due_date ON kev_catalog(due_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_catalog(date_added)")
        
        conn.commit()
        conn.close()
        
        logger.info("CISA KEV database initialized")
    
    async def fetch_catalog(self) -> int:
        """Fetch the latest CISA KEV catalog"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.catalog_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return await self._process_catalog(data)
                    else:
                        logger.error(f"CISA KEV fetch failed: {resp.status}")
                        return 0
                        
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
            return 0
    
    async def _process_catalog(self, data: Dict) -> int:
        """Process catalog JSON data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        added = 0
        updated = 0
        
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID', '')
            
            # Check if exists
            cursor.execute(
                "SELECT 1 FROM kev_catalog WHERE cve_id = ?",
                (cve_id,)
            )
            exists = cursor.fetchone()
            
            cursor.execute("""
                INSERT OR REPLACE INTO kev_catalog (
                    cve_id, vendor_project, product, vulnerability_name,
                    date_added, short_description, required_action,
                    due_date, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                vuln.get('vendorProject', ''),
                vuln.get('product', ''),
                vuln.get('vulnerabilityName', ''),
                vuln.get('dateAdded', ''),
                vuln.get('shortDescription', ''),
                vuln.get('requiredAction', ''),
                vuln.get('dueDate', ''),
                vuln.get('notes', '')
            ))
            
            if exists:
                updated += 1
            else:
                added += 1
        
        conn.commit()
        conn.close()
        
        # Record update
        await self._record_update(added, updated, 'success')
        
        logger.info(f"CISA KEV processed: {added} new, {updated} updated")
        return added + updated
    
    async def _record_update(self, added: int, updated: int, status: str):
        """Record update in history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO kev_updates (records_added, records_updated, status)
            VALUES (?, ?, ?)
        """, (added, updated, status))
        
        conn.commit()
        conn.close()
    
    async def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT 1 FROM kev_catalog WHERE cve_id = ?",
            (cve_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    async def get_kev_details(self, cve_id: str) -> Optional[Dict]:
        """Get KEV details for a CVE"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM kev_catalog WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'cve_id': row[0],
                'vendor_project': row[1],
                'product': row[2],
                'vulnerability_name': row[3],
                'date_added': row[4],
                'short_description': row[5],
                'required_action': row[6],
                'due_date': row[7],
                'notes': row[8]
            }
        return None
    
    async def get_due_soon(self, days: int = 30) -> List[Dict]:
        """Get KEVs due within specified days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = (datetime.now() + timedelta(days=days)).date().isoformat()
        
        cursor.execute("""
            SELECT * FROM kev_catalog 
            WHERE due_date <= ? AND due_date >= date('now')
            ORDER BY due_date ASC
        """, (cutoff,))
        
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            results.append({
                'cve_id': row[0],
                'vendor_project': row[1],
                'product': row[2],
                'vulnerability_name': row[3],
                'date_added': row[4],
                'short_description': row[5],
                'required_action': row[6],
                'due_date': row[7],
                'notes': row[8]
            })
        
        return results
    
    async def get_stats(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM kev_catalog")
        total = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM kev_catalog 
            WHERE due_date < date('now')
        """)
        overdue = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM kev_catalog 
            WHERE date_added > date('now', '-30 days')
        """)
        recent = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_kev': total,
            'overdue': overdue,
            'added_last_30_days': recent
        }