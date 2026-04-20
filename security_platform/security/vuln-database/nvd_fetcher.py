#!/usr/bin/env python3
"""
NVD (National Vulnerability Database) Fetcher
Downloads and parses CVE data from NVD
"""

import aiohttp
import asyncio
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
import gzip
import io

logger = logging.getLogger(__name__)

class NVDFetcher:
    """Fetches and processes NVD CVE data"""
    
    def __init__(self, db_path: str = "data/vuln_db.sqlite"):
        self.db_path = db_path
        self.api_key = os.getenv('NVD_API_KEY', '')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.init_database()
        
    def init_database(self):
        """Initialize database tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # CVEs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                data JSON,
                cvss_score REAL,
                severity TEXT,
                published_date TIMESTAMP,
                last_modified TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # CPEs table (affected products)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                cpe_string TEXT,
                product TEXT,
                vendor TEXT,
                version TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
            )
        """)
        
        # CWEs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cwes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                cwe_id TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
            )
        """)
        
        # References table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                url TEXT,
                source TEXT,
                tags TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
            )
        """)
        
        # Update history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                records_added INTEGER,
                records_updated INTEGER,
                status TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpes_product ON cpes(product)")
        
        conn.commit()
        conn.close()
        
        logger.info("NVD database initialized")
    
    async def fetch_recent(self, days: int = 7) -> int:
        """Fetch CVEs from last N days"""
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        return await self._fetch_batch(start_date=start_date)
    
    async def fetch_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch a specific CVE by ID"""
        params = {'cveId': cve_id}
        if self.api_key:
            params['apiKey'] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('vulnerabilities'):
                            return self._parse_cve(data['vulnerabilities'][0]['cve'])
                    elif resp.status == 403:
                        logger.error("NVD API key invalid or rate limited")
                    else:
                        logger.warning(f"NVD returned status {resp.status}")
            return None
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {e}")
            return None
    
    async def _fetch_batch(self, start_date: Optional[str] = None, 
                          start_index: int = 0) -> int:
        """Fetch a batch of CVEs"""
        params = {
            'startIndex': start_index,
            'resultsPerPage': 2000
        }
        
        if start_date:
            params['lastModStartDate'] = start_date
        
        if self.api_key:
            params['apiKey'] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        total = data.get('totalResults', 0)
                        results = data.get('vulnerabilities', [])
                        
                        # Process batch
                        added = 0
                        updated = 0
                        
                        for item in results:
                            cve_data = self._parse_cve(item['cve'])
                            if await self._save_cve(cve_data):
                                updated += 1
                            else:
                                added += 1
                        
                        # Record update
                        await self._record_update(added, updated, 'success')
                        
                        logger.info(f"Fetched {len(results)} CVEs (total: {total})")
                        
                        # Recursively fetch next batch
                        if start_index + len(results) < total:
                            await asyncio.sleep(6)  # Rate limiting
                            await self._fetch_batch(start_date, start_index + 2000)
                        
                        return len(results)
                    else:
                        logger.error(f"Failed to fetch NVD data: {resp.status}")
                        return 0
                        
        except Exception as e:
            logger.error(f"Error fetching NVD batch: {e}")
            await self._record_update(0, 0, f"failed: {e}")
            return 0
    
    def _parse_cve(self, cve: Dict) -> Dict:
        """Parse CVE JSON into structured format"""
        cve_id = cve.get('id', '')
        
        # Get metrics
        metrics = cve.get('metrics', {})
        cvss_data = None
        
        # Try CVSS v3.1 first
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0]
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0]
        
        cvss_score = 0.0
        severity = 'UNKNOWN'
        
        if cvss_data:
            cvss = cvss_data.get('cvssData', {})
            cvss_score = cvss.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
        
        # Get descriptions
        descriptions = cve.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d['lang'] == 'en'),
            descriptions[0]['value'] if descriptions else ''
        )
        
        # Get references
        references = []
        for ref in cve.get('references', []):
            references.append({
                'url': ref.get('url'),
                'source': ref.get('source'),
                'tags': ref.get('tags', [])
            })
        
        # Get CWEs
        cwes = []
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwes.append(desc['value'])
        
        # Get configurations (affected products)
        products = []
        configs = cve.get('configurations', [])
        for config in configs:
            for node in config.get('nodes', []):
                for cpe in node.get('cpeMatch', []):
                    if 'criteria' in cpe:
                        products.append(cpe['criteria'])
        
        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'published': cve.get('published'),
            'modified': cve.get('lastModified'),
            'products': list(set(products)),
            'references': references,
            'cwes': list(set(cwes)),
            'raw_data': cve
        }
    
    async def _save_cve(self, cve_data: Dict) -> bool:
        """Save CVE to database, returns True if updated, False if new"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if exists
        cursor.execute(
            "SELECT last_modified FROM cves WHERE cve_id = ?",
            (cve_data['cve_id'],)
        )
        existing = cursor.fetchone()
        
        # Save main CVE record
        cursor.execute("""
            INSERT OR REPLACE INTO cves 
            (cve_id, data, cvss_score, severity, published_date, last_modified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cve_data['cve_id'],
            json.dumps(cve_data),
            cve_data['cvss_score'],
            cve_data['severity'],
            cve_data['published'],
            cve_data['modified']
        ))
        
        # Save CPEs
        for cpe in cve_data['products']:
            cursor.execute("""
                INSERT INTO cpes (cve_id, cpe_string, product, vendor, version)
                VALUES (?, ?, ?, ?, ?)
            """, (cve_data['cve_id'], cpe, '', '', ''))
        
        # Save CWEs
        for cwe in cve_data['cwes']:
            cursor.execute("""
                INSERT INTO cwes (cve_id, cwe_id)
                VALUES (?, ?)
            """, (cve_data['cve_id'], cwe))
        
        conn.commit()
        conn.close()
        
        return existing is not None
    
    async def _record_update(self, added: int, updated: int, status: str):
        """Record update in history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO updates (records_added, records_updated, status)
            VALUES (?, ?, ?)
        """, (added, updated, status))
        
        conn.commit()
        conn.close()
    
    async def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get CVE from local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT data FROM cves WHERE cve_id = ?",
            (cve_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return json.loads(row[0])
        return None
    
    async def search_cves(self, **kwargs) -> List[Dict]:
        """Search CVEs by various criteria"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT data FROM cves WHERE 1=1"
        params = []
        
        if 'severity' in kwargs:
            query += " AND severity = ?"
            params.append(kwargs['severity'].upper())
        
        if 'product' in kwargs:
            query += " AND EXISTS (SELECT 1 FROM cpes WHERE cve_id = cves.cve_id AND product LIKE ?)"
            params.append(f"%{kwargs['product']}%")
        
        if 'cwe' in kwargs:
            query += " AND EXISTS (SELECT 1 FROM cwes WHERE cve_id = cves.cve_id AND cwe_id = ?)"
            params.append(kwargs['cwe'])
        
        if 'days' in kwargs:
            days_ago = (datetime.utcnow() - timedelta(days=kwargs['days'])).isoformat()
            query += " AND published_date >= ?"
            params.append(days_ago)
        
        query += " ORDER BY published_date DESC LIMIT ?"
        params.append(kwargs.get('limit', 100))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [json.loads(row[0]) for row in rows]
    
    async def get_stats(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cves")
        total = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM cves 
            GROUP BY severity
        """)
        by_severity = dict(cursor.fetchall())
        
        cursor.execute("""
            SELECT status, COUNT(*) 
            FROM updates 
            GROUP BY status
        """)
        updates = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_cves': total,
            'by_severity': by_severity,
            'updates': updates
        }