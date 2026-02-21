#!/usr/bin/env python3
"""
Enterprise Vulnerability Database with Enrichment from Multiple Sources
"""

import aiohttp
import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import logging
from dataclasses import dataclass, asdict
import requests
from bs4 import BeautifulSoup
import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EnrichedVulnerability:
    """Enhanced vulnerability data model"""
    # Core fields
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    
    # Enrichment fields
    epss_score: float  # Exploit prediction score
    exploit_available: bool
    exploit_type: Optional[str]  # metasploit, exploit-db, etc.
    ransomware_associated: bool
    cisa_kev: bool  # CISA Known Exploited Vulnerabilities
    patch_available: bool
    
    # Context
    affected_products: List[str]
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: bool
    
    # References
    references: List[str]
    cwe_ids: List[str]
    
    # Timestamps
    published_date: datetime
    last_modified: datetime
    
    def to_dict(self):
        data = asdict(self)
        data['published_date'] = self.published_date.isoformat()
        data['last_modified'] = self.last_modified.isoformat()
        return data

class EnrichedVulnerabilityDatabase:
    """Advanced vulnerability database with multiple enrichment sources"""
    
    def __init__(self):
        self.sources = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'exploit_db': 'https://www.exploit-db.com',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'epss': 'https://api.first.org/data/v1/epss',
            'metasploit': 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'
        }
        
        self.cache = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.db_path = 'vulnerability_db.sqlite'
        self.init_database()
        
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enrichment_sources (
                source_name TEXT PRIMARY KEY,
                last_fetched TIMESTAMP,
                data_hash TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(
                json_extract(data, '$.severity')
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def enrich_vulnerability(self, cve_id: str) -> EnrichedVulnerability:
        """Enrich a single vulnerability with data from all sources"""
        
        # Check cache first
        cached = self.cache.get(f"vuln:{cve_id}")
        if cached:
            return EnrichedVulnerability(**json.loads(cached))
        
        # Fetch from all sources in parallel
        tasks = [
            self.fetch_nvd(cve_id),
            self.fetch_epss(cve_id),
            self.check_exploit_db(cve_id),
            self.check_cisa_kev(cve_id),
            self.check_ransomware(cve_id)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Parse results
        nvd_data = results[0] if not isinstance(results[0], Exception) else {}
        epss_data = results[1] if not isinstance(results[1], Exception) else {}
        exploit_data = results[2] if not isinstance(results[2], Exception) else {}
        cisa_data = results[3] if not isinstance(results[3], Exception) else {}
        ransomware_data = results[4] if not isinstance(results[4], Exception) else {}
        
        # Create enriched vulnerability
        enriched = EnrichedVulnerability(
            cve_id=cve_id,
            cvss_score=nvd_data.get('cvss', 0.0),
            severity=nvd_data.get('severity', 'UNKNOWN'),
            description=nvd_data.get('description', ''),
            epss_score=epss_data.get('epss', 0.0),
            exploit_available=exploit_data.get('available', False),
            exploit_type=exploit_data.get('type'),
            ransomware_associated=ransomware_data.get('associated', False),
            cisa_kev=cisa_data.get('kev', False),
            patch_available=nvd_data.get('patch_available', False),
            affected_products=nvd_data.get('products', []),
            attack_vector=nvd_data.get('attack_vector', 'NETWORK'),
            attack_complexity=nvd_data.get('attack_complexity', 'LOW'),
            privileges_required=nvd_data.get('privileges_required', 'NONE'),
            user_interaction=nvd_data.get('user_interaction', False),
            references=nvd_data.get('references', []),
            cwe_ids=nvd_data.get('cwe', []),
            published_date=datetime.fromisoformat(nvd_data.get('published', datetime.now().isoformat())),
            last_modified=datetime.fromisoformat(nvd_data.get('modified', datetime.now().isoformat()))
        )
        
        # Cache for 1 hour
        self.cache.setex(
            f"vuln:{cve_id}",
            3600,
            json.dumps(enriched.to_dict())
        )
        
        # Store in database
        self.store_vulnerability(enriched)
        
        return enriched
    
    async def fetch_nvd(self, cve_id: str) -> Dict:
        """Fetch data from NVD"""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.sources['nvd']}?cveId={cve_id}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self.parse_nvd_response(data)
        return {}
    
    async def fetch_epss(self, cve_id: str) -> Dict:
        """Fetch EPSS (Exploit Prediction Scoring System) score"""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.sources['epss']}?cve={cve_id}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self.parse_epss_response(data)
        return {}
    
    async def check_exploit_db(self, cve_id: str) -> Dict:
        """Check if exploit exists in Exploit-DB"""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://www.exploit-db.com/search?cve={cve_id}"
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    return self.parse_exploit_db_response(text, cve_id)
        return {}
    
    async def check_cisa_kev(self, cve_id: str) -> Dict:
        """Check CISA Known Exploited Vulnerabilities catalog"""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.sources['cisa_kev']) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self.parse_cisa_response(data, cve_id)
        return {}
    
    async def check_ransomware(self, cve_id: str) -> Dict:
        """Check if vulnerability is associated with ransomware"""
        # Query multiple threat intel sources
        ransomware_feeds = [
            "https://raw.githubusercontent.com/sophos/ransomware-poc/main/cves.json",
            "https://raw.githubusercontent.com/blacklotus/ransomware-tracker/main/cves.json"
        ]
        
        async with aiohttp.ClientSession() as session:
            for feed in ransomware_feeds:
                try:
                    async with session.get(feed) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if cve_id in data.get('cves', []):
                                return {"associated": True, "family": data.get('family', 'unknown')}
                except:
                    continue
        
        return {"associated": False}
    
    def parse_nvd_response(self, data: Dict) -> Dict:
        """Parse NVD JSON response"""
        try:
            vuln = data['vulnerabilities'][0]['cve']
            
            metrics = vuln.get('metrics', {})
            cvss_data = (metrics.get('cvssMetricV31') or 
                        metrics.get('cvssMetricV30') or 
                        metrics.get('cvssMetricV2', [{}]))[0]
            
            cvss = cvss_data.get('cvssData', {})
            
            return {
                'cvss': cvss.get('baseScore', 0),
                'severity': cvss_data.get('baseSeverity', 'UNKNOWN'),
                'description': vuln.get('descriptions', [{}])[0].get('value', ''),
                'published': vuln.get('published'),
                'modified': vuln.get('lastModified'),
                'attack_vector': cvss.get('attackVector', 'NETWORK'),
                'attack_complexity': cvss.get('attackComplexity', 'LOW'),
                'privileges_required': cvss.get('privilegesRequired', 'NONE'),
                'user_interaction': cvss.get('userInteraction', 'NONE') == 'REQUIRED',
                'products': self.extract_products(vuln),
                'references': [ref.get('url') for ref in vuln.get('references', [])],
                'cwe': self.extract_cwe(vuln)
            }
        except Exception as e:
            logger.error(f"Error parsing NVD response: {e}")
            return {}
    
    def extract_products(self, vuln: Dict) -> List[str]:
        """Extract affected products from NVD data"""
        products = []
        for node in vuln.get('configurations', []):
            for cpe in node.get('cpeMatch', []):
                if 'criteria' in cpe:
                    parts = cpe['criteria'].split(':')
                    if len(parts) > 4:
                        products.append(f"{parts[4]}:{parts[5]}")
        return list(set(products))
    
    def extract_cwe(self, vuln: Dict) -> List[str]:
        """Extract CWE IDs"""
        cwes = []
        for problem in vuln.get('weaknesses', []):
            for desc in problem.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwes.append(desc['value'])
        return cwes
    
    def parse_epss_response(self, data: Dict) -> Dict:
        """Parse EPSS API response"""
        try:
            if data.get('data'):
                return {
                    'epss': float(data['data'][0].get('epss', 0)),
                    'percentile': float(data['data'][0].get('percentile', 0))
                }
        except:
            pass
        return {}
    
    def parse_exploit_db_response(self, html: str, cve_id: str) -> Dict:
        """Parse Exploit-DB search results"""
        soup = BeautifulSoup(html, 'html.parser')
        results = soup.find_all('tr')
        
        for result in results:
            if cve_id in result.text:
                return {
                    'available': True,
                    'type': 'exploit-db',
                    'url': result.find('a')['href'] if result.find('a') else None
                }
        
        return {'available': False}
    
    def parse_cisa_response(self, data: Dict, cve_id: str) -> Dict:
        """Parse CISA KEV catalog"""
        for vuln in data.get('vulnerabilities', []):
            if vuln.get('cveID') == cve_id:
                return {
                    'kev': True,
                    'due_date': vuln.get('dueDate'),
                    'action': vuln.get('requiredAction'),
                    'notes': vuln.get('notes')
                }
        return {'kev': False}
    
    def store_vulnerability(self, vuln: EnrichedVulnerability):
        """Store vulnerability in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vulnerabilities 
            (cve_id, data, epss_score, exploit_available, cisa_kev, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            vuln.cve_id,
            json.dumps(vuln.to_dict()),
            vuln.epss_score,
            vuln.exploit_available,
            vuln.cisa_kev,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def batch_enrich(self, cve_ids: List[str]) -> List[EnrichedVulnerability]:
        """Enrich multiple CVEs in parallel"""
        tasks = [self.enrich_vulnerability(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if not isinstance(r, Exception)]
    
    def get_priority_score(self, vuln: EnrichedVulnerability) -> float:
        """Calculate priority score for remediation"""
        score = 0.0
        
        # Base CVSS score (0-10)
        score += vuln.cvss_score
        
        # EPSS score (0-1, weighted)
        score += vuln.epss_score * 10
        
        # Exploit availability bonus
        if vuln.exploit_available:
            score += 3.0
        
        # CISA KEV bonus
        if vuln.cisa_kev:
            score += 5.0
        
        # Ransomware association bonus
        if vuln.ransomware_associated:
            score += 4.0
        
        # Attack vector impact
        if vuln.attack_vector == 'NETWORK':
            score += 2.0
        
        # Complexity impact
        if vuln.attack_complexity == 'LOW':
            score += 1.0
        
        return min(score, 20.0)  # Cap at 20
    
    def get_remediation_priority(self, vuln: EnrichedVulnerability) -> str:
        """Get remediation priority based on score"""
        score = self.get_priority_score(vuln)
        
        if score >= 15:
            return "CRITICAL - Remediate within 24 hours"
        elif score >= 10:
            return "HIGH - Remediate within 72 hours"
        elif score >= 5:
            return "MEDIUM - Remediate within 1 week"
        else:
            return "LOW - Remediate within 30 days"

# Initialize global database
vuln_db = EnrichedVulnerabilityDatabase()