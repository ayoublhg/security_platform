#!/usr/bin/env python3
"""
Priority Calculator for Vulnerability Remediation
Calculates risk scores based on multiple factors
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class PriorityCalculator:
    """Calculates remediation priority based on multiple risk factors"""
    
    def __init__(self):
        self.weights = {
            'cvss': 3.0,
            'epss': 4.0,
            'exploit_available': 5.0,
            'cisa_kev': 6.0,
            'ransomware': 7.0,
            'age': 2.0,
            'reachable': 3.0,
            'public_facing': 4.0,
            'critical_asset': 5.0
        }
        
        self.severity_map = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0,
            'info': 0.0
        }
    
    def calculate_priority(self, finding: Dict, context: Optional[Dict] = None) -> Dict:
        """
        Calculate priority score for a finding
        Returns score and priority level
        """
        context = context or {}
        score = 0.0
        factors = []
        
        # 1. CVSS Score
        cvss = finding.get('metadata', {}).get('cvss_score', finding.get('cvss_score', 0))
        if cvss:
            score += cvss * self.weights['cvss']
            factors.append({
                'factor': 'cvss',
                'value': cvss,
                'contribution': cvss * self.weights['cvss']
            })
        else:
            # Use severity as fallback
            severity = finding.get('severity', 'medium').lower()
            severity_score = self.severity_map.get(severity, 5.0)
            score += severity_score * self.weights['cvss'] / 2
            factors.append({
                'factor': 'severity',
                'value': severity,
                'contribution': severity_score * self.weights['cvss'] / 2
            })
        
        # 2. EPSS Score
        epss = finding.get('metadata', {}).get('epss_score', 0)
        if epss:
            score += epss * 10 * self.weights['epss']
            factors.append({
                'factor': 'epss',
                'value': epss,
                'contribution': epss * 10 * self.weights['epss']
            })
        
        # 3. Exploit Available
        exploit_available = finding.get('metadata', {}).get('exploit_available', False)
        if exploit_available:
            score += self.weights['exploit_available'] * 10
            factors.append({
                'factor': 'exploit_available',
                'value': True,
                'contribution': self.weights['exploit_available'] * 10
            })
        
        # 4. CISA KEV
        cisa_kev = finding.get('metadata', {}).get('cisa_kev', False)
        if cisa_kev:
            score += self.weights['cisa_kev'] * 10
            factors.append({
                'factor': 'cisa_kev',
                'value': True,
                'contribution': self.weights['cisa_kev'] * 10
            })
        
        # 5. Ransomware Association
        ransomware = finding.get('metadata', {}).get('ransomware_associated', False)
        if ransomware:
            score += self.weights['ransomware'] * 10
            factors.append({
                'factor': 'ransomware',
                'value': True,
                'contribution': self.weights['ransomware'] * 10
            })
        
        # 6. Age of finding
        found_at = finding.get('found_at')
        if found_at:
            if isinstance(found_at, str):
                found_at = datetime.fromisoformat(found_at.replace('Z', '+00:00'))
            days_old = (datetime.now() - found_at).days
            age_score = min(days_old * 0.5, 10)  # Max 10 points
            score += age_score * self.weights['age']
            factors.append({
                'factor': 'age',
                'value': days_old,
                'contribution': age_score * self.weights['age']
            })
        
        # 7. Context factors (from tenant/asset info)
        if context:
            # Asset criticality
            if context.get('critical_asset'):
                score += self.weights['critical_asset'] * 10
                factors.append({
                    'factor': 'critical_asset',
                    'value': True,
                    'contribution': self.weights['critical_asset'] * 10
                })
            
            # Public facing
            if context.get('public_facing'):
                score += self.weights['public_facing'] * 8
                factors.append({
                    'factor': 'public_facing',
                    'value': True,
                    'contribution': self.weights['public_facing'] * 8
                })
        
        # Determine priority level
        priority_level = self._get_priority_level(score)
        
        # Calculate SLA
        sla = self._calculate_sla(score, priority_level)
        
        return {
            'score': round(score, 2),
            'priority': priority_level,
            'sla_hours': sla,
            'factors': factors,
            'breakdown': {
                'total': round(score, 2),
                'by_factor': {f['factor']: round(f['contribution'], 2) for f in factors}
            }
        }
    
    def _get_priority_level(self, score: float) -> str:
        """Convert score to priority level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'info'
    
    def _calculate_sla(self, score: float, priority: str) -> int:
        """Calculate SLA in hours based on priority"""
        slas = {
            'critical': 24,
            'high': 72,
            'medium': 168,  # 1 week
            'low': 720,      # 30 days
            'info': 2160     # 90 days
        }
        return slas.get(priority, 168)
    
    def batch_calculate(self, findings: List[Dict], contexts: Optional[Dict] = None) -> List[Dict]:
        """Calculate priority for multiple findings"""
        results = []
        contexts = contexts or {}
        
        for finding in findings:
            finding_id = finding.get('finding_id', finding.get('id'))
            context = contexts.get(finding_id, {})
            
            priority = self.calculate_priority(finding, context)
            results.append({
                'finding_id': finding_id,
                'priority': priority
            })
        
        return results
    
    def get_remediation_order(self, findings: List[Dict]) -> List[Dict]:
        """Get findings ordered by priority"""
        prioritized = self.batch_calculate(findings)
        sorted_findings = sorted(
            prioritized,
            key=lambda x: x['priority']['score'],
            reverse=True
        )
        return sorted_findings