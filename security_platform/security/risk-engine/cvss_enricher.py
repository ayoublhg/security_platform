#!/usr/bin/env python3
"""
CVSS Enricher - Adds detailed CVSS metrics to findings
"""

import logging
from typing import Dict, List, Optional, Any
import json

logger = logging.getLogger(__name__)

class CVSSEnricher:
    """Enriches findings with detailed CVSS information"""
    
    def __init__(self):
        self.severity_scores = {
            'none': 0.0,
            'low': 0.1 - 3.9,
            'medium': 4.0 - 6.9,
            'high': 7.0 - 8.9,
            'critical': 9.0 - 10.0
        }
        
    def enrich(self, finding: Dict, cvss_data: Optional[Dict] = None) -> Dict:
        """Enrich finding with CVSS data"""
        enriched = finding.copy()
        
        if 'metadata' not in enriched:
            enriched['metadata'] = {}
        
        if cvss_data:
            # Use provided CVSS data
            enriched['metadata']['cvss'] = cvss_data
            enriched['cvss_score'] = cvss_data.get('baseScore', 
                                                   enriched.get('cvss_score', 0))
            enriched['severity'] = cvss_data.get('baseSeverity', 
                                                 enriched.get('severity', 'unknown')).lower()
        else:
            # Try to extract from existing data
            cvss = self._extract_cvss(finding)
            if cvss:
                enriched['metadata']['cvss'] = cvss
                enriched['cvss_score'] = cvss.get('baseScore', 
                                                   enriched.get('cvss_score', 0))
        
        # Add vector breakdown
        vector = enriched.get('metadata', {}).get('cvss', {}).get('vectorString', '')
        if vector:
            enriched['metadata']['cvss_breakdown'] = self._parse_vector(vector)
        
        return enriched
    
    def _extract_cvss(self, finding: Dict) -> Optional[Dict]:
        """Extract CVSS data from finding metadata"""
        metadata = finding.get('metadata', {})
        
        # Check different possible locations
        if 'cvss' in metadata:
            return metadata['cvss']
        
        if 'cvss_score' in finding:
            # Construct basic CVSS from score
            score = finding['cvss_score']
            return {
                'baseScore': score,
                'baseSeverity': self._score_to_severity(score)
            }
        
        return None
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def _parse_vector(self, vector: str) -> Dict:
        """Parse CVSS vector string into components"""
        if not vector or not vector.startswith('CVSS:'):
            return {}
        
        components = {}
        parts = vector.split('/')
        
        for part in parts[1:]:  # Skip CVSS:3.1/ prefix
            if ':' in part:
                key, value = part.split(':', 1)
                components[key] = value
        
        return {
            'attack_vector': components.get('AV', ''),
            'attack_complexity': components.get('AC', ''),
            'privileges_required': components.get('PR', ''),
            'user_interaction': components.get('UI', ''),
            'scope': components.get('S', ''),
            'confidentiality': components.get('C', ''),
            'integrity': components.get('I', ''),
            'availability': components.get('A', '')
        }
    
    def calculate_temporal_score(self, finding: Dict) -> float:
        """Calculate temporal score considering exploit maturity"""
        base_score = finding.get('cvss_score', 0)
        
        # Adjust based on exploit availability
        exploit_available = finding.get('metadata', {}).get('exploit_available', False)
        if exploit_available:
            base_score *= 1.2
        
        # Adjust based on patch availability
        patch_available = finding.get('metadata', {}).get('patch_available', False)
        if not patch_available:
            base_score *= 1.1
        
        return min(base_score, 10.0)
    
    def calculate_environmental_score(self, finding: Dict, 
                                      asset_criticality: str = 'medium') -> float:
        """Calculate environmental score based on asset context"""
        base_score = finding.get('cvss_score', 0)
        
        # Adjust based on asset criticality
        criticality_multipliers = {
            'critical': 1.5,
            'high': 1.3,
            'medium': 1.0,
            'low': 0.7
        }
        
        multiplier = criticality_multipliers.get(asset_criticality, 1.0)
        return min(base_score * multiplier, 10.0)
    
    def get_risk_vector(self, finding: Dict) -> Dict:
        """Get risk vector analysis"""
        cvss = finding.get('metadata', {}).get('cvss', {})
        breakdown = self._parse_vector(cvss.get('vectorString', ''))
        
        return {
            'exploitability': self._calculate_exploitability(breakdown),
            'impact': self._calculate_impact(breakdown),
            'scope_changed': breakdown.get('scope') == 'C',
            'requires_privileges': breakdown.get('privileges_required') not in ['N', 'NONE'],
            'requires_interaction': breakdown.get('user_interaction') == 'R'
        }
    
    def _calculate_exploitability(self, breakdown: Dict) -> float:
        """Calculate exploitability sub-score"""
        score = 8.22  # Base
        
        av = breakdown.get('attack_vector', '')
        if av == 'N':
            score *= 1.0
        elif av == 'A':
            score *= 0.85
        elif av == 'L':
            score *= 0.55
        elif av == 'P':
            score *= 0.2
        
        ac = breakdown.get('attack_complexity', '')
        if ac == 'L':
            score *= 1.0
        elif ac == 'H':
            score *= 0.44
        
        pr = breakdown.get('privileges_required', '')
        if pr == 'N':
            score *= 1.0
        elif pr == 'L':
            score *= 0.62
        elif pr == 'H':
            score *= 0.27
        
        ui = breakdown.get('user_interaction', '')
        if ui == 'N':
            score *= 1.0
        elif ui == 'R':
            score *= 0.62
        
        return round(score, 1)
    
    def _calculate_impact(self, breakdown: Dict) -> float:
        """Calculate impact sub-score"""
        # Simplified impact calculation
        conf = breakdown.get('confidentiality', '')
        integ = breakdown.get('integrity', '')
        avail = breakdown.get('availability', '')
        
        def impact_value(metric: str) -> float:
            if metric == 'H':
                return 0.56
            elif metric == 'L':
                return 0.22
            else:
                return 0
        
        iss = 1 - ((1 - impact_value(conf)) * 
                   (1 - impact_value(integ)) * 
                   (1 - impact_value(avail)))
        
        scope = breakdown.get('scope', '')
        if scope == 'C':
            return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            return 6.42 * iss