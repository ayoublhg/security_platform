#!/usr/bin/env python3
"""
HIPAA Compliance Mapper
Maps security findings to HIPAA Security Rule standards
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class HIPAAMapper:
    """Maps findings to HIPAA Security Rule"""
    
    def __init__(self):
        self.standards = {
            '164.308': {
                'name': 'Administrative Safeguards',
                'sections': {
                    'a1': 'Security Management Process',
                    'a2': 'Assigned Security Responsibility',
                    'a3': 'Workforce Security',
                    'a4': 'Information Access Management',
                    'a5': 'Security Awareness and Training',
                    'a6': 'Security Incident Procedures',
                    'a7': 'Contingency Plan',
                    'a8': 'Evaluation'
                },
                'keywords': {
                    'risk': ['a1'],
                    'assessment': ['a1'],
                    'responsibility': ['a2'],
                    'workforce': ['a3'],
                    'access': ['a4'],
                    'training': ['a5'],
                    'awareness': ['a5'],
                    'incident': ['a6'],
                    'contingency': ['a7'],
                    'backup': ['a7'],
                    'disaster': ['a7'],
                    'evaluation': ['a8']
                }
            },
            '164.310': {
                'name': 'Physical Safeguards',
                'sections': {
                    'b1': 'Facility Access Controls',
                    'b2': 'Workstation Use',
                    'b3': 'Workstation Security',
                    'b4': 'Device and Media Controls'
                },
                'keywords': {
                    'facility': ['b1'],
                    'physical': ['b1'],
                    'workstation': ['b2', 'b3'],
                    'device': ['b4'],
                    'media': ['b4']
                }
            },
            '164.312': {
                'name': 'Technical Safeguards',
                'sections': {
                    'c1': 'Access Control',
                    'c2': 'Audit Controls',
                    'c3': 'Integrity',
                    'c4': 'Person or Entity Authentication',
                    'c5': 'Transmission Security'
                },
                'keywords': {
                    'access': ['c1'],
                    'authentication': ['c4'],
                    'password': ['c4'],
                    'audit': ['c2'],
                    'log': ['c2'],
                    'integrity': ['c3'],
                    'encryption': ['c5'],
                    'tls': ['c5'],
                    'ssl': ['c5']
                }
            },
            '164.314': {
                'name': 'Organizational Requirements',
                'sections': {
                    'd1': 'Business Associate Contracts',
                    'd2': 'Requirements for Group Health Plans'
                },
                'keywords': {
                    'baa': ['d1'],
                    'business': ['d1'],
                    'associate': ['d1'],
                    'contract': ['d1']
                }
            },
            '164.316': {
                'name': 'Policies and Procedures',
                'sections': {
                    'e1': 'Policies and Procedures',
                    'e2': 'Documentation'
                },
                'keywords': {
                    'policy': ['e1', 'e2'],
                    'procedure': ['e1', 'e2'],
                    'documentation': ['e2']
                }
            }
        }
        
    def map_finding(self, finding: Dict) -> Dict:
        """Map a finding to HIPAA standards"""
        finding_type = finding.get('type', '').lower()
        finding_title = finding.get('title', '').lower()
        finding_description = finding.get('description', '').lower()
        scanner = finding.get('scanner', '').lower()
        severity = finding.get('severity', 'medium').lower()
        
        combined_text = f"{finding_type} {finding_title} {finding_description} {scanner}"
        
        affected_standards = {}
        
        # Find matching standards and sections
        for std_id, std_info in self.standards.items():
            matched_sections = set()
            
            for keyword, sections in std_info.get('keywords', {}).items():
                if keyword in combined_text:
                    matched_sections.update(sections)
            
            if matched_sections:
                affected_standards[std_id] = {
                    'name': std_info['name'],
                    'sections': [f"{std_id}.{s}" for s in sorted(matched_sections)]
                }
        
        # Check for PHI indicators
        phi_indicators = ['patient', 'health', 'medical', 'phi', 'ehr', 'emr']
        phi_related = any(ind in combined_text for ind in phi_indicators)
        
        # Determine HIPAA impact
        hipaa_impact = self._determine_hipaa_impact(severity, phi_related)
        
        # Generate evidence
        evidence = self._generate_evidence(finding)
        
        return {
            'framework': 'HIPAA',
            'standards': affected_standards,
            'phi_related': phi_related,
            'impact': hipaa_impact,
            'evidence': evidence,
            'remediation_guidance': self._get_remediation_guidance(affected_standards, severity),
            'mapped_at': datetime.utcnow().isoformat()
        }
    
    def _determine_hipaa_impact(self, severity: str, phi_related: bool) -> str:
        """Determine HIPAA compliance impact"""
        phi_note = " Involves PHI." if phi_related else ""
        
        impacts = {
            'critical': f"High HIPAA impact. Immediate action required.{phi_note} "
                       f"Potential breach notification required.",
            'high': f"Moderate HIPAA impact. Address within 72 hours.{phi_note} "
                   f"Security incident procedures should be followed.",
            'medium': f"Low HIPAA impact. Address within 2 weeks.{phi_note} "
                     f"Security measure enhancement needed.",
            'low': f"Informational. Address within 30 days.{phi_note} "
                  f"Minor improvement suggested."
        }
        
        return impacts.get(severity, f"HIPAA Security Rule impact identified.{phi_note}")
    
    def _generate_evidence(self, finding: Dict) -> Dict:
        """Generate audit evidence for finding"""
        return {
            'finding_id': finding.get('id', ''),
            'timestamp': finding.get('timestamp', datetime.utcnow().isoformat()),
            'scanner': finding.get('scanner', ''),
            'type': finding.get('type', ''),
            'severity': finding.get('severity', ''),
            'description': finding.get('description', ''),
            'phi_indicators': self._check_phi_indicators(finding)
        }
    
    def _check_phi_indicators(self, finding: Dict) -> List[str]:
        """Check for PHI indicators in finding"""
        phi_indicators = ['patient', 'health', 'medical', 'phi', 'ehr', 'emr']
        text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
        return [ind for ind in phi_indicators if ind in text]
    
    def _get_remediation_guidance(self, standards: Dict, severity: str) -> str:
        """Get HIPAA-specific remediation guidance"""
        if not standards:
            return "Review HIPAA Security Rule requirements."
        
        std_list = ', '.join(standards.keys())
        sections = []
        for std, info in standards.items():
            sections.extend(info['sections'])
        
        section_list = ', '.join(sections)
        
        base = f"HIPAA Security Rule standards affected: {std_list} (sections {section_list}). "
        
        if '164.312' in standards:
            base += "Ensure technical safeguards are implemented. "
        if '164.308' in standards:
            base += "Review administrative safeguards and security management process. "
        if '164.310' in standards:
            base += "Verify physical safeguards are in place. "
        
        timeframes = {
            'critical': "Remediate within 24 hours. Document in risk management process. ",
            'high': "Remediate within 72 hours. Update security incident procedures. ",
            'medium': "Remediate within 2 weeks. Enhance security measures. ",
            'low': "Remediate within 30 days. Update policies and procedures. "
        }
        
        return timeframes.get(severity, "") + base
    
    def get_standard_details(self, standard_id: str) -> Dict:
        """Get details about a specific standard"""
        if standard_id in self.standards:
            std = self.standards[standard_id]
            return {
                'id': standard_id,
                'name': std['name'],
                'sections': [
                    {
                        'id': f"{standard_id}.{sid}",
                        'name': sname
                    }
                    for sid, sname in std['sections'].items()
                ]
            }
        return {}
    
    def get_framework_summary(self) -> Dict:
        """Get summary of HIPAA framework"""
        return {
            'framework': 'HIPAA',
            'version': 'Security Rule',
            'standards': [
                {
                    'id': sid,
                    'name': info['name'],
                    'sections': [
                        f"{sid}.{sec_id}: {sec_name}"
                        for sec_id, sec_name in info['sections'].items()
                    ]
                }
                for sid, info in self.standards.items()
            ]
        }