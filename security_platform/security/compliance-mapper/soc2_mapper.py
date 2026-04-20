#!/usr/bin/env python3
"""
SOC2 Compliance Mapper
Maps security findings to SOC2 Trust Services Criteria
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class SOC2Mapper:
    """Maps findings to SOC2 controls (CC1-CC9)"""
    
    def __init__(self):
        self.controls = {
            'CC1': {
                'name': 'Control Environment',
                'description': 'Demonstrates commitment to integrity and ethical values',
                'mappings': {
                    'access': ['CC6'],
                    'authentication': ['CC6'],
                    'authorization': ['CC6'],
                    'change': ['CC8'],
                    'configuration': ['CC8'],
                    'encryption': ['CC6'],
                    'incident': ['CC7'],
                    'logging': ['CC7'],
                    'monitoring': ['CC7'],
                    'password': ['CC6'],
                    'patch': ['CC8'],
                    'permission': ['CC6'],
                    'secret': ['CC6'],
                    'vulnerability': ['CC7']
                }
            },
            'CC2': {
                'name': 'Communication and Information',
                'description': 'Communicates information internally and externally',
                'mappings': {
                    'reporting': ['CC2'],
                    'notification': ['CC2'],
                    'documentation': ['CC2']
                }
            },
            'CC3': {
                'name': 'Risk Assessment',
                'description': 'Identifies and analyzes risks',
                'mappings': {
                    'risk': ['CC3'],
                    'assessment': ['CC3']
                }
            },
            'CC4': {
                'name': 'Monitoring Activities',
                'description': 'Monitors controls for effectiveness',
                'mappings': {
                    'monitor': ['CC4'],
                    'review': ['CC4']
                }
            },
            'CC5': {
                'name': 'Control Activities',
                'description': 'Selects and develops control activities',
                'mappings': {
                    'default': ['CC5']
                }
            },
            'CC6': {
                'name': 'Logical and Physical Access',
                'description': 'Restricts logical and physical access',
                'mappings': {
                    'access': ['CC6'],
                    'authentication': ['CC6'],
                    'authorization': ['CC6'],
                    'encryption': ['CC6'],
                    'firewall': ['CC6'],
                    'network': ['CC6'],
                    'password': ['CC6'],
                    'permission': ['CC6'],
                    'secret': ['CC6'],
                    'tls': ['CC6'],
                    'ssh': ['CC6']
                }
            },
            'CC7': {
                'name': 'System Operations',
                'description': 'Manages system operations',
                'mappings': {
                    'availability': ['CC7'],
                    'backup': ['CC7'],
                    'capacity': ['CC7'],
                    'disaster': ['CC7'],
                    'incident': ['CC7'],
                    'logging': ['CC7'],
                    'monitoring': ['CC7'],
                    'recovery': ['CC7'],
                    'vulnerability': ['CC7']
                }
            },
            'CC8': {
                'name': 'Change Management',
                'description': 'Manages changes to the system',
                'mappings': {
                    'change': ['CC8'],
                    'configuration': ['CC8'],
                    'deployment': ['CC8'],
                    'patch': ['CC8'],
                    'release': ['CC8'],
                    'update': ['CC8'],
                    'version': ['CC8']
                }
            },
            'CC9': {
                'name': 'Risk Mitigation',
                'description': 'Mitigates risks',
                'mappings': {
                    'vendor': ['CC9'],
                    'third-party': ['CC9'],
                    'supplier': ['CC9']
                }
            }
        }
        
    def map_finding(self, finding: Dict) -> Dict:
        """Map a finding to SOC2 controls"""
        finding_type = finding.get('type', '').lower()
        finding_title = finding.get('title', '').lower()
        finding_description = finding.get('description', '').lower()
        scanner = finding.get('scanner', '').lower()
        severity = finding.get('severity', 'medium').lower()
        
        # Combine all text for matching
        combined_text = f"{finding_type} {finding_title} {finding_description} {scanner}"
        
        affected_controls = set()
        
        # Find matching controls
        for control_id, control_info in self.controls.items():
            for keyword, mappings in control_info['mappings'].items():
                if keyword in combined_text:
                    affected_controls.update(mappings)
        
        # If no matches, default to CC5
        if not affected_controls:
            affected_controls.add('CC5')
        
        # Determine compliance impact
        impact = self._determine_impact(severity)
        
        # Generate evidence
        evidence = self._generate_evidence(finding)
        
        return {
            'framework': 'SOC2',
            'controls': list(affected_controls),
            'impact': impact,
            'evidence': evidence,
            'remediation_guidance': self._get_remediation_guidance(affected_controls, severity),
            'mapped_at': datetime.utcnow().isoformat()
        }
    
    def _determine_impact(self, severity: str) -> str:
        """Determine compliance impact based on severity"""
        impacts = {
            'critical': 'High - Control deficiency impacts security objective',
            'high': 'Moderate - Control weakness identified',
            'medium': 'Low - Control enhancement needed',
            'low': 'Informational - Minor control improvement'
        }
        return impacts.get(severity, 'Unknown impact')
    
    def _generate_evidence(self, finding: Dict) -> Dict:
        """Generate audit evidence for finding"""
        return {
            'finding_id': finding.get('id', ''),
            'timestamp': finding.get('timestamp', datetime.utcnow().isoformat()),
            'scanner': finding.get('scanner', ''),
            'type': finding.get('type', ''),
            'severity': finding.get('severity', ''),
            'file': finding.get('file', ''),
            'line': finding.get('line', 0),
            'description': finding.get('description', '')
        }
    
    def _get_remediation_guidance(self, controls: set, severity: str) -> str:
        """Get remediation guidance based on controls"""
        control_list = ', '.join(sorted(controls))
        
        base_guidance = {
            'critical': f"Immediate remediation required. Controls affected: {control_list}. "
                       f"Control deficiency impacts security objective.",
            'high': f"Remediate within 72 hours. Controls affected: {control_list}. "
                   f"Control weakness identified.",
            'medium': f"Remediate within 2 weeks. Controls affected: {control_list}. "
                     f"Process improvement needed.",
            'low': f"Remediate within 30 days. Controls affected: {control_list}. "
                  f"Minor control enhancement."
        }
        
        return base_guidance.get(severity, f"Follow standard remediation process. "
                                          f"Controls affected: {control_list}")
    
    def get_control_details(self, control_id: str) -> Dict:
        """Get details about a specific control"""
        if control_id in self.controls:
            return {
                'id': control_id,
                'name': self.controls[control_id]['name'],
                'description': self.controls[control_id]['description']
            }
        return {}
    
    def get_framework_summary(self) -> Dict:
        """Get summary of the SOC2 framework"""
        return {
            'framework': 'SOC2',
            'version': '2017',
            'control_count': len(self.controls),
            'controls': [
                {
                    'id': cid,
                    'name': info['name'],
                    'description': info['description']
                }
                for cid, info in self.controls.items()
            ]
        }