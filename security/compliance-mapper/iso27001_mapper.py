#!/usr/bin/env python3
"""
ISO27001 Compliance Mapper
Maps security findings to ISO27001 Annex A controls
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ISO27001Mapper:
    """Maps findings to ISO27001 Annex A controls"""
    
    def __init__(self):
        self.controls = {
            'A.5': {
                'name': 'Information Security Policies',
                'controls': {
                    '5.1': 'Management direction for information security',
                    '5.2': 'Information security policies and procedures'
                },
                'keywords': ['policy', 'procedure', 'documentation']
            },
            'A.6': {
                'name': 'Organization of Information Security',
                'controls': {
                    '6.1': 'Internal organization',
                    '6.2': 'Mobile devices and teleworking',
                    '6.3': 'Information security roles and responsibilities'
                },
                'keywords': ['organization', 'role', 'responsibility', 'mobile', 'telework']
            },
            'A.7': {
                'name': 'Human Resource Security',
                'controls': {
                    '7.1': 'Prior to employment',
                    '7.2': 'During employment',
                    '7.3': 'Termination and change of employment'
                },
                'keywords': ['employee', 'training', 'awareness', 'termination', 'hr']
            },
            'A.8': {
                'name': 'Asset Management',
                'controls': {
                    '8.1': 'Responsibility for assets',
                    '8.2': 'Information classification',
                    '8.3': 'Media handling'
                },
                'keywords': ['asset', 'inventory', 'classification', 'media', 'label']
            },
            'A.9': {
                'name': 'Access Control',
                'controls': {
                    '9.1': 'Business requirements of access control',
                    '9.2': 'User access management',
                    '9.3': 'User responsibilities',
                    '9.4': 'System and application access control'
                },
                'keywords': ['access', 'authentication', 'authorization', 'permission', 'password', 'rbac']
            },
            'A.10': {
                'name': 'Cryptography',
                'controls': {
                    '10.1': 'Cryptographic controls',
                    '10.2': 'Key management'
                },
                'keywords': ['encryption', 'crypto', 'tls', 'ssl', 'key', 'certificate']
            },
            'A.11': {
                'name': 'Physical and Environmental Security',
                'controls': {
                    '11.1': 'Secure areas',
                    '11.2': 'Equipment security'
                },
                'keywords': ['physical', 'facility', 'data center', 'equipment']
            },
            'A.12': {
                'name': 'Operations Security',
                'controls': {
                    '12.1': 'Operational procedures and responsibilities',
                    '12.2': 'Protection from malware',
                    '12.3': 'Backup',
                    '12.4': 'Logging and monitoring',
                    '12.5': 'Control of operational software',
                    '12.6': 'Technical vulnerability management',
                    '12.7': 'Information systems audit considerations'
                },
                'keywords': ['operation', 'procedure', 'malware', 'backup', 'log', 'monitor', 'vulnerability', 'patch']
            },
            'A.13': {
                'name': 'Communications Security',
                'controls': {
                    '13.1': 'Network security management',
                    '13.2': 'Information transfer'
                },
                'keywords': ['network', 'communication', 'transfer', 'firewall']
            },
            'A.14': {
                'name': 'System Acquisition, Development and Maintenance',
                'controls': {
                    '14.1': 'Security requirements of information systems',
                    '14.2': 'Security in development and support processes',
                    '14.3': 'Test data'
                },
                'keywords': ['development', 'code', 'testing', 'sdlc', 'application']
            },
            'A.15': {
                'name': 'Supplier Relationships',
                'controls': {
                    '15.1': 'Information security in supplier relationships',
                    '15.2': 'Supplier service delivery management'
                },
                'keywords': ['supplier', 'vendor', 'third-party', 'outsource']
            },
            'A.16': {
                'name': 'Information Security Incident Management',
                'controls': {
                    '16.1': 'Management of information security incidents and improvements'
                },
                'keywords': ['incident', 'breach', 'response', 'event']
            },
            'A.17': {
                'name': 'Information Security Aspects of Business Continuity Management',
                'controls': {
                    '17.1': 'Information security continuity',
                    '17.2': 'Redundancies'
                },
                'keywords': ['continuity', 'disaster', 'recovery', 'bcp', 'drp']
            },
            'A.18': {
                'name': 'Compliance',
                'controls': {
                    '18.1': 'Compliance with legal and contractual requirements',
                    '18.2': 'Information security reviews'
                },
                'keywords': ['compliance', 'legal', 'regulation', 'audit', 'review']
            }
        }
        
    def map_finding(self, finding: Dict) -> Dict:
        """Map a finding to ISO27001 controls"""
        finding_type = finding.get('type', '').lower()
        finding_title = finding.get('title', '').lower()
        finding_description = finding.get('description', '').lower()
        scanner = finding.get('scanner', '').lower()
        severity = finding.get('severity', 'medium').lower()
        
        combined_text = f"{finding_type} {finding_title} {finding_description} {scanner}"
        
        affected_controls = {}
        
        # Find matching controls
        for annex_id, annex_info in self.controls.items():
            matched_controls = []
            
            for control_id, control_name in annex_info['controls'].items():
                full_id = f"{annex_id}.{control_id}"
                
                # Check keywords
                for keyword in annex_info.get('keywords', []):
                    if keyword in combined_text:
                        matched_controls.append({
                            'id': full_id,
                            'name': control_name,
                            'confidence': 'high'
                        })
                        break
            
            if matched_controls:
                affected_controls[annex_id] = {
                    'name': annex_info['name'],
                    'controls': matched_controls
                }
        
        # Determine ISO impact
        iso_impact = self._determine_iso_impact(severity)
        
        # Generate evidence
        evidence = self._generate_evidence(finding)
        
        return {
            'framework': 'ISO27001',
            'controls': affected_controls,
            'impact': iso_impact,
            'evidence': evidence,
            'remediation_guidance': self._get_remediation_guidance(affected_controls, severity),
            'mapped_at': datetime.utcnow().isoformat()
        }
    
    def _determine_iso_impact(self, severity: str) -> str:
        """Determine ISO27001 compliance impact"""
        impacts = {
            'critical': "High ISO27001 impact. Control objective compromised.",
            'high': "Moderate ISO27001 impact. Control weakness identified.",
            'medium': "Low ISO27001 impact. Control enhancement needed.",
            'low': "Informational. Minor control improvement."
        }
        return impacts.get(severity, "ISO27001 control impact identified")
    
    def _generate_evidence(self, finding: Dict) -> Dict:
        """Generate audit evidence for finding"""
        return {
            'finding_id': finding.get('id', ''),
            'timestamp': finding.get('timestamp', datetime.utcnow().isoformat()),
            'scanner': finding.get('scanner', ''),
            'type': finding.get('type', ''),
            'severity': finding.get('severity', ''),
            'description': finding.get('description', ''),
            'statement_of_applicability': self._get_soa_recommendation(finding)
        }
    
    def _get_soa_recommendation(self, finding: Dict) -> str:
        """Get Statement of Applicability recommendation"""
        severity = finding.get('severity', 'medium')
        
        if severity in ['critical', 'high']:
            return "Control should be implemented and documented in SoA"
        elif severity == 'medium':
            return "Consider implementing control based on risk assessment"
        else:
            return "Control may be considered optional based on risk appetite"
    
    def _get_remediation_guidance(self, controls: Dict, severity: str) -> str:
        """Get ISO27001-specific remediation guidance"""
        if not controls:
            return "Review ISO27001 Annex A controls in Statement of Applicability."
        
        control_list = []
        for annex, info in controls.items():
            for ctrl in info['controls']:
                control_list.append(ctrl['id'])
        
        control_str = ', '.join(control_list)
        
        base = f"ISO27001 Annex A controls affected: {control_str}. "
        base += "Update Statement of Applicability and risk treatment plan. "
        
        timeframes = {
            'critical': "Remediate within 24 hours. Control implementation required. ",
            'high': "Remediate within 72 hours. Update risk treatment plan. ",
            'medium': "Remediate within 2 weeks. Consider in next management review. ",
            'low': "Remediate within 30 days. Document in continuous improvement. "
        }
        
        return timeframes.get(severity, "") + base
    
    def get_control_details(self, control_id: str) -> Dict:
        """Get details about a specific control"""
        for annex_id, annex_info in self.controls.items():
            for cid, cname in annex_info['controls'].items():
                if control_id == f"{annex_id}.{cid}":
                    return {
                        'id': control_id,
                        'name': cname,
                        'annex': annex_id,
                        'annex_name': annex_info['name'],
                        'implementation_guidance': self._get_implementation_guidance(control_id)
                    }
        return {}
    
    def _get_implementation_guidance(self, control_id: str) -> str:
        """Get implementation guidance for a control"""
        guidance = {
            'A.9.1': "Implement access control policy and procedures",
            'A.9.2': "Manage user access rights and reviews",
            'A.12.6': "Implement vulnerability management process",
            'A.16.1': "Establish incident response procedures"
        }
        return guidance.get(control_id, "Refer to ISO27002 for implementation guidance")
    
    def get_framework_summary(self) -> Dict:
        """Get summary of ISO27001 framework"""
        return {
            'framework': 'ISO27001',
            'version': '2022',
            'annexes': [
                {
                    'id': aid,
                    'name': info['name'],
                    'controls': [
                        f"{aid}.{cid}: {cname}"
                        for cid, cname in info['controls'].items()
                    ]
                }
                for aid, info in self.controls.items()
            ]
        }