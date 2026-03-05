#!/usr/bin/env python3
"""
PCI-DSS Compliance Mapper
Maps security findings to PCI-DSS requirements
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class PCIDSSMapper:
    """Maps findings to PCI-DSS requirements (12 requirements)"""
    
    def __init__(self):
        self.requirements = {
            '1': {
                'name': 'Install and maintain firewall configuration',
                'description': 'Protect cardholder data with firewalls',
                'keywords': ['firewall', 'network', 'port', 'acl', 'router']
            },
            '2': {
                'name': 'Do not use vendor-supplied defaults',
                'description': 'Change default passwords and settings',
                'keywords': ['default', 'password', 'vendor', 'default credential']
            },
            '3': {
                'name': 'Protect stored cardholder data',
                'description': 'Encrypt stored cardholder data',
                'keywords': ['encryption', 'storage', 'cardholder', 'pan', 'data at rest']
            },
            '4': {
                'name': 'Encrypt transmission of cardholder data',
                'description': 'Encrypt data in transit',
                'keywords': ['tls', 'ssl', 'encryption', 'transmission', 'network', 'https']
            },
            '5': {
                'name': 'Protect against malware',
                'description': 'Use anti-malware solutions',
                'keywords': ['malware', 'virus', 'antivirus', 'scan']
            },
            '6': {
                'name': 'Develop and maintain secure systems',
                'description': 'Patch and update systems regularly',
                'keywords': ['patch', 'update', 'vulnerability', 'cve', 'dependency']
            },
            '7': {
                'name': 'Restrict access to cardholder data',
                'description': 'Need-to-know access',
                'keywords': ['access', 'permission', 'authorization', 'rbac']
            },
            '8': {
                'name': 'Identify and authenticate access',
                'description': 'Strong authentication',
                'keywords': ['authentication', 'password', 'mfa', 'credential', 'login']
            },
            '9': {
                'name': 'Restrict physical access',
                'description': 'Physical security controls',
                'keywords': ['physical', 'facility', 'data center']
            },
            '10': {
                'name': 'Track and monitor access',
                'description': 'Logging and monitoring',
                'keywords': ['log', 'audit', 'monitor', 'tracking', 'event']
            },
            '11': {
                'name': 'Test security systems',
                'description': 'Regular security testing',
                'keywords': ['scan', 'test', 'penetration', 'assessment', 'vulnerability scan']
            },
            '12': {
                'name': 'Maintain information security policy',
                'description': 'Security policies and procedures',
                'keywords': ['policy', 'procedure', 'documentation', 'training']
            }
        }
        
    def map_finding(self, finding: Dict) -> Dict:
        """Map a finding to PCI-DSS requirements"""
        finding_type = finding.get('type', '').lower()
        finding_title = finding.get('title', '').lower()
        finding_description = finding.get('description', '').lower()
        scanner = finding.get('scanner', '').lower()
        severity = finding.get('severity', 'medium').lower()
        
        # Combine all text for matching
        combined_text = f"{finding_type} {finding_title} {finding_description} {scanner}"
        
        affected_requirements = set()
        
        # Find matching requirements
        for req_id, req_info in self.requirements.items():
            for keyword in req_info['keywords']:
                if keyword in combined_text:
                    affected_requirements.add(req_id)
                    break
        
        # Special cases based on scanner
        if scanner == 'trivy' or scanner == 'grype':
            affected_requirements.add('6')  # Secure systems
            if 'container' in combined_text:
                affected_requirements.add('2')  # Defaults
        
        if scanner == 'gitleaks' or scanner == 'trufflehog':
            affected_requirements.add('8')  # Authentication
            affected_requirements.add('3')  # Protect stored data
        
        if scanner == 'checkov' or scanner == 'tfsec':
            affected_requirements.add('1')  # Firewall
            affected_requirements.add('2')  # Defaults
        
        # Determine PCI impact
        pci_impact = self._determine_pci_impact(severity, affected_requirements)
        
        # Generate evidence
        evidence = self._generate_evidence(finding)
        
        return {
            'framework': 'PCI-DSS',
            'requirements': list(affected_requirements),
            'impact': pci_impact,
            'evidence': evidence,
            'remediation_guidance': self._get_remediation_guidance(affected_requirements, severity),
            'mapped_at': datetime.utcnow().isoformat()
        }
    
    def _determine_pci_impact(self, severity: str, requirements: set) -> str:
        """Determine PCI compliance impact"""
        if not requirements:
            return "No direct PCI impact identified"
        
        req_list = ', '.join(sorted(requirements))
        
        impacts = {
            'critical': f"High PCI impact - Requirements {req_list} affected. "
                       f"Cardholder data may be at risk.",
            'high': f"Moderate PCI impact - Requirements {req_list} affected. "
                   f"Control weaknesses identified.",
            'medium': f"Low PCI impact - Requirements {req_list} affected. "
                     f"Process improvements needed.",
            'low': f"Informational - Requirements {req_list} affected. "
                  f"Minor enhancements suggested."
        }
        
        return impacts.get(severity, f"PCI requirements affected: {req_list}")
    
    def _generate_evidence(self, finding: Dict) -> Dict:
        """Generate audit evidence for finding"""
        return {
            'finding_id': finding.get('id', ''),
            'timestamp': finding.get('timestamp', datetime.utcnow().isoformat()),
            'scanner': finding.get('scanner', ''),
            'type': finding.get('type', ''),
            'severity': finding.get('severity', ''),
            'description': finding.get('description', ''),
            'evidence_data': {
                'file': finding.get('file', ''),
                'line': finding.get('line', 0),
                'code_snippet': finding.get('metadata', {}).get('code', '')
            }
        }
    
    def _get_remediation_guidance(self, requirements: set, severity: str) -> str:
        """Get PCI-specific remediation guidance"""
        req_list = ', '.join(sorted(requirements))
        
        if '3' in requirements or '4' in requirements:
            encryption = "Ensure all cardholder data is encrypted at rest and in transit. "
        else:
            encryption = ""
        
        if '1' in requirements:
            firewall = "Review firewall rules and network segmentation. "
        else:
            firewall = ""
        
        if '6' in requirements:
            patching = "Apply security patches and updates. "
        else:
            patching = ""
        
        if '8' in requirements:
            auth = "Strengthen authentication controls. "
        else:
            auth = ""
        
        base = f"PCI-DSS Requirements affected: {req_list}. "
        
        timeframes = {
            'critical': "Remediate within 24 hours. ",
            'high': "Remediate within 72 hours. ",
            'medium': "Remediate within 2 weeks. ",
            'low': "Remediate within 30 days. "
        }
        
        return timeframes.get(severity, "") + base + encryption + firewall + patching + auth
    
    def get_requirement_details(self, req_id: str) -> Dict:
        """Get details about a specific requirement"""
        if req_id in self.requirements:
            return {
                'id': req_id,
                'name': self.requirements[req_id]['name'],
                'description': self.requirements[req_id]['description'],
                'testing_procedures': self._get_testing_procedures(req_id)
            }
        return {}
    
    def _get_testing_procedures(self, req_id: str) -> List[str]:
        """Get PCI testing procedures for a requirement"""
        procedures = {
            '1': [
                "Review firewall configuration",
                "Verify firewall rules restrict access",
                "Check for unnecessary open ports"
            ],
            '2': [
                "Review default account configurations",
                "Verify default passwords are changed",
                "Check vendor default settings"
            ],
            '3': [
                "Verify data encryption methods",
                "Review key management procedures",
                "Check data retention policies"
            ],
            '4': [
                "Verify TLS/SSL configurations",
                "Check certificate validity",
                "Review encryption protocols"
            ],
            '6': [
                "Review patch management process",
                "Verify vulnerability scans are performed",
                "Check system hardening standards"
            ],
            '8': [
                "Review authentication mechanisms",
                "Verify password policies",
                "Check MFA implementation"
            ],
            '10': [
                "Review audit log settings",
                "Verify log monitoring",
                "Check log retention"
            ],
            '11': [
                "Review vulnerability scan results",
                "Verify penetration testing is performed",
                "Check security testing procedures"
            ]
        }
        return procedures.get(req_id, ["Review PCI DSS requirements"])
    
    def get_framework_summary(self) -> Dict:
        """Get summary of PCI-DSS framework"""
        return {
            'framework': 'PCI-DSS',
            'version': '3.2.1',
            'requirement_count': len(self.requirements),
            'requirements': [
                {
                    'id': rid,
                    'name': info['name'],
                    'description': info['description']
                }
                for rid, info in self.requirements.items()
            ]
        }