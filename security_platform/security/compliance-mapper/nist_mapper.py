#!/usr/bin/env python3
"""
NIST SP 800-53 Compliance Mapper
Maps security findings to NIST 800-53 controls
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class NISTMapper:
    """Maps findings to NIST SP 800-53 controls"""
    
    def __init__(self):
        self.families = {
            'AC': {
                'name': 'Access Control',
                'description': 'Access control policies and procedures',
                'controls': {
                    '1': 'Access Control Policy and Procedures',
                    '2': 'Account Management',
                    '3': 'Access Enforcement',
                    '4': 'Information Flow Enforcement',
                    '5': 'Separation of Duties',
                    '6': 'Least Privilege',
                    '7': 'Unsuccessful Logon Attempts',
                    '8': 'System Use Notification',
                    '9': 'Previous Logon Notification',
                    '10': 'Concurrent Session Control',
                    '11': 'Device Lock',
                    '12': 'Session Termination',
                    '13': 'Supervision and Review',
                    '14': 'Permitted Actions Without Identification',
                    '15': 'Automated Marking',
                    '16': 'Security Attributes',
                    '17': 'Remote Access',
                    '18': 'Wireless Access',
                    '19': 'Access Control for Mobile Devices',
                    '20': 'Use of External Information Systems',
                    '21': 'Information Sharing',
                    '22': 'Publicly Accessible Content'
                },
                'keywords': ['access', 'authentication', 'authorization', 'permission', 'password', 'rbac', 'acl']
            },
            'AU': {
                'name': 'Audit and Accountability',
                'description': 'Audit logging and monitoring',
                'controls': {
                    '1': 'Audit and Accountability Policy and Procedures',
                    '2': 'Audit Events',
                    '3': 'Content of Audit Records',
                    '4': 'Audit Storage Capacity',
                    '5': 'Response to Audit Processing Failures',
                    '6': 'Audit Review, Analysis, and Reporting',
                    '7': 'Audit Reduction and Report Generation',
                    '8': 'Time Stamps',
                    '9': 'Protection of Audit Information',
                    '10': 'Non-Repudiation',
                    '11': 'Audit Record Retention',
                    '12': 'Audit Generation',
                    '13': 'Monitoring for Information Disclosure',
                    '14': 'Session Audit',
                    '15': 'Alternate Audit Capability',
                    '16': 'Cross-Organizational Auditing'
                },
                'keywords': ['audit', 'log', 'monitor', 'tracking', 'event']
            },
            'CM': {
                'name': 'Configuration Management',
                'description': 'Configuration settings and baselines',
                'controls': {
                    '1': 'Configuration Management Policy and Procedures',
                    '2': 'Baseline Configuration',
                    '3': 'Configuration Change Control',
                    '4': 'Security Impact Analysis',
                    '5': 'Access Restrictions for Change',
                    '6': 'Configuration Settings',
                    '7': 'Least Functionality',
                    '8': 'Information System Component Inventory',
                    '9': 'Configuration Management Plan',
                    '10': 'Software Usage Restrictions',
                    '11': 'User-Installed Software'
                },
                'keywords': ['configuration', 'baseline', 'setting', 'hardening', 'change', 'version']
            },
            'IA': {
                'name': 'Identification and Authentication',
                'description': 'User identification and authentication',
                'controls': {
                    '1': 'Identification and Authentication Policy and Procedures',
                    '2': 'Identification and Authentication (Organizational Users)',
                    '3': 'Device Identification and Authentication',
                    '4': 'Identifier Management',
                    '5': 'Authenticator Management',
                    '6': 'Authenticator Feedback',
                    '7': 'Cryptographic Module Authentication',
                    '8': 'Authentication Mechanisms',
                    '9': 'Service Identification and Authentication',
                    '10': 'Adaptive Authentication',
                    '11': 'Re-authentication'
                },
                'keywords': ['identity', 'authentication', 'login', 'password', 'mfa', 'credential']
            },
            'IR': {
                'name': 'Incident Response',
                'description': 'Incident handling and reporting',
                'controls': {
                    '1': 'Incident Response Policy and Procedures',
                    '2': 'Incident Response Training',
                    '3': 'Incident Response Testing',
                    '4': 'Incident Handling',
                    '5': 'Incident Monitoring',
                    '6': 'Incident Reporting',
                    '7': 'Incident Response Assistance',
                    '8': 'Incident Response Plan',
                    '9': 'Information Spillage Response',
                    '10': 'Integrated Information Security Analysis Team'
                },
                'keywords': ['incident', 'breach', 'response', 'containment', 'eradication']
            },
            'RA': {
                'name': 'Risk Assessment',
                'description': 'Risk analysis and vulnerability scanning',
                'controls': {
                    '1': 'Risk Assessment Policy and Procedures',
                    '2': 'Security Categorization',
                    '3': 'Risk Assessment',
                    '4': 'Risk Assessment Update',
                    '5': 'Vulnerability Scanning',
                    '6': 'Technical Surveillance Countermeasures Survey',
                    '7': 'Risk Response',
                    '8': 'Privacy Impact Assessment'
                },
                'keywords': ['risk', 'assessment', 'vulnerability', 'scan', 'cve']
            },
            'SA': {
                'name': 'System and Services Acquisition',
                'description': 'Development and acquisition security',
                'controls': {
                    '1': 'System and Services Acquisition Policy and Procedures',
                    '2': 'Allocation of Resources',
                    '3': 'System Development Life Cycle',
                    '4': 'Acquisition Process',
                    '5': 'Information System Documentation',
                    '6': 'Software Usage Restrictions',
                    '7': 'User-Installed Software',
                    '8': 'Security Engineering Principles',
                    '9': 'External Information System Services',
                    '10': 'Developer Configuration Management',
                    '11': 'Developer Security Testing',
                    '12': 'Supply Chain Protection'
                },
                'keywords': ['development', 'acquisition', 'procurement', 'vendor', 'supply chain']
            },
            'SC': {
                'name': 'System and Communications Protection',
                'description': 'Network and system security',
                'controls': {
                    '1': 'System and Communications Protection Policy and Procedures',
                    '2': 'Application Partitioning',
                    '3': 'Security Function Isolation',
                    '4': 'Information in Shared Resources',
                    '5': 'Denial of Service Protection',
                    '6': 'Resource Availability',
                    '7': 'Boundary Protection',
                    '8': 'Transmission Confidentiality and Integrity',
                    '9': 'Transmission Confidentiality',
                    '10': 'Network Disconnect',
                    '11': 'Trusted Path',
                    '12': 'Cryptographic Key Establishment and Management',
                    '13': 'Cryptographic Protection',
                    '14': 'Public Access Protections',
                    '15': 'Collaborative Computing Devices',
                    '16': 'Transmission of Security Attributes',
                    '17': 'Public Key Infrastructure Certificates',
                    '18': 'Mobile Code',
                    '19': 'Voice Over Internet Protocol',
                    '20': 'Secure Name/Address Resolution Service',
                    '21': 'Secure Name/Address Resolution Service (Recursive or Caching Resolver)',
                    '22': 'Architecture and Provisioning for Name/Address Resolution Service',
                    '23': 'Session Authenticity',
                    '24': 'Fail in Known State',
                    '25': 'Thin Nodes',
                    '26': 'Honeypots',
                    '27': 'Platform-Independent Applications',
                    '28': 'Protection of Information at Rest',
                    '29': 'Heterogeneity',
                    '30': 'Concealment and Misdirection',
                    '31': 'Covert Channel Analysis',
                    '32': 'Information System Partitioning',
                    '33': 'Transmission Preparation Integrity',
                    '34': 'Non-Modifiable Executable Programs',
                    '35': 'External Malicious Code Identification',
                    '36': 'Distributed Processing and Storage',
                    '37': 'Out-of-Band Channels',
                    '38': 'Operations Security',
                    '39': 'Process Isolation',
                    '40': 'Wireless Link Protection',
                    '41': 'Port and I/O Device Access',
                    '42': 'Sensor Capability and Data',
                    '43': 'Usage Restrictions',
                    '44': 'Detonation Chambers'
                },
                'keywords': ['network', 'communication', 'encryption', 'tls', 'firewall', 'boundary']
            },
            'SI': {
                'name': 'System and Information Integrity',
                'description': 'System integrity and flaw remediation',
                'controls': {
                    '1': 'System and Information Integrity Policy and Procedures',
                    '2': 'Flaw Remediation',
                    '3': 'Malicious Code Protection',
                    '4': 'Information System Monitoring',
                    '5': 'Security Alerts, Advisories, and Directives',
                    '6': 'Security Function Verification',
                    '7': 'Software, Firmware, and Information Integrity',
                    '8': 'Spam Protection',
                    '9': 'Information Input Validation',
                    '10': 'Information Output Handling and Retention',
                    '11': 'Error Handling',
                    '12': 'Information Handling and Retention',
                    '13': 'Predictable Failure Prevention',
                    '14': 'Non-Persistence',
                    '15': 'Information Output Filtering',
                    '16': 'Memory Protection',
                    '17': 'Fail-Safe Procedures',
                    '18': 'Cybersecurity Maturity Model Certification',
                    '19': 'De-identification',
                    '20': 'Tainting',
                    '21': 'Information Refresh',
                    '22': 'Information Diversity',
                    '23': 'Information Fragmentation',
                    '24': 'Information Hiding'
                },
                'keywords': ['integrity', 'malware', 'virus', 'patch', 'update', 'validation', 'input']
            }
        }
        
    def map_finding(self, finding: Dict) -> Dict:
        """Map a finding to NIST controls"""
        finding_type = finding.get('type', '').lower()
        finding_title = finding.get('title', '').lower()
        finding_description = finding.get('description', '').lower()
        scanner = finding.get('scanner', '').lower()
        severity = finding.get('severity', 'medium').lower()
        
        combined_text = f"{finding_type} {finding_title} {finding_description} {scanner}"
        
        affected_families = {}
        
        # Find matching families and controls
        for family_id, family_info in self.families.items():
            matched_controls = []
            
            # Check keywords
            for keyword in family_info.get('keywords', []):
                if keyword in combined_text:
                    # Find specific control numbers (simplified)
                    if 'access' in keyword:
                        if 'account' in combined_text:
                            matched_controls.append('2')
                        elif 'enforcement' in combined_text:
                            matched_controls.append('3')
                        elif 'privilege' in combined_text:
                            matched_controls.append('6')
                        else:
                            matched_controls.append('1')
                    elif 'audit' in keyword or 'log' in keyword:
                        if 'review' in combined_text:
                            matched_controls.append('6')
                        elif 'retention' in combined_text:
                            matched_controls.append('11')
                        else:
                            matched_controls.append('2')
                    elif 'configuration' in keyword:
                        if 'baseline' in combined_text:
                            matched_controls.append('2')
                        elif 'change' in combined_text:
                            matched_controls.append('3')
                        else:
                            matched_controls.append('1')
                    elif 'incident' in keyword:
                        matched_controls.append('4')
                    elif 'vulnerability' in keyword or 'scan' in keyword:
                        matched_controls.append('5')
                    else:
                        # Add first control as default
                        first_control = next(iter(family_info['controls'].keys()))
                        matched_controls.append(first_control)
                    
                    break
            
            if matched_controls:
                affected_families[family_id] = {
                    'name': family_info['name'],
                    'controls': [
                        {
                            'id': f"{family_id}-{ctrl}",
                            'name': family_info['controls'].get(ctrl, f'Control {ctrl}')
                        }
                        for ctrl in sorted(set(matched_controls))
                    ]
                }
        
        # Special cases based on scanner
        if scanner == 'semgrep' or scanner == 'sonarqube':
            if 'SI' not in affected_families:
                affected_families['SI'] = {
                    'name': self.families['SI']['name'],
                    'controls': [{'id': 'SI-2', 'name': self.families['SI']['controls']['2']}]
                }
        
        if scanner == 'trivy' or scanner == 'grype':
            if 'RA' not in affected_families:
                affected_families['RA'] = {
                    'name': self.families['RA']['name'],
                    'controls': [{'id': 'RA-5', 'name': self.families['RA']['controls']['5']}]
                }
        
        # Determine impact level
        impact_level = self._determine_impact_level(severity)
        
        # Generate evidence
        evidence = self._generate_evidence(finding)
        
        return {
            'framework': 'NIST SP 800-53',
            'families': affected_families,
            'impact_level': impact_level,
            'evidence': evidence,
            'remediation_guidance': self._get_remediation_guidance(affected_families, severity),
            'mapped_at': datetime.utcnow().isoformat()
        }
    
    def _determine_impact_level(self, severity: str) -> str:
        """Determine NIST impact level"""
        mapping = {
            'critical': 'HIGH',
            'high': 'HIGH',
            'medium': 'MODERATE',
            'low': 'LOW',
            'info': 'LOW'
        }
        return mapping.get(severity, 'MODERATE')
    
    def _generate_evidence(self, finding: Dict) -> Dict:
        """Generate audit evidence for finding"""
        return {
            'finding_id': finding.get('id', ''),
            'timestamp': finding.get('timestamp', datetime.utcnow().isoformat()),
            'scanner': finding.get('scanner', ''),
            'type': finding.get('type', ''),
            'severity': finding.get('severity', ''),
            'description': finding.get('description', ''),
            'nist_category': self._categorize_finding(finding)
        }
    
    def _categorize_finding(self, finding: Dict) -> str:
        """Categorize finding for NIST"""
        text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
        
        if 'access' in text or 'permission' in text:
            return 'Access Control'
        elif 'audit' in text or 'log' in text:
            return 'Audit and Accountability'
        elif 'configuration' in text:
            return 'Configuration Management'
        elif 'incident' in text:
            return 'Incident Response'
        elif 'vulnerability' in text or 'cve' in text:
            return 'Risk Assessment'
        elif 'encryption' in text or 'tls' in text:
            return 'System and Communications Protection'
        else:
            return 'System and Information Integrity'
    
    def _get_remediation_guidance(self, families: Dict, severity: str) -> str:
        """Get NIST-specific remediation guidance"""
        if not families:
            return "Review NIST SP 800-53 controls based on system impact level."
        
        family_list = ', '.join(families.keys())
        controls = []
        for fam_id, fam_info in families.items():
            for ctrl in fam_info['controls']:
                controls.append(ctrl['id'])
        
        control_str = ', '.join(controls)
        
        base = f"NIST SP 800-53 controls affected: {control_str}. "
        base += f"Review security controls in family {family_list}. "
        
        impact = self._determine_impact_level(severity)
        base += f"System impact level: {impact}. "
        
        timeframes = {
            'critical': "Remediate immediately. Control deficiencies impact high-impact system. ",
            'high': "Remediate within 72 hours. Update System Security Plan. ",
            'medium': "Remediate within 2 weeks. Address in continuous monitoring. ",
            'low': "Remediate within 30 days. Document in Plan of Action and Milestones. "
        }
        
        return timeframes.get(severity, "") + base
    
    def get_control_details(self, control_id: str) -> Dict:
        """Get details about a specific control"""
        if '-' not in control_id:
            return {}
        
        family = control_id.split('-')[0]
        control_num = control_id.split('-')[1]
        
        if family in self.families and control_num in self.families[family]['controls']:
            return {
                'id': control_id,
                'name': self.families[family]['controls'][control_num],
                'family': family,
                'family_name': self.families[family]['name'],
                'family_description': self.families[family]['description']
            }
        return {}
    
    def get_framework_summary(self) -> Dict:
        """Get summary of NIST framework"""
        return {
            'framework': 'NIST SP 800-53',
            'version': 'Rev 5',
            'families': [
                {
                    'id': fid,
                    'name': info['name'],
                    'description': info['description'],
                    'control_count': len(info['controls'])
                }
                for fid, info in self.families.items()
            ]
        }