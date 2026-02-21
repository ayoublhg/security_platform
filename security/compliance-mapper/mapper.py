#!/usr/bin/env python3
"""
Enterprise Compliance Mapping Engine
Maps security findings to multiple compliance frameworks
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime
import json
import yaml
import sqlite3
import logging

logger = logging.getLogger(__name__)

class ComplianceFramework(str, Enum):
    SOC2 = "SOC2"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    ISO27001 = "ISO27001"
    NIST_800_53 = "NIST-800-53"
    GDPR = "GDPR"
    CCPA = "CCPA"

class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "na"
    NOT_TESTED = "not_tested"

class ComplianceMapper:
    """Maps security findings to compliance controls"""
    
    def __init__(self):
        self.frameworks = {
            ComplianceFramework.SOC2: SOC2Mapper(),
            ComplianceFramework.PCI_DSS: PCIDSSMapper(),
            ComplianceFramework.HIPAA: HIPAAMapper(),
            ComplianceFramework.ISO27001: ISO27001Mapper(),
            ComplianceFramework.NIST_800_53: NISTMapper()
        }
        self.control_definitions = self.load_control_definitions()
        
    def load_control_definitions(self) -> Dict:
        """Load control definitions from YAML files"""
        controls = {}
        
        # SOC2 controls
        controls[ComplianceFramework.SOC2] = {
            "CC1": "Control Environment",
            "CC2": "Communication and Information",
            "CC3": "Risk Assessment",
            "CC4": "Monitoring Activities",
            "CC5": "Control Activities",
            "CC6": "Logical and Physical Access",
            "CC7": "System Operations",
            "CC8": "Change Management",
            "CC9": "Risk Mitigation"
        }
        
        # PCI-DSS controls
        controls[ComplianceFramework.PCI_DSS] = {
            "1": "Install and maintain firewall configuration",
            "2": "Do not use vendor-supplied defaults",
            "3": "Protect stored cardholder data",
            "4": "Encrypt transmission of cardholder data",
            "5": "Protect against malware",
            "6": "Develop and maintain secure systems",
            "7": "Restrict access to cardholder data",
            "8": "Identify and authenticate access",
            "9": "Restrict physical access",
            "10": "Track and monitor access",
            "11": "Test security systems",
            "12": "Maintain information security policy"
        }
        
        return controls
    
    def map_finding(self, finding: Dict, frameworks: List[ComplianceFramework]) -> Dict:
        """Map a single finding to compliance frameworks"""
        result = {}
        
        for framework in frameworks:
            mapper = self.frameworks.get(framework)
            if mapper:
                controls = mapper.map_control(finding)
                result[framework.value] = {
                    "controls": controls,
                    "status": self.determine_status(finding, controls),
                    "evidence": self.collect_evidence(finding, controls),
                    "remediation": mapper.get_remediation(finding, controls)
                }
        
        return result
    
    def map_findings_batch(self, findings: List[Dict], 
                           frameworks: List[ComplianceFramework]) -> Dict:
        """Map multiple findings to compliance frameworks"""
        compliance_report = {}
        
        for framework in frameworks:
            framework_results = []
            affected_controls = set()
            
            for finding in findings:
                mapping = self.map_finding(finding, [framework])
                if mapping.get(framework.value):
                    framework_results.append({
                        "finding": finding,
                        "mapping": mapping[framework.value]
                    })
                    for control in mapping[framework.value].get("controls", []):
                        affected_controls.add(control)
            
            # Calculate framework compliance
            total_controls = len(self.control_definitions.get(framework, {}))
            compliant_controls = self.calculate_compliant_controls(
                framework_results, framework
            )
            
            compliance_report[framework.value] = {
                "total_findings": len(framework_results),
                "affected_controls": list(affected_controls),
                "compliance_score": (compliant_controls / total_controls * 100) if total_controls > 0 else 0,
                "status": self.get_framework_status(compliant_controls, total_controls),
                "details": framework_results,
                "audit_evidence": self.generate_audit_evidence(framework_results)
            }
        
        return compliance_report
    
    def determine_status(self, finding: Dict, controls: List[str]) -> ControlStatus:
        """Determine control status based on finding"""
        severity = finding.get('severity', 'low').upper()
        
        if severity in ['CRITICAL', 'HIGH']:
            return ControlStatus.NON_COMPLIANT
        elif severity == 'MEDIUM':
            return ControlStatus.PARTIAL
        elif severity == 'LOW':
            return ControlStatus.COMPLIANT
        else:
            return ControlStatus.NOT_TESTED
    
    def collect_evidence(self, finding: Dict, controls: List[str]) -> Dict:
        """Collect evidence for audit"""
        return {
            "finding_id": finding.get('id'),
            "timestamp": datetime.now().isoformat(),
            "scanner": finding.get('scanner'),
            "evidence_data": {
                "file": finding.get('file'),
                "line": finding.get('line'),
                "description": finding.get('description')
            },
            "controls": controls
        }
    
    def calculate_compliant_controls(self, results: List[Dict], 
                                      framework: ComplianceFramework) -> int:
        """Calculate number of compliant controls"""
        control_status = {}
        
        for result in results:
            for control in result['mapping']['controls']:
                status = result['mapping']['status']
                if control not in control_status or status.value == 'non_compliant':
                    control_status[control] = status
        
        return sum(1 for status in control_status.values() 
                  if status == ControlStatus.COMPLIANT)
    
    def get_framework_status(self, compliant: int, total: int) -> str:
        """Get overall framework compliance status"""
        percentage = (compliant / total * 100) if total > 0 else 0
        
        if percentage >= 95:
            return "Excellent"
        elif percentage >= 80:
            return "Good"
        elif percentage >= 60:
            return "Needs Improvement"
        else:
            return "Non-Compliant"
    
    def generate_audit_evidence(self, results: List[Dict]) -> Dict:
        """Generate auditor-ready evidence package"""
        return {
            "summary": {
                "total_findings": len(results),
                "compliant": sum(1 for r in results 
                               if r['mapping']['status'] == ControlStatus.COMPLIANT),
                "non_compliant": sum(1 for r in results 
                                   if r['mapping']['status'] == ControlStatus.NON_COMPLIANT)
            },
            "evidence_files": [r['mapping']['evidence'] for r in results],
            "audit_trail": self.generate_audit_trail(results),
            "timestamp": datetime.now().isoformat()
        }
    
    def generate_audit_trail(self, results: List[Dict]) -> List[Dict]:
        """Generate audit trail for findings"""
        audit_trail = []
        
        for result in results:
            audit_trail.append({
                "action": "finding_detected",
                "timestamp": result['finding'].get('timestamp'),
                "finding_id": result['finding'].get('id'),
                "scanner": result['finding'].get('scanner'),
                "controls_affected": result['mapping']['controls']
            })
        
        return sorted(audit_trail, key=lambda x: x['timestamp'])

class SOC2Mapper:
    """SOC2 specific control mapping"""
    
    def map_control(self, finding: Dict) -> List[str]:
        """Map finding to SOC2 controls"""
        controls = []
        
        # Mapping logic based on finding type
        finding_type = finding.get('type', '')
        
        if 'access' in finding_type.lower() or 'permission' in finding_type.lower():
            controls.append('CC6')  # Logical and Physical Access
        elif 'change' in finding_type.lower() or 'version' in finding_type.lower():
            controls.append('CC8')  # Change Management
        elif 'vulnerability' in finding_type.lower() or 'cve' in finding_type.lower():
            controls.append('CC7')  # System Operations
        elif 'secret' in finding_type.lower() or 'password' in finding_type.lower():
            controls.append('CC6')  # Logical Access
        elif 'encryption' in finding_type.lower():
            controls.append('CC6')  # Encryption controls
        elif 'monitoring' in finding_type.lower() or 'log' in finding_type.lower():
            controls.append('CC7')  # Monitoring
        else:
            controls.append('CC5')  # Default to Control Activities
        
        return controls
    
    def get_remediation(self, finding: Dict, controls: List[str]) -> str:
        """Get SOC2-specific remediation guidance"""
        severity = finding.get('severity', 'medium')
        
        base_remediation = {
            'critical': "Immediate remediation required. Control deficiency impacts security objective.",
            'high': "Remediate within 72 hours. Control weakness identified.",
            'medium': "Remediate within 2 weeks. Process improvement needed.",
            'low': "Remediate within 30 days. Minor control enhancement."
        }
        
        return base_remediation.get(severity, "Follow standard remediation process.")

class PCIDSSMapper:
    """PCI-DSS specific control mapping"""
    
    def map_control(self, finding: Dict) -> List[str]:
        """Map finding to PCI-DSS requirements"""
        controls = []
        
        finding_type = finding.get('type', '')
        
        if 'cardholder' in finding_type.lower() or 'pan' in finding_type.lower():
            controls.extend(['3', '4'])  # Protect stored data, encrypt transmission
        elif 'authentication' in finding_type.lower() or 'password' in finding_type.lower():
            controls.append('8')  # Identify and authenticate access
        elif 'firewall' in finding_type.lower() or 'network' in finding_type.lower():
            controls.append('1')  # Firewall configuration
        elif 'malware' in finding_type.lower() or 'virus' in finding_type.lower():
            controls.append('5')  # Protect against malware
        elif 'vulnerability' in finding_type.lower() or 'cve' in finding_type.lower():
            controls.append('6')  # Secure systems
        elif 'log' in finding_type.lower() or 'audit' in finding_type.lower():
            controls.append('10')  # Track and monitor
        elif 'test' in finding_type.lower():
            controls.append('11')  # Test security
        
        return controls
    
    def get_remediation(self, finding: Dict, controls: List[str]) -> str:
        """Get PCI-DSS specific remediation"""
        control_list = ', '.join(controls)
        return f"Address finding to comply with PCI-DSS Requirement(s) {control_list}. " \
               f"Document remediation in compliance evidence package."

class HIPAAMapper:
    """HIPAA specific control mapping"""
    
    def map_control(self, finding: Dict) -> List[str]:
        """Map finding to HIPAA Security Rule standards"""
        controls = []
        
        finding_type = finding.get('type', '')
        
        # Administrative Safeguards
        if 'risk' in finding_type.lower():
            controls.append('164.308(a)(1)')  # Risk Analysis
        elif 'training' in finding_type.lower():
            controls.append('164.308(a)(5)')  # Security Awareness Training
        
        # Physical Safeguards
        elif 'physical' in finding_type.lower() or 'facility' in finding_type.lower():
            controls.append('164.310')  # Physical Access Controls
        
        # Technical Safeguards
        elif 'access' in finding_type.lower():
            controls.append('164.312(a)')  # Access Control
        elif 'audit' in finding_type.lower() or 'log' in finding_type.lower():
            controls.append('164.312(b)')  # Audit Controls
        elif 'integrity' in finding_type.lower():
            controls.append('164.312(c)')  # Integrity
        elif 'authentication' in finding_type.lower():
            controls.append('164.312(d)')  # Person or Entity Authentication
        elif 'transmission' in finding_type.lower() or 'encryption' in finding_type.lower():
            controls.append('164.312(e)')  # Transmission Security
        
        return controls
    
    def get_remediation(self, finding: Dict, controls: List[str]) -> str:
        """Get HIPAA-specific remediation"""
        return f"Address HIPAA Security Rule standard {', '.join(controls)}. " \
               "Document in risk management process. Consider potential PHI impact."

class ISO27001Mapper:
    """ISO27001 specific control mapping (Annex A)"""
    
    def map_control(self, finding: Dict) -> List[str]:
        """Map finding to ISO27001 Annex A controls"""
        controls = []
        
        finding_type = finding.get('type', '')
        
        # Information Security Policies
        if 'policy' in finding_type.lower():
            controls.append('A.5')  # Information Security Policies
        
        # Organization of Information Security
        elif 'role' in finding_type.lower() or 'responsibility' in finding_type.lower():
            controls.append('A.6')  # Organization of Information Security
        
        # Human Resource Security
        elif 'training' in finding_type.lower():
            controls.append('A.7')  # Human Resource Security
        
        # Asset Management
        elif 'asset' in finding_type.lower() or 'inventory' in finding_type.lower():
            controls.append('A.8')  # Asset Management
        
        # Access Control
        elif 'access' in finding_type.lower() or 'permission' in finding_type.lower():
            controls.append('A.9')  # Access Control
        
        # Cryptography
        elif 'encryption' in finding_type.lower() or 'crypto' in finding_type.lower():
            controls.append('A.10')  # Cryptography
        
        # Physical Security
        elif 'physical' in finding_type.lower():
            controls.append('A.11')  # Physical and Environmental Security
        
        # Operations Security
        elif 'operation' in finding_type.lower() or 'process' in finding_type.lower():
            controls.append('A.12')  # Operations Security
        
        # Communications Security
        elif 'network' in finding_type.lower() or 'communication' in finding_type.lower():
            controls.append('A.13')  # Communications Security
        
        # System Acquisition, Development and Maintenance
        elif 'development' in finding_type.lower() or 'code' in finding_type.lower():
            controls.append('A.14')  # System Acquisition, Development and Maintenance
        
        # Supplier Relationships
        elif 'supplier' in finding_type.lower() or 'third' in finding_type.lower():
            controls.append('A.15')  # Supplier Relationships
        
        # Information Security Incident Management
        elif 'incident' in finding_type.lower():
            controls.append('A.16')  # Information Security Incident Management
        
        # Information Security Aspects of Business Continuity Management
        elif 'continuity' in finding_type.lower() or 'backup' in finding_type.lower():
            controls.append('A.17')  # Information Security Aspects of Business Continuity Management
        
        # Compliance
        elif 'compliance' in finding_type.lower() or 'legal' in finding_type.lower():
            controls.append('A.18')  # Compliance
        
        return controls
    
    def get_remediation(self, finding: Dict, controls: List[str]) -> str:
        """Get ISO27001-specific remediation"""
        return f"Address ISO27001 Annex A control(s) {', '.join(controls)}. " \
               "Update Statement of Applicability if necessary."

class NISTMapper:
    """NIST SP 800-53 control mapping"""
    
    def map_control(self, finding: Dict) -> List[str]:
        """Map finding to NIST 800-53 controls"""
        controls = []
        
        finding_type = finding.get('type', '')
        
        # Access Control (AC)
        if 'access' in finding_type.lower():
            controls.append('AC-3')  # Access Enforcement
            controls.append('AC-6')  # Least Privilege
        
        # Audit and Accountability (AU)
        elif 'audit' in finding_type.lower() or 'log' in finding_type.lower():
            controls.append('AU-2')  # Event Logging
            controls.append('AU-6')  # Audit Review, Analysis, and Reporting
        
        # Configuration Management (CM)
        elif 'configuration' in finding_type.lower() or 'setting' in finding_type.lower():
            controls.append('CM-2')  # Baseline Configuration
            controls.append('CM-6')  # Configuration Settings
        
        # Identification and Authentication (IA)
        elif 'authentication' in finding_type.lower() or 'password' in finding_type.lower():
            controls.append('IA-5')  # Authenticator Management
        
        # Incident Response (IR)
        elif 'incident' in finding_type.lower():
            controls.append('IR-4')  # Incident Handling
        
        # Maintenance (MA)
        elif 'maintenance' in finding_type.lower():
            controls.append('MA-4')  # Nonlocal Maintenance
        
        # Media Protection (MP)
        elif 'media' in finding_type.lower():
            controls.append('MP-2')  # Media Access
            controls.append('MP-6')  # Media Sanitization
        
        # Physical and Environmental Protection (PE)
        elif 'physical' in finding_type.lower():
            controls.append('PE-3')  # Physical Access Control
        
        # Planning (PL)
        elif 'plan' in finding_type.lower():
            controls.append('PL-4')  # Rules of Behavior
        
        # Program Management (PM)
        elif 'program' in finding_type.lower():
            controls.append('PM-1')  # Information Security Program Plan
        
        # Personnel Security (PS)
        elif 'personnel' in finding_type.lower() or 'employee' in finding_type.lower():
            controls.append('PS-3')  # Personnel Screening
        
        # Risk Assessment (RA)
        elif 'risk' in finding_type.lower() or 'vulnerability' in finding_type.lower():
            controls.append('RA-3')  # Risk Assessment
            controls.append('RA-5')  # Vulnerability Scanning
        
        # System and Services Acquisition (SA)
        elif 'acquisition' in finding_type.lower() or 'procurement' in finding_type.lower():
            controls.append('SA-3')  # System Development Life Cycle
        
        # System and Communications Protection (SC)
        elif 'encryption' in finding_type.lower() or 'cryptography' in finding_type.lower():
            controls.append('SC-8')  # Transmission Confidentiality and Integrity
            controls.append('SC-13')  # Cryptographic Protection
        
        # System and Information Integrity (SI)
        elif 'integrity' in finding_type.lower() or 'malware' in finding_type.lower():
            controls.append('SI-3')  # Malicious Code Protection
            controls.append('SI-4')  # Information System Monitoring
        
        return controls
    
    def get_remediation(self, finding: Dict, controls: List[str]) -> str:
        """Get NIST-specific remediation"""
        return f"Address NIST SP 800-53 control(s) {', '.join(controls)}. " \
               "Update System Security Plan (SSP) accordingly."