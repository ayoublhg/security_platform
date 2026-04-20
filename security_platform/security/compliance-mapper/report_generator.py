#!/usr/bin/env python3
"""
Compliance Report Generator
Generates PDF/HTML reports for compliance audits
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import os
import html
import weasyprint
from jinja2 import Template

logger = logging.getLogger(__name__)

class ComplianceReportGenerator:
    """Generates compliance reports for various frameworks"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        self.report_templates = {
            'soc2': self._generate_soc2_report,
            'pci': self._generate_pci_report,
            'hipaa': self._generate_hipaa_report,
            'iso27001': self._generate_iso_report,
            'nist': self._generate_nist_report,
            'executive': self._generate_executive_report
        }
        
    async def generate_report(self, report_type: str, data: Dict) -> Dict:
        """Generate a compliance report"""
        if report_type not in self.report_templates:
            raise ValueError(f"Unknown report type: {report_type}")
        
        generator = self.report_templates[report_type]
        report_data = await generator(data)
        
        # Generate HTML
        html_content = await self._render_html(report_type, report_data)
        
        # Save files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_id = f"{report_type}_{timestamp}"
        
        # Save HTML
        html_path = os.path.join(self.output_dir, f"{report_id}.html")
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        # Generate PDF
        pdf_path = os.path.join(self.output_dir, f"{report_id}.pdf")
        weasyprint.HTML(string=html_content).write_pdf(pdf_path)
        
        return {
            'report_id': report_id,
            'report_type': report_type,
            'generated_at': datetime.now().isoformat(),
            'html_path': html_path,
            'pdf_path': pdf_path,
            'summary': report_data.get('summary', {}),
            'data': report_data
        }
    
    async def _generate_soc2_report(self, data: Dict) -> Dict:
        """Generate SOC2 report"""
        findings = data.get('findings', [])
        tenant_info = data.get('tenant', {})
        
        # Group findings by control
        controls_affected = {}
        for finding in findings:
            mapping = finding.get('compliance', {}).get('SOC2', {})
            for control in mapping.get('controls', []):
                if control not in controls_affected:
                    controls_affected[control] = []
                controls_affected[control].append(finding)
        
        # Calculate compliance by control
        control_status = {}
        for control, ctrl_findings in controls_affected.items():
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            for f in ctrl_findings:
                sev = f.get('severity', 'low')
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            status = 'non_compliant' if severity_counts['critical'] > 0 or severity_counts['high'] > 0 else 'compliant'
            control_status[control] = {
                'findings_count': len(ctrl_findings),
                'severity_breakdown': severity_counts,
                'status': status
            }
        
        return {
            'title': 'SOC2 Trust Services Criteria Compliance Report',
            'framework': 'SOC2',
            'tenant': tenant_info,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(findings),
                'controls_affected': len(controls_affected),
                'compliant_controls': sum(1 for s in control_status.values() if s['status'] == 'compliant'),
                'non_compliant_controls': sum(1 for s in control_status.values() if s['status'] == 'non_compliant')
            },
            'control_details': control_status,
            'findings': findings
        }
    
    async def _generate_pci_report(self, data: Dict) -> Dict:
        """Generate PCI-DSS report"""
        findings = data.get('findings', [])
        tenant_info = data.get('tenant', {})
        
        # Group by requirement
        requirements_affected = {}
        for finding in findings:
            mapping = finding.get('compliance', {}).get('PCI-DSS', {})
            for req in mapping.get('requirements', []):
                if req not in requirements_affected:
                    requirements_affected[req] = []
                requirements_affected[req].append(finding)
        
        return {
            'title': 'PCI-DSS Compliance Report',
            'framework': 'PCI-DSS',
            'tenant': tenant_info,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(findings),
                'requirements_affected': len(requirements_affected),
                'cardholder_data_environment': self._assess_cde_impact(findings)
            },
            'requirement_details': requirements_affected,
            'findings': findings
        }
    
    async def _generate_hipaa_report(self, data: Dict) -> Dict:
        """Generate HIPAA report"""
        findings = data.get('findings', [])
        tenant_info = data.get('tenant', {})
        
        # Check for PHI-related findings
        phi_findings = [f for f in findings if f.get('compliance', {}).get('HIPAA', {}).get('phi_related')]
        
        return {
            'title': 'HIPAA Security Rule Compliance Report',
            'framework': 'HIPAA',
            'tenant': tenant_info,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(findings),
                'phi_related_findings': len(phi_findings),
                'breach_risk': 'HIGH' if len(phi_findings) > 0 else 'LOW'
            },
            'phi_findings': phi_findings,
            'all_findings': findings
        }
    
    async def _generate_iso_report(self, data: Dict) -> Dict:
        """Generate ISO27001 report"""
        findings = data.get('findings', [])
        tenant_info = data.get('tenant', {})
        
        # Group by Annex
        annex_affected = {}
        for finding in findings:
            mapping = finding.get('compliance', {}).get('ISO27001', {})
            for annex, info in mapping.get('controls', {}).items():
                if annex not in annex_affected:
                    annex_affected[annex] = {
                        'name': info.get('name', ''),
                        'findings': []
                    }
                annex_affected[annex]['findings'].append(finding)
        
        return {
            'title': 'ISO27001 Compliance Report',
            'framework': 'ISO27001',
            'tenant': tenant_info,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(findings),
                'annexes_affected': len(annex_affected),
                'statement_of_applicability_updates': self._get_soa_updates(annex_affected)
            },
            'annex_details': annex_affected,
            'findings': findings
        }
    
    async def _generate_nist_report(self, data: Dict) -> Dict:
        """Generate NIST report"""
        findings = data.get('findings', [])
        tenant_info = data.get('tenant', {})
        impact_level = data.get('impact_level', 'MODERATE')
        
        # Group by control family
        families_affected = {}
        for finding in findings:
            mapping = finding.get('compliance', {}).get('NIST SP 800-53', {})
            for family, info in mapping.get('families', {}).items():
                if family not in families_affected:
                    families_affected[family] = {
                        'name': info.get('name', ''),
                        'controls': {}
                    }
                for control in info.get('controls', []):
                    ctrl_id = control['id']
                    if ctrl_id not in families_affected[family]['controls']:
                        families_affected[family]['controls'][ctrl_id] = {
                            'name': control['name'],
                            'findings': []
                        }
                    families_affected[family]['controls'][ctrl_id]['findings'].append(finding)
        
        return {
            'title': 'NIST SP 800-53 Compliance Report',
            'framework': 'NIST SP 800-53',
            'impact_level': impact_level,
            'tenant': tenant_info,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(findings),
                'families_affected': len(families_affected),
                'controls_affected': sum(len(f['controls']) for f in families_affected.values()),
                'impact_level': impact_level
            },
            'family_details': families_affected,
            'findings': findings
        }
    
    async def _generate_executive_report(self, data: Dict) -> Dict:
        """Generate executive summary report"""
        findings = data.get('findings', [])
        tenant_info = data.get('tenant', {})
        
        # Overall metrics
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            sev = f.get('severity', 'low')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Compliance scores
        compliance_scores = {}
        frameworks = ['SOC2', 'PCI-DSS', 'HIPAA', 'ISO27001', 'NIST SP 800-53']
        
        for framework in frameworks:
            framework_findings = [
                f for f in findings 
                if framework in f.get('compliance', {})
            ]
            
            if framework_findings:
                score = max(0, 100 - (len(framework_findings) * 5))
                compliance_scores[framework] = min(score, 100)
            else:
                compliance_scores[framework] = 100
        
        # Remediation metrics
        remediated = data.get('remediated_count', 0)
        open_findings = len(findings)
        
        return {
            'title': 'Executive Security Summary',
            'tenant': tenant_info,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_findings': open_findings,
                'remediated': remediated,
                'open_findings': open_findings,
                'severity_breakdown': severity_counts,
                'compliance_scores': compliance_scores,
                'security_posture': self._calculate_posture(severity_counts)
            },
            'risk_trend': data.get('trend', []),
            'remediation_metrics': {
                'mean_time_to_remediate': data.get('mttr', 0),
                'remediation_rate': data.get('remediation_rate', 0)
            }
        }
    
    async def _render_html(self, report_type: str, data: Dict) -> str:
        """Render report as HTML"""
        template = self._get_html_template(report_type)
        
        # Add common styling
        css = """
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            h2 { color: #34495e; margin-top: 30px; }
            .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .stat { display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .critical { color: #e74c3c; }
            .high { color: #e67e22; }
            .medium { color: #f1c40f; }
            .low { color: #27ae60; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th { background: #3498db; color: white; padding: 10px; text-align: left; }
            td { padding: 10px; border-bottom: 1px solid #bdc3c7; }
            .footer { margin-top: 50px; font-size: 0.8em; color: #7f8c8d; text-align: center; }
        </style>
        """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{data.get('title', 'Compliance Report')}</title>
            {css}
        </head>
        <body>
            <h1>{data.get('title', 'Compliance Report')}</h1>
            <p>Generated: {data.get('generated_at', '')}</p>
            <p>Tenant: {data.get('tenant', {}).get('name', 'N/A')}</p>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                {self._render_summary_html(data.get('summary', {}))}
            </div>
            
            {template(data)}
            
            <div class="footer">
                <p>Generated by Enterprise Security Platform</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _render_summary_html(self, summary: Dict) -> str:
        """Render summary section as HTML"""
        html = '<div style="display: flex; flex-wrap: wrap;">'
        
        for key, value in summary.items():
            if isinstance(value, dict):
                continue
            html += f'<div class="stat"><strong>{key.replace("_", " ").title()}:</strong> {value}</div>'
        
        # Add severity breakdown if present
        if 'severity_breakdown' in summary:
            sev = summary['severity_breakdown']
            html += '<div style="margin-top: 20px; width: 100%;">'
            html += '<h3>Findings by Severity</h3>'
            html += f'<span class="critical">Critical: {sev.get("critical", 0)}</span> | '
            html += f'<span class="high">High: {sev.get("high", 0)}</span> | '
            html += f'<span class="medium">Medium: {sev.get("medium", 0)}</span> | '
            html += f'<span class="low">Low: {sev.get("low", 0)}</span>'
            html += '</div>'
        
        html += '</div>'
        return html
    
    def _get_html_template(self, report_type: str) -> callable:
        """Get HTML template function for report type"""
        templates = {
            'soc2': self._soc2_html,
            'pci': self._pci_html,
            'hipaa': self._hipaa_html,
            'iso27001': self._iso_html,
            'nist': self._nist_html,
            'executive': self._executive_html
        }
        return templates.get(report_type, lambda x: '')
    
    def _soc2_html(self, data: Dict) -> str:
        """SOC2 HTML template"""
        html = '<h2>SOC2 Trust Services Criteria</h2>'
        html += '<table><tr><th>Control</th><th>Status</th><th>Findings</th></tr>'
        
        for control, details in data.get('control_details', {}).items():
            html += f'<tr>'
            html += f'<td>{control}</td>'
            html += f'<td>{details.get("status", "unknown")}</td>'
            html += f'<td>{details.get("findings_count", 0)}</td>'
            html += f'</tr>'
        
        html += '</table>'
        return html
    
    def _pci_html(self, data: Dict) -> str:
        """PCI HTML template"""
        html = '<h2>PCI-DSS Requirements</h2>'
        html += '<table><tr><th>Requirement</th><th>Findings</th></tr>'
        
        for req, findings in data.get('requirement_details', {}).items():
            html += f'<tr><td>Requirement {req}</td><td>{len(findings)}</td></tr>'
        
        html += '</table>'
        return html
    
    def _hipaa_html(self, data: Dict) -> str:
        """HIPAA HTML template"""
        html = '<h2>HIPAA Security Rule</h2>'
        html += f'<p>PHI-Related Findings: {len(data.get("phi_findings", []))}</p>'
        
        if data.get('phi_findings'):
            html += '<h3>PHI-Related Findings</h3>'
            html += '<ul>'
            for f in data['phi_findings']:
                html += f'<li>{f.get("title", "")} - {f.get("severity", "")}</li>'
            html += '</ul>'
        
        return html
    
    def _iso_html(self, data: Dict) -> str:
        """ISO HTML template"""
        html = '<h2>ISO27001 Annex A</h2>'
        html += '<table><tr><th>Annex</th><th>Findings</th></tr>'
        
        for annex, details in data.get('annex_details', {}).items():
            html += f'<tr><td>{annex}: {details.get("name", "")}</td>'
            html += f'<td>{len(details.get("findings", []))}</td></tr>'
        
        html += '</table>'
        return html
    
    def _nist_html(self, data: Dict) -> str:
        """NIST HTML template"""
        html = '<h2>NIST SP 800-53 Controls</h2>'
        html += f'<p>Impact Level: {data.get("impact_level", "MODERATE")}</p>'
        
        for family, details in data.get('family_details', {}).items():
            html += f'<h3>{family}: {details.get("name", "")}</h3>'
            html += '<table><tr><th>Control</th><th>Findings</th></tr>'
            
            for control, ctrl_details in details.get('controls', {}).items():
                html += f'<tr><td>{control}</td><td>{len(ctrl_details.get("findings", []))}</td></tr>'
            
            html += '</table>'
        
        return html
    
    def _executive_html(self, data: Dict) -> str:
        """Executive summary HTML template"""
        html = '<h2>Security Posture Overview</h2>'
        
        summary = data.get('summary', {})
        
        html += '<div style="display: flex;">'
        html += f'<div class="stat"><strong>Security Posture:</strong> {summary.get("security_posture", "Unknown")}</div>'
        html += '</div>'
        
        # Compliance scores
        html += '<h3>Compliance Scores</h3>'
        html += '<table><tr><th>Framework</th><th>Score</th></tr>'
        for framework, score in summary.get('compliance_scores', {}).items():
            html += f'<tr><td>{framework}</td><td>{score}%</td></tr>'
        html += '</table>'
        
        # Remediation metrics
        html += '<h3>Remediation Metrics</h3>'
        metrics = data.get('remediation_metrics', {})
        html += f'<p>Mean Time to Remediate: {metrics.get("mean_time_to_remediate", 0)} hours</p>'
        html += f'<p>Remediation Rate: {metrics.get("remediation_rate", 0)}%</p>'
        
        return html
    
    def _assess_cde_impact(self, findings: List[Dict]) -> str:
        """Assess impact on cardholder data environment"""
        cde_indicators = ['cardholder', 'pan', 'cvv', 'pci', 'payment']
        
        for finding in findings:
            text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
            if any(ind in text for ind in cde_indicators):
                return 'IMPACTED'
        
        return 'NOT IMPACTED'
    
    def _get_soa_updates(self, annex_affected: Dict) -> List[str]:
        """Get Statement of Applicability updates"""
        updates = []
        for annex, info in annex_affected.items():
            updates.append(f"Update SoA for {annex}: {len(info.get('findings', []))} findings identified")
        return updates
    
    def _calculate_posture(self, severity_counts: Dict) -> str:
        """Calculate overall security posture"""
        if severity_counts.get('critical', 0) > 0:
            return 'CRITICAL'
        elif severity_counts.get('high', 0) > 5:
            return 'POOR'
        elif severity_counts.get('high', 0) > 0:
            return 'FAIR'
        elif severity_counts.get('medium', 0) > 10:
            return 'GOOD'
        else:
            return 'EXCELLENT'