#!/usr/bin/env python3
"""
Enterprise Compliance Mapping Engine
Maps security findings to multiple compliance frameworks
"""

from fastapi import FastAPI, HTTPException
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime
import logging
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Compliance Mapper", version="1.0.0")

class ComplianceFramework(str, Enum):
    SOC2 = "SOC2"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    ISO27001 = "ISO27001"
    NIST_800_53 = "NIST-800-53"

class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "na"

class ComplianceMapper:
    """Maps security findings to compliance controls"""
    
    def __init__(self):
        self.control_definitions = self.load_control_definitions()
        
    def load_control_definitions(self) -> Dict:
        """Load control definitions"""
        return {
            "SOC2": {
                "CC6": "Logical and Physical Access",
                "CC7": "System Operations",
                "CC8": "Change Management"
            },
            "PCI-DSS": {
                "1": "Firewall Configuration",
                "3": "Protect Stored Data",
                "6": "Secure Systems",
                "8": "Access Control"
            },
            "HIPAA": {
                "164.312(a)": "Access Control",
                "164.312(b)": "Audit Controls",
                "164.312(e)": "Transmission Security"
            }
        }
    
    def map_finding(self, finding: Dict, framework: str) -> Dict:
        """Map a finding to compliance controls"""
        finding_type = finding.get('type', '').lower()
        severity = finding.get('severity', 'medium')
        
        controls = []
        if framework == "SOC2":
            if 'access' in finding_type or 'secret' in finding_type:
                controls.append("CC6")
            elif 'vulnerability' in finding_type:
                controls.append("CC7")
            elif 'change' in finding_type:
                controls.append("CC8")
        
        elif framework == "PCI-DSS":
            if 'secret' in finding_type:
                controls.append("8")
            elif 'vulnerability' in finding_type:
                controls.append("6")
        
        status = ControlStatus.NON_COMPLIANT if severity in ['critical', 'high'] else ControlStatus.PARTIAL
        
        return {
            "framework": framework,
            "controls": controls,
            "status": status.value,
            "evidence": {
                "finding_id": finding.get('id'),
                "timestamp": datetime.now().isoformat()
            }
        }
    
    def get_compliance_score(self, framework: str, findings: List[Dict]) -> float:
        """Calculate compliance score for a framework"""
        total_controls = len(self.control_definitions.get(framework, {}))
        if total_controls == 0:
            return 100.0
        
        affected_controls = set()
        for finding in findings:
            mapping = self.map_finding(finding, framework)
            affected_controls.update(mapping['controls'])
        
        compliant_controls = total_controls - len(affected_controls)
        return (compliant_controls / total_controls) * 100

# Initialize mapper
mapper = ComplianceMapper()

@app.get("/")
async def root():
    return {
        "service": "Compliance Mapper",
        "version": "1.0.0",
        "frameworks": ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"],
        "status": "running"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/v1/compliance/map")
async def map_finding(finding: Dict, framework: str):
    """Map a finding to compliance controls"""
    try:
        result = mapper.map_finding(finding, framework)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/compliance/score/{framework}")
async def get_compliance_score(framework: str):
    """Get compliance score for a framework"""
    # Mock findings for demo
    mock_findings = [
        {"type": "access", "severity": "high", "id": "1"},
        {"type": "vulnerability", "severity": "medium", "id": "2"}
    ]
    
    try:
        score = mapper.get_compliance_score(framework, mock_findings)
        return {
            "framework": framework,
            "compliance_score": score,
            "status": "Good" if score >= 80 else "Needs Improvement",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)