#!/usr/bin/env python3
"""
SQLAlchemy models for the Enterprise Security Platform
"""

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Boolean, JSON, 
    ForeignKey, Text, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

class Tenant(Base):
    """Multi-tenant configuration"""
    __tablename__ = 'tenants'
    
    tenant_id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Configuration
    max_concurrent_scans = Column(Integer, default=5)
    allowed_scanners = Column(JSON, default=list)
    scan_timeout_minutes = Column(Integer, default=30)
    
    # Integrations
    webhook_url = Column(String(500))
    slack_channel = Column(String(100))
    jira_project = Column(String(50))
    github_repos = Column(JSON, default=list)
    
    # Compliance
    compliance_frameworks = Column(JSON, default=list)
    compliance_score = Column(Float, default=0.0)
    
    # Status
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    scans = relationship("Scan", back_populates="tenant")
    findings = relationship("Finding", back_populates="tenant")
    compliance_reports = relationship("ComplianceReport", back_populates="tenant")
    
    def __repr__(self):
        return f"<Tenant {self.tenant_id}: {self.name}>"


class Scan(Base):
    """Security scan record"""
    __tablename__ = 'scans'
    
    scan_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(50), ForeignKey('tenants.tenant_id'))
    
    # Scan details
    repo_url = Column(String(500), nullable=False)
    branch = Column(String(100), default='main')
    scan_types = Column(JSON, default=list)
    depth = Column(String(20), default='standard')
    
    # Status
    status = Column(String(20), default='queued')  # queued, running, completed, failed
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration_seconds = Column(Integer)
    
    # Results
    findings = Column(JSON, default=dict)
    summary = Column(JSON, default=dict)
    metadata = Column(JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="scans")
    scan_findings = relationship("Finding", back_populates="scan")
    
    def __repr__(self):
        return f"<Scan {self.scan_id}: {self.status}>"


class Finding(Base):
    """Security finding/vulnerability"""
    __tablename__ = 'findings'
    
    finding_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.scan_id'))
    tenant_id = Column(String(50), ForeignKey('tenants.tenant_id'))
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20))  # critical, high, medium, low, info
    scanner = Column(String(50))   # semgrep, snyk, gitleaks, etc.
    finding_type = Column(String(50))  # sast, sca, secret, container, iac
    
    # Location
    file_path = Column(String(500))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    
    # Enrichment
    cvss_score = Column(Float)
    epss_score = Column(Float)
    exploit_available = Column(Boolean, default=False)
    cisa_kev = Column(Boolean, default=False)
    ransomware_related = Column(Boolean, default=False)
    
    # Metadata
    cve = Column(String(20))
    cwe = Column(String(20))
    metadata = Column(JSON, default=dict)
    
    # Status
    status = Column(String(20), default='open')  # open, in_progress, fixed, false_positive, accepted_risk
    found_at = Column(DateTime, default=datetime.utcnow)
    remediated_at = Column(DateTime)
    remediation_effort = Column(String(50))  # easy, medium, hard
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="scan_findings")
    tenant = relationship("Tenant", back_populates="findings")
    approval_request = relationship("ApprovalRequest", uselist=False, back_populates="finding")
    
    def __repr__(self):
        return f"<Finding {self.finding_id}: {self.severity} - {self.title[:50]}>"


class ApprovalRequest(Base):
    """Approval request for remediation"""
    __tablename__ = 'approval_requests'
    
    request_id = Column(String(50), primary_key=True)
    finding_id = Column(String(36), ForeignKey('findings.finding_id'))
    
    # Request details
    severity = Column(String(20))
    fix_details = Column(JSON, default=dict)
    required_approvers = Column(JSON, default=list)
    approvals = Column(JSON, default=dict)
    comments = Column(JSON, default=list)
    
    # Status
    status = Column(String(20), default='pending')  # pending, partially_approved, approved, rejected, expired
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    executed_at = Column(DateTime)
    execution_result = Column(JSON)
    
    # Relationships
    finding = relationship("Finding", back_populates="approval_request")
    
    def __repr__(self):
        return f"<ApprovalRequest {self.request_id}: {self.status}>"


class ComplianceReport(Base):
    """Compliance report record"""
    __tablename__ = 'compliance_reports'
    
    report_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(50), ForeignKey('tenants.tenant_id'))
    
    # Report details
    framework = Column(String(50))  # SOC2, PCI-DSS, HIPAA, ISO27001, NIST
    report_type = Column(String(20))  # executive, detailed, audit
    report_data = Column(JSON, default=dict)
    
    # Metrics
    compliance_score = Column(Float)
    total_findings = Column(Integer)
    critical_findings = Column(Integer)
    high_findings = Column(Integer)
    controls_passed = Column(Integer)
    controls_failed = Column(Integer)
    
    # File paths
    html_path = Column(String(500))
    pdf_path = Column(String(500))
    
    # Timestamps
    generated_at = Column(DateTime, default=datetime.utcnow)
    report_date = Column(DateTime)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="compliance_reports")
    
    def __repr__(self):
        return f"<ComplianceReport {self.report_id}: {self.framework}>"


class RemediationLog(Base):
    """Log of remediation actions"""
    __tablename__ = 'remediation_logs'
    
    log_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey('findings.finding_id'))
    tenant_id = Column(String(50), ForeignKey('tenants.tenant_id'))
    
    # Action details
    action_type = Column(String(50))  # pr_created, ticket_created, comment_added, fix_applied
    action_data = Column(JSON, default=dict)
    status = Column(String(20))  # success, failed, pending
    
    # Results
    result_url = Column(String(500))  # PR URL, ticket URL
    result_id = Column(String(100))   # PR number, ticket key
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<RemediationLog {self.log_id}: {self.action_type}>"


class AuditLog(Base):
    """Audit trail for all actions"""
    __tablename__ = 'audit_logs'
    
    log_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(50), ForeignKey('tenants.tenant_id'))
    user_id = Column(String(100))
    
    # Action
    action = Column(String(100))
    resource_type = Column(String(50))  # scan, finding, tenant, report
    resource_id = Column(String(100))
    
    # Details
    details = Column(JSON, default=dict)
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    
    # Result
    status = Column(String(20))  # success, failure
    error = Column(Text)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<AuditLog {self.log_id}: {self.action}>"