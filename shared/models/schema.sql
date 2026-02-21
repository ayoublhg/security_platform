-- Enterprise Security Platform Database Schema

-- Tenants table
CREATE TABLE tenants (
    tenant_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    max_concurrent_scans INTEGER DEFAULT 5,
    allowed_scanners JSONB,
    webhook_url VARCHAR(500),
    slack_channel VARCHAR(100),
    jira_project VARCHAR(50),
    compliance_frameworks JSONB,
    active BOOLEAN DEFAULT true,
    settings JSONB,
    CONSTRAINT valid_tenant_id CHECK (tenant_id ~ '^[a-z0-9-]+$')
);

-- Scans table
CREATE TABLE scans (
    scan_id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    repo_url VARCHAR(500) NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    status VARCHAR(20) CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    findings JSONB,
    summary JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tenant_time (tenant_id, start_time)
);

-- Findings table with enrichment
CREATE TABLE findings (
    finding_id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) REFERENCES scans(scan_id),
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    cve_id VARCHAR(20),
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    scanner VARCHAR(50),
    file_path VARCHAR(500),
    line_number INTEGER,
    description TEXT,
    remediation TEXT,
    enriched_data JSONB,
    epss_score FLOAT,
    exploit_available BOOLEAN DEFAULT false,
    cisa_kev BOOLEAN DEFAULT false,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'fixed', 'false_positive', 'accepted_risk')),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_cve (cve_id)
);

-- Remediation tickets
CREATE TABLE remediation_tickets (
    ticket_id VARCHAR(50) PRIMARY KEY,
    finding_id VARCHAR(36) REFERENCES findings(finding_id),
    jira_key VARCHAR(20),
    pr_url VARCHAR(500),
    status VARCHAR(20) CHECK (status IN ('pending', 'approved', 'rejected', 'completed', 'failed')),
    strategy VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    completed_at TIMESTAMP,
    metadata JSONB
);

-- Compliance reports
CREATE TABLE compliance_reports (
    report_id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    framework VARCHAR(50) NOT NULL,
    report_date DATE NOT NULL,
    compliance_score FLOAT,
    findings_count INTEGER,
    controls_passed INTEGER,
    controls_failed INTEGER,
    report_data JSONB,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, framework, report_date)
);

-- Audit log
CREATE TABLE audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    user_id VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tenant_action (tenant_id, action),
    INDEX idx_time (created_at)
);

-- Create views for reporting
CREATE VIEW tenant_security_score AS
SELECT 
    t.tenant_id,
    t.name,
    COALESCE((
        SELECT AVG(compliance_score) 
        FROM compliance_reports cr 
        WHERE cr.tenant_id = t.tenant_id 
        AND cr.report_date >= CURRENT_DATE - INTERVAL '30 days'
    ), 0) as avg_compliance_score,
    COALESCE((
        SELECT COUNT(*) 
        FROM findings f 
        WHERE f.tenant_id = t.tenant_id 
        AND f.status = 'open' 
        AND f.severity IN ('critical', 'high')
    ), 0) as open_critical_findings,
    COALESCE((
        SELECT AVG(EXTRACT(EPOCH FROM (remediated_at - found_at))/3600)
        FROM findings 
        WHERE tenant_id = t.tenant_id 
        AND remediated_at IS NOT NULL
    ), 0) as avg_mttr_hours
FROM tenants t;

-- Create materialized view for performance
CREATE MATERIALIZED VIEW mv_daily_metrics AS
SELECT 
    DATE(start_time) as scan_date,
    tenant_id,
    COUNT(*) as total_scans,
    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_scans,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_scans,
    SUM((summary->>'critical')::int) as total_critical,
    SUM((summary->>'high')::int) as total_high
FROM scans
WHERE start_time >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY DATE(start_time), tenant_id;

-- Create indexes for performance
CREATE INDEX idx_findings_tenant_severity ON findings(tenant_id, severity) WHERE status = 'open';
CREATE INDEX idx_scans_tenant_completed ON scans(tenant_id) WHERE status = 'completed';
CREATE INDEX idx_audit_time ON audit_log(created_at DESC);

-- Add full text search for findings
CREATE INDEX idx_findings_fts ON findings USING gin(to_tsvector('english', description));