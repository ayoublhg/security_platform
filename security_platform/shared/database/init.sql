-- Initialize database schema for Enterprise Security Platform

-- ============ TENANTS TABLE ============
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    max_concurrent_scans INTEGER DEFAULT 5,
    allowed_scanners JSONB DEFAULT '[]',
    scan_timeout_minutes INTEGER DEFAULT 30,
    webhook_url VARCHAR(500),
    slack_channel VARCHAR(100),
    jira_project VARCHAR(50),
    github_repos JSONB DEFAULT '[]',
    compliance_frameworks JSONB DEFAULT '[]',
    compliance_score FLOAT DEFAULT 0.0,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- ============ SCANS TABLE ============
CREATE TABLE IF NOT EXISTS scans (
    scan_id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    repo_url VARCHAR(500) NOT NULL,
    branch VARCHAR(100) DEFAULT 'main',
    scan_types JSONB DEFAULT '[]',
    depth VARCHAR(20) DEFAULT 'standard',
    status VARCHAR(20) DEFAULT 'queued',
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    findings JSONB DEFAULT '{}',
    summary JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- ============ FINDINGS TABLE ============
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) REFERENCES scans(scan_id),
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    scanner VARCHAR(50),
    finding_type VARCHAR(50),
    file_path VARCHAR(500),
    line_number INTEGER,
    code_snippet TEXT,
    cvss_score FLOAT,
    epss_score FLOAT,
    exploit_available BOOLEAN DEFAULT false,
    cisa_kev BOOLEAN DEFAULT false,
    ransomware_related BOOLEAN DEFAULT false,
    cve VARCHAR(20),
    cwe VARCHAR(20),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open',
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP,
    remediation_effort VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- ============ APPROVAL REQUESTS TABLE ============
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id VARCHAR(50) PRIMARY KEY,
    finding_id VARCHAR(36) REFERENCES findings(finding_id),
    severity VARCHAR(20),
    fix_details JSONB DEFAULT '{}',
    required_approvers JSONB DEFAULT '[]',
    approvals JSONB DEFAULT '{}',
    comments JSONB DEFAULT '[]',
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    executed_at TIMESTAMP,
    execution_result JSONB
);

-- ============ COMPLIANCE REPORTS TABLE ============
CREATE TABLE IF NOT EXISTS compliance_reports (
    report_id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    framework VARCHAR(50),
    report_type VARCHAR(20),
    report_data JSONB DEFAULT '{}',
    compliance_score FLOAT,
    total_findings INTEGER,
    critical_findings INTEGER,
    high_findings INTEGER,
    controls_passed INTEGER,
    controls_failed INTEGER,
    html_path VARCHAR(500),
    pdf_path VARCHAR(500),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    report_date TIMESTAMP
);

-- ============ REMEDIATION LOGS TABLE ============
CREATE TABLE IF NOT EXISTS remediation_logs (
    log_id VARCHAR(36) PRIMARY KEY,
    finding_id VARCHAR(36) REFERENCES findings(finding_id),
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    action_type VARCHAR(50),
    action_data JSONB DEFAULT '{}',
    status VARCHAR(20),
    result_url VARCHAR(500),
    result_id VARCHAR(100),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============ AUDIT LOGS TABLE ============
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id),
    user_id VARCHAR(100),
    action VARCHAR(100),
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(50),
    user_agent VARCHAR(500),
    status VARCHAR(20),
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============ CREATE INDEXES ============
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);

CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- ============ INSERT DEFAULT TENANT ============
INSERT INTO tenants (tenant_id, name, description, allowed_scanners, compliance_frameworks)
VALUES (
    'default',
    'Default Tenant',
    'Default tenant for development and testing',
    '["sast", "sca", "secrets", "container", "iac"]',
    '["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"]'
) ON CONFLICT (tenant_id) DO NOTHING;

-- ============ CREATE FUNCTIONS ============
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- ============ CREATE TRIGGERS ============
DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_scans_updated_at ON scans;
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_findings_updated_at ON findings;
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============ CREATE VIEWS ============
CREATE OR REPLACE VIEW vw_tenant_summary AS
SELECT 
    t.tenant_id,
    t.name,
    COUNT(DISTINCT s.scan_id) as total_scans,
    COUNT(DISTINCT f.finding_id) as total_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'critical' THEN f.finding_id END) as critical_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'high' THEN f.finding_id END) as high_findings,
    COUNT(DISTINCT CASE WHEN f.status = 'open' THEN f.finding_id END) as open_findings,
    t.compliance_score
FROM tenants t
LEFT JOIN scans s ON t.tenant_id = s.tenant_id
LEFT JOIN findings f ON t.tenant_id = f.tenant_id
GROUP BY t.tenant_id, t.name, t.compliance_score;

-- ============ GRANT PERMISSIONS ============
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;

-- ============ VERIFICATION ============
SELECT '✅ Database initialized successfully' as status;