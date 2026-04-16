-- ============================================
-- ENTERPRISE SECURITY PLATFORM - SCHEMA SQL
-- ============================================

-- ============ EXTENSIONS ============
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

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
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP,
    settings JSONB DEFAULT '{}'
);

-- ============ SCANS TABLE ============
CREATE TABLE IF NOT EXISTS scans (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    scan_name VARCHAR(200),
    repo_url VARCHAR(500) NOT NULL,
    repo_branch VARCHAR(100) DEFAULT 'main',
    scan_types JSONB NOT NULL DEFAULT '["sast"]',
    scan_depth VARCHAR(20) DEFAULT 'standard',
    status VARCHAR(20) DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'medium',
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (completed_at - started_at))) STORED,
    findings_summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0,"total":0}',
    raw_results JSONB,
    metadata JSONB DEFAULT '{}',
    error_message TEXT,
    triggered_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============ FINDINGS TABLE ============
CREATE TABLE IF NOT EXISTS findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    scanner_name VARCHAR(100) NOT NULL,
    finding_type VARCHAR(50) NOT NULL,
    file_path VARCHAR(500),
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    cve_id VARCHAR(20),
    cwe_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),
    exploit_available BOOLEAN DEFAULT false,
    cisa_kev BOOLEAN DEFAULT false,
    ransomware_related BOOLEAN DEFAULT false,
    has_patch BOOLEAN DEFAULT false,
    fix_version VARCHAR(100),
    remediation_advice TEXT,
    remediation_effort VARCHAR(20),
    status VARCHAR(20) DEFAULT 'open',
    status_changed_at TIMESTAMP WITH TIME ZONE,
    fixed_at TIMESTAMP WITH TIME ZONE,
    fix_commit_url VARCHAR(500),
    metadata JSONB DEFAULT '{}',
    tags TEXT[],
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============ APPROVAL REQUESTS TABLE ============
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    request_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    fix_details JSONB,
    required_approvers JSONB NOT NULL DEFAULT '[]',
    current_approvers JSONB DEFAULT '[]',
    approvals JSONB DEFAULT '{}',
    comments JSONB DEFAULT '[]',
    status VARCHAR(20) DEFAULT 'pending',
    decision_comment TEXT,
    decided_by VARCHAR(100),
    decided_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    execution_status VARCHAR(20),
    execution_result JSONB,
    executed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

-- ============ COMPLIANCE REPORTS TABLE ============
CREATE TABLE IF NOT EXISTS compliance_reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    report_name VARCHAR(200) NOT NULL,
    framework VARCHAR(50) NOT NULL,
    report_type VARCHAR(20),
    report_date DATE NOT NULL DEFAULT CURRENT_DATE,
    period_start DATE,
    period_end DATE,
    compliance_score DECIMAL(5,2),
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    controls_passed INTEGER DEFAULT 0,
    controls_failed INTEGER DEFAULT 0,
    controls_not_applicable INTEGER DEFAULT 0,
    report_data JSONB NOT NULL DEFAULT '{}',
    executive_summary TEXT,
    recommendations TEXT,
    html_report_path VARCHAR(500),
    pdf_report_path VARCHAR(500),
    json_report_path VARCHAR(500),
    generated_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============ REMEDIATION LOGS TABLE ============
CREATE TABLE IF NOT EXISTS remediation_logs (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    tenant_id VARCHAR(50) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    action_status VARCHAR(20) NOT NULL,
    integration_type VARCHAR(50),
    integration_id VARCHAR(200),
    integration_url VARCHAR(500),
    action_data JSONB NOT NULL DEFAULT '{}',
    result_data JSONB,
    error_message TEXT,
    performed_by VARCHAR(100),
    automated BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============ AUDIT LOGS TABLE ============
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    event_action VARCHAR(100) NOT NULL,
    user_id VARCHAR(100),
    user_email VARCHAR(200),
    user_role VARCHAR(50),
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    resource_name VARCHAR(500),
    request_id VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    request_path VARCHAR(500),
    request_method VARCHAR(10),
    response_status INTEGER,
    details JSONB,
    changes JSONB,
    error_details TEXT,
    status VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============ METRICS TABLE ============
CREATE TABLE IF NOT EXISTS metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL NOT NULL,
    metric_unit VARCHAR(20),
    dimensions JSONB DEFAULT '{}',
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============ INDEXES ============
CREATE INDEX IF NOT EXISTS idx_scans_tenant_status ON scans(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_queued_at ON scans(queued_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_scans_repo_url ON scans(repo_url);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity ON findings(tenant_id, severity) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON findings(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_requests_finding ON approval_requests(finding_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_time ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_tenant_name_time ON metrics(tenant_id, metric_name, recorded_at DESC);

-- ============ FUNCTIONS ============
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE OR REPLACE FUNCTION update_status_changed_at()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        NEW.status_changed_at = CURRENT_TIMESTAMP;
        IF NEW.status = 'fixed' AND OLD.status != 'fixed' THEN
            NEW.fixed_at = CURRENT_TIMESTAMP;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- ============ TRIGGERS ============
DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_scans_updated_at ON scans;
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_findings_updated_at ON findings;
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_findings_status_changed ON findings;
CREATE TRIGGER update_findings_status_changed BEFORE UPDATE OF status ON findings
    FOR EACH ROW EXECUTE FUNCTION update_status_changed_at();

DROP TRIGGER IF EXISTS update_approval_requests_updated_at ON approval_requests;
CREATE TRIGGER update_approval_requests_updated_at BEFORE UPDATE ON approval_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============ DEFAULT DATA ============
INSERT INTO tenants (tenant_id, name, description, allowed_scanners, compliance_frameworks, settings)
VALUES (
    'default',
    'Default Tenant',
    'Default tenant for development and testing',
    '["sast", "sca", "secrets"]',
    '["SOC2", "PCI-DSS", "ISO27001"]',
    '{"notifications": {"email": false, "slack": false}}'
) ON CONFLICT (tenant_id) DO NOTHING;

-- ============ VERIFICATION ============
SELECT '✅ Database schema created successfully' as status;