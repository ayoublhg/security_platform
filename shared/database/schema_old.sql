#!/usr/bin/env python3
"""
Database seeding script for development and testing
Matches the exact schema from schema.sql
"""

import asyncio
import logging
from datetime import datetime, timedelta
import random
import uuid
import asyncpg
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def seed_database(pool):
    """Seed database with test data"""
    logger.info("Seeding database with test data...")
    
    try:
        # Create test tenant
        tenant = await seed_tenant(pool)
        
        # Create test scans
        scans = await seed_scans(pool, tenant['tenant_id'])
        
        # Create test findings
        await seed_findings(pool, tenant['tenant_id'], scans)
        
        # Create compliance reports
        await seed_compliance_reports(pool, tenant['tenant_id'])
        
        logger.info("✅ Database seeding completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Error seeding database: {e}")
        raise

async def seed_tenant(pool):
    """Create a test tenant"""
    tenant_id = "test-tenant"
    
    async with pool.acquire() as conn:
        # Check if exists
        existing = await conn.fetchval(
            "SELECT tenant_id FROM tenants WHERE tenant_id = $1",
            tenant_id
        )
        
        if existing:
            logger.info(f"Tenant {tenant_id} already exists")
            return {'tenant_id': tenant_id}
        
        # Create tenant
        await conn.execute("""
            INSERT INTO tenants (
                tenant_id, name, description, max_concurrent_scans,
                allowed_scanners, scan_timeout_minutes, webhook_url, slack_channel,
                jira_project, github_repos, compliance_frameworks,
                compliance_score, settings, active, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
        """,
            tenant_id,
            "Test Tenant",
            "Tenant for development and testing",
            10,
            json.dumps(['sast', 'sca', 'secrets', 'container', 'iac']),
            30,
            "https://webhook.example.com/test",
            "#security-test",
            "TEST",
            json.dumps(['test-org/repo1', 'test-org/repo2']),
            json.dumps(['SOC2', 'PCI-DSS', 'ISO27001']),
            85.5,
            json.dumps({'notifications': {'email': True, 'slack': True}}),
            True
        )
        
        logger.info(f"✅ Created tenant {tenant_id}")
        return {'tenant_id': tenant_id}

async def seed_scans(pool, tenant_id, count=10):
    """Create test scans - FIXED to match schema.sql exactly"""
    scans = []
    
    async with pool.acquire() as conn:
        for i in range(count):
            scan_id = uuid.uuid4()
            start_time = datetime.now() - timedelta(days=random.randint(0, 30))
            
            # Random status
            status = random.choice(['completed', 'completed', 'completed', 'failed', 'running'])
            
            # Calculate timings
            queued_at = start_time - timedelta(minutes=random.randint(1, 5))
            started_at = start_time
            completed_at = start_time + timedelta(minutes=random.randint(2, 15)) if status == 'completed' else None
            
            # Random priority
            priority = random.choice(['low', 'medium', 'high', 'critical'])
            
            # Generate summary
            critical = random.randint(0, 5)
            high = random.randint(0, 10)
            medium = random.randint(0, 20)
            low = random.randint(0, 30)
            
            findings_summary = {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': random.randint(0, 10),
                'total': critical + high + medium + low
            }
            
            # FIXED: Using correct column names from schema.sql
            await conn.execute("""
                INSERT INTO scans (
                    scan_id, tenant_id, scan_name, repo_url, repo_branch,
                    scan_types, scan_depth, status, priority,
                    queued_at, started_at, completed_at,
                    findings_summary, metadata, triggered_by, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            """,
                scan_id,
                tenant_id,
                f"Scan {i+1}: Test Repository",
                f"https://github.com/test-org/repo{i}.git",
                "main",
                json.dumps(['sast', 'sca', 'secrets']),
                random.choice(['quick', 'standard', 'deep']),
                status,
                priority,
                queued_at,
                started_at,
                completed_at,
                json.dumps(findings_summary),
                json.dumps({'test': True, 'source': 'seed'}),
                "seed-script",
                start_time
            )
            
            scans.append(str(scan_id))
            
            if i % 10 == 0 and i > 0:
                logger.info(f"Created {i} scans")
    
    logger.info(f"✅ Created {len(scans)} scans")
    return scans

async def seed_findings(pool, tenant_id, scans, count=50):
    """Create test findings - FIXED to match schema.sql exactly"""
    severities = ['critical', 'high', 'medium', 'low', 'info']
    scanners = ['semgrep', 'snyk', 'gitleaks', 'trivy', 'checkov']
    types = ['sast', 'sca', 'secret', 'container', 'iac', 'dast']
    statuses = ['open', 'open', 'open', 'fixed', 'false_positive', 'accepted_risk']
    efforts = ['easy', 'medium', 'hard', 'unknown']
    
    async with pool.acquire() as conn:
        for i in range(count):
            finding_id = uuid.uuid4()
            scan_id = random.choice(scans) if scans else None
            severity = random.choice(severities)
            
            # Calculate dates
            detected_at = datetime.now() - timedelta(days=random.randint(0, 60))
            fixed_at = None
            status = random.choice(statuses)
            
            if status == 'fixed':
                fixed_at = detected_at + timedelta(days=random.randint(1, 30))
            
            # CVE and CWE
            cve_id = f"CVE-2024-{random.randint(1000, 9999)}" if random.choice([True, False]) else None
            cwe_id = f"CWE-{random.randint(79, 89)}" if random.choice([True, False]) else None
            
            # CVSS score based on severity
            cvss_map = {
                'critical': random.uniform(9.0, 10.0),
                'high': random.uniform(7.0, 8.9),
                'medium': random.uniform(4.0, 6.9),
                'low': random.uniform(0.1, 3.9),
                'info': 0.0
            }
            cvss = cvss_map[severity]
            
            # EPSS score
            epss = random.uniform(0.1, 0.9) if severity in ['critical', 'high'] else random.uniform(0.01, 0.3)
            
            # Titles based on severity
            titles = {
                'critical': [
                    'Critical SQL Injection Vulnerability',
                    'Remote Code Execution in Authentication Module',
                    'Authentication Bypass in Admin Panel'
                ],
                'high': [
                    'Cross-Site Scripting (XSS) in User Input',
                    'Insecure Direct Object Reference (IDOR)',
                    'CSRF Vulnerability in Form Submission'
                ],
                'medium': [
                    'Information Disclosure in Error Messages',
                    'Weak Password Policy Configuration',
                    'Missing Security Headers'
                ],
                'low': [
                    'Information Leakage in Comments',
                    'Deprecated Function Usage',
                    'Code Smell: Duplicate Code'
                ],
                'info': [
                    'Debug Mode Enabled',
                    'Verbose Error Messages',
                    'Outdated Comments in Code'
                ]
            }
            
            title = random.choice(titles.get(severity, ['Security Finding']))
            
            # File path
            file_path = f"src/{random.choice(['app', 'models', 'controllers', 'views', 'utils'])}/file{random.randint(1, 20)}.py"
            line_start = random.randint(1, 500)
            
            # FIXED: Using correct column names from schema.sql
            await conn.execute("""
                INSERT INTO findings (
                    finding_id, scan_id, tenant_id, title, description,
                    severity, scanner_name, finding_type,
                    file_path, line_start, line_end, code_snippet,
                    cve_id, cwe_id, cvss_score, epss_score,
                    exploit_available, cisa_kev, ransomware_related, has_patch,
                    fix_version, remediation_advice, remediation_effort,
                    status, status_changed_at, fixed_at, fix_commit_url,
                    metadata, tags, detected_at, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16, $17, $18, $19, $20,
                         $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, NOW())
            """,
                finding_id,
                uuid.UUID(scan_id) if scan_id else None,
                tenant_id,
                f"{title} - {severity.upper()}",
                f"This is a test {severity} severity finding detected by {random.choice(scanners)}. "
                f"The vulnerability affects authentication mechanisms and could lead to data exposure.",
                severity,
                random.choice(scanners),
                random.choice(types),
                file_path,
                line_start,
                line_start + random.randint(1, 10) if random.choice([True, False]) else None,
                "def vulnerable_function():\n    return eval(user_input)",
                cve_id,
                cwe_id,
                round(cvss, 1),
                round(epss, 4),
                random.choice([True, False]) if severity in ['critical', 'high'] else False,
                random.choice([True, False]) if severity == 'critical' else False,
                random.choice([True, False]) if severity in ['critical', 'high'] else False,
                random.choice([True, False]),
                f"2.{random.randint(0, 5)}.{random.randint(0, 9)}" if random.choice([True, False]) else None,
                f"Update to the latest version and implement input validation.",
                random.choice(efforts),
                status,
                detected_at if status != 'open' else None,
                fixed_at,
                f"https://github.com/test-org/repo/commit/{uuid.uuid4().hex[:8]}" if fixed_at else None,
                json.dumps({
                    'references': ['https://example.com/cve', 'https://nvd.nist.gov'],
                    'tags': [severity, random.choice(types)],
                    'cvss_vector': f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }),
                [severity, random.choice(types), 'test'],
                detected_at
            )
            
            if i % 50 == 0 and i > 0:
                logger.info(f"Created {i} findings")
    
    logger.info(f"✅ Created {count} findings")
    return count

async def seed_compliance_reports(pool, tenant_id):
    """Create test compliance reports - FIXED to match schema.sql exactly"""
    frameworks = ['SOC2', 'PCI-DSS', 'HIPAA', 'ISO27001', 'NIST-800-53']
    report_types = ['executive', 'detailed', 'audit', 'gap']
    
    async with pool.acquire() as conn:
        for framework in frameworks:
            for days_ago in [7, 14, 30, 60, 90]:
                report_date = datetime.now() - timedelta(days=days_ago)
                report_id = uuid.uuid4()
                
                # Random compliance score that improves over time
                base_score = 70 + (90 - days_ago) * 0.3
                score = min(100, max(0, base_score + random.uniform(-5, 5)))
                
                # Generate random findings counts
                total = random.randint(20, 100)
                critical = random.randint(0, max(1, int(total * 0.1)))
                high = random.randint(0, max(1, int(total * 0.2)))
                medium = random.randint(0, max(1, int(total * 0.3)))
                low = total - critical - high - medium
                
                # Controls
                controls_passed = random.randint(30, 50)
                controls_failed = random.randint(5, 20)
                controls_na = random.randint(0, 10)
                
                # FIXED: Using correct column names from schema.sql
                await conn.execute("""
                    INSERT INTO compliance_reports (
                        report_id, tenant_id, report_name, framework, report_type,
                        report_date, period_start, period_end,
                        compliance_score, total_findings,
                        critical_findings, high_findings, medium_findings, low_findings,
                        controls_passed, controls_failed, controls_not_applicable,
                        report_data, executive_summary, recommendations,
                        generated_by, created_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                             $15, $16, $17, $18, $19, $20, $21, $22)
                """,
                    report_id,
                    tenant_id,
                    f"{framework} Report - {days_ago} days ago",
                    framework,
                    random.choice(report_types),
                    report_date,
                    report_date - timedelta(days=30),
                    report_date,
                    round(score, 2),
                    total,
                    critical,
                    high,
                    medium,
                    low,
                    controls_passed,
                    controls_failed,
                    controls_na,
                    json.dumps({
                        'summary': f"Compliance report for {framework}",
                        'controls': {
                            'passed': controls_passed,
                            'failed': controls_failed,
                            'na': controls_na
                        },
                        'findings_by_severity': {
                            'critical': critical,
                            'high': high,
                            'medium': medium,
                            'low': low
                        }
                    }),
                    f"Overall compliance score is {round(score, 2)}%. " +
                    f"Critical findings: {critical}, High: {high}",
                    f"Focus on fixing critical and high findings. Update security controls.",
                    "seed-script",
                    report_date
                )
    
    logger.info(f"✅ Created compliance reports for {len(frameworks)} frameworks")

async def create_audit_logs(pool, tenant_id, count=100):
    """Create test audit logs"""
    event_types = ['scan', 'finding', 'tenant', 'report', 'auth']
    event_actions = ['created', 'updated', 'deleted', 'viewed', 'executed']
    resource_types = ['scan', 'finding', 'tenant', 'report', 'approval']
    statuses = ['success', 'success', 'success', 'failure', 'warning']
    
    async with pool.acquire() as conn:
        for i in range(count):
            event_type = random.choice(event_types)
            event_action = random.choice(event_actions)
            status = random.choice(statuses)
            
            await conn.execute("""
                INSERT INTO audit_logs (
                    tenant_id, event_type, event_action,
                    user_id, user_email, user_role,
                    resource_type, resource_id, resource_name,
                    ip_address, user_agent, request_path, request_method, response_status,
                    details, status, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            """,
                tenant_id,
                event_type,
                event_action,
                f"user{random.randint(1, 5)}",
                f"user{random.randint(1, 5)}@example.com",
                random.choice(['admin', 'security', 'developer', 'auditor']),
                random.choice(resource_types),
                str(uuid.uuid4()),
                f"{event_type}-{random.randint(1000, 9999)}",
                f"192.168.1.{random.randint(1, 255)}",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                f"/api/v1/{event_type}s/{random.randint(1, 100)}",
                random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                random.choice([200, 201, 400, 403, 404, 500]),
                json.dumps({'details': f"Test audit log entry", 'changes': {'field': 'value'}}),
                status,
                datetime.now() - timedelta(hours=random.randint(0, 720))
            )
            
            if i % 50 == 0 and i > 0:
                logger.info(f"Created {i} audit logs")
    
    logger.info(f"✅ Created {count} audit logs")

async def verify_seed(pool):
    """Verify that seeding was successful"""
    async with pool.acquire() as conn:
        # Check counts
        tenant_count = await conn.fetchval("SELECT COUNT(*) FROM tenants")
        scan_count = await conn.fetchval("SELECT COUNT(*) FROM scans")
        finding_count = await conn.fetchval("SELECT COUNT(*) FROM findings")
        report_count = await conn.fetchval("SELECT COUNT(*) FROM compliance_reports")
        audit_count = await conn.fetchval("SELECT COUNT(*) FROM audit_logs")
        
        logger.info("=" * 60)
        logger.info("📊 DATABASE SEED VERIFICATION")
        logger.info("=" * 60)
        logger.info(f"Tenants: {tenant_count}")
        logger.info(f"Scans: {scan_count}")
        logger.info(f"Findings: {finding_count}")
        logger.info(f"Compliance Reports: {report_count}")
        logger.info(f"Audit Logs: {audit_count}")
        
        # Get severity distribution
        severity_counts = await conn.fetch("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            GROUP BY severity 
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                    ELSE 5 
                END
        """)
        
        logger.info("-" * 60)
        logger.info("Findings by Severity:")
        for row in severity_counts:
            logger.info(f"  {row['severity']}: {row['count']}")
        
        if tenant_count > 0 and scan_count > 0 and finding_count > 0:
            logger.info("-" * 60)
            logger.info("✅ Database seeded successfully!")
            return True
        else:
            logger.warning("⚠️ Database seeding may be incomplete")
            return False

async def main():
    """Main function"""
    logger.info("=" * 60)
    logger.info("🚀 DATABASE SEEDING SCRIPT")
    logger.info("=" * 60)
    
    # Database connection parameters
    db_config = {
        'user': 'postgres',
        'password': 'secure_password',
        'database': 'security_platform',
        'host': 'localhost',
        'port': 5432
    }
    
    # Create connection pool
    logger.info(f"Connecting to PostgreSQL at {db_config['host']}:{db_config['port']}...")
    pool = await asyncpg.create_pool(**db_config)
    
    try:
        await seed_database(pool)
        await create_audit_logs(pool, 'test-tenant', 100)
        await verify_seed(pool)
    except Exception as e:
        logger.error(f"❌ Seeding failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await pool.close()
    
    logger.info("=" * 60)
    logger.info("✅ Seeding script completed")
    logger.info("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())