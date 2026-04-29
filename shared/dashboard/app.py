#!/usr/bin/env python3
"""
Unified Security Dashboard - Version with REAL data from database
Combines data from Platform and Security components
"""

from flask import Flask, Response, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import psycopg2
import psycopg2.extras
import redis
import json
from datetime import datetime, timedelta
import os
import logging
from uuid import UUID
import subprocess
import uuid
import tempfile
import shutil
import threading
import asyncio

# Import des nouvelles fonctionnalités
from pdf_generator import PDFReportGenerator
from email_notifier import EmailNotifier
from scan_scheduler import ScanScheduler
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, REGISTRY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# SocketIO avec configuration optimisée pour éviter les déconnexions
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    ping_timeout=60,
    ping_interval=25,
    transports=['websocket', 'polling'],
    async_mode='threading'
)

# Redis client
redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)

# Initialisation des services
email_notifier = EmailNotifier()
scan_scheduler = ScanScheduler()

# Créer un loop asyncio pour le thread principal
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

def get_db():
    """Get database connection"""
    try:
        conn = psycopg2.connect(
            user=os.getenv('POSTGRES_USER', 'postgres'),
            password=os.getenv('POSTGRES_PASSWORD', 'secure_password'),
            database=os.getenv('POSTGRES_DB', 'security_platform'),
            host='postgres',
            port=5432
        )
        logger.info("✅ Dashboard connected to PostgreSQL")
        return conn
    except Exception as e:
        logger.error(f"❌ Database connection error: {e}")
        return None

# ============ ROUTES PRINCIPALES ============

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return Response(
        generate_latest(REGISTRY),
        mimetype=CONTENT_TYPE_LATEST
    )

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/test-email')
def test_email():
    """Test email notification endpoint"""
    if not email_notifier.enabled:
        return jsonify({'error': 'Email notifier disabled - check SMTP credentials'}), 400
    
    recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
    if not recipients or not recipients[0]:
        return jsonify({'error': 'No recipients configured'}), 400
    
    test_finding = {
        'title': 'TEST - Email Notification System',
        'description': 'This is a test email to verify that email notifications are working correctly on the Enterprise Security Platform.',
        'severity': 'info',
        'scanner': 'test',
        'file': 'test.py',
        'line': 42
    }
    
    asyncio.run_coroutine_threadsafe(
        email_notifier.send_critical_alert(test_finding, 'default', recipients),
        loop
    )
    
    return jsonify({'status': 'success', 'message': f'Test email sent to {", ".join(recipients)}'})

@app.route('/api/scanners')
def get_scanners():
    """Get list of scanners that have findings in the database"""
    try:
        conn = get_db()
        if not conn:
            return jsonify([])
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT DISTINCT scanner_name, 
                   COUNT(*) as count
            FROM findings 
            WHERE scanner_name IS NOT NULL
            GROUP BY scanner_name
            ORDER BY scanner_name
        """)
        
        scanners = []
        icons = {
            'semgrep': '🔍',
            'gitleaks': '🔐', 
            'trivy': '🐳',
            'checkov': '🏗️',
            'dependency-check': '📦'
        }
        types = {
            'semgrep': 'SAST',
            'gitleaks': 'Secrets',
            'trivy': 'Container',
            'checkov': 'IaC',
            'dependency-check': 'SCA'
        }
        
        for row in cur.fetchall():
            name = row['scanner_name']
            scanners.append({
                'name': name,
                'icon': icons.get(name, '🔧'),
                'type': types.get(name, 'Unknown'),
                'count': row['count']
            })
        
        cur.close()
        conn.close()
        return jsonify(scanners)
        
    except Exception as e:
        logger.error(f"Error getting scanners: {e}")
        return jsonify([])

@app.route('/api/system/health')
def system_health():
    """Get system health metrics for monitoring"""
    try:
        containers = []
        try:
            result = subprocess.run(['docker', 'ps', '--format', 'json'], 
                                   capture_output=True, text=True, timeout=10)
            if result.stdout:
                containers = [json.loads(line) for line in result.stdout.strip().split('\n') if line]
        except Exception as e:
            logger.warning(f"Could not get container stats: {e}")
        
        services = {
            'orchestrator': any('orchestrator' in c.get('Names', '') for c in containers),
            'dashboard': any('dashboard' in c.get('Names', '') for c in containers),
            'postgres': any('postgres' in c.get('Names', '') for c in containers),
            'redis': any('redis' in c.get('Names', '') for c in containers),
            'grafana': any('grafana' in c.get('Names', '') for c in containers),
            'prometheus': any('prometheus' in c.get('Names', '') for c in containers),
            'api-gateway': any('api-gateway' in c.get('Names', '') for c in containers),
        }
        
        health_data = {
            'status': 'healthy' if all(services.values()) else 'degraded',
            'services': services,
            'uptime': subprocess.getoutput('uptime'),
            'active_containers': len(containers),
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(health_data)
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/system/metrics')
def system_metrics():
    """Get detailed system metrics without external dependencies"""
    try:
        conn = get_db()
        db_stats = {}
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM findings")
            db_stats['total_findings'] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM scans")
            db_stats['total_scans'] = cur.fetchone()[0]
            cur.close()
            conn.close()
        
        metrics = {
            'cpu': {'percent': 'N/A', 'cores': 'N/A'},
            'memory': {'percent': 'N/A', 'available': 'N/A', 'used': 'N/A'},
            'database': db_stats,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return jsonify({'error': str(e)}), 500

# ============ API POUR LES SCANS (multi_scan.py) ============

@app.route('/api/v1/findings', methods=['POST'])
def add_finding_v1():
    """API pour ajouter un finding depuis les scanners (multi_scan.py)"""
    try:
        data = request.json
        logger.info(f"📥 Receiving finding: {data.get('title', 'No title')[:50]}")
        
        conn = get_db()
        if not conn:
            return jsonify({'error': 'Database not available'}), 500
        
        cur = conn.cursor()
        
        scan_id = data.get('scan_id')
        cur.execute("SELECT 1 FROM scans WHERE scan_id = %s", (scan_id,))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO scans (scan_id, tenant_id, repo_url, status, created_at)
                VALUES (%s, %s, %s, 'completed', NOW())
            """, (scan_id, data.get('tenant_id', 'default'), 'https://github.com/scan-repo'))
            conn.commit()
            logger.info(f"📝 Created scan record for {scan_id}")
        
        cur.execute("""
            INSERT INTO findings (
                finding_id, scan_id, tenant_id, title, description,
                severity, scanner_name, finding_type, file_path, line_start,
                status, detected_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', NOW())
        """, (
            data.get('finding_id'), data.get('scan_id'), data.get('tenant_id', 'default'),
            data.get('title', '')[:500], data.get('description', '')[:1000],
            data.get('severity', 'medium'), data.get('scanner_name', 'unknown'),
            data.get('finding_type', 'vulnerability'), data.get('file_path', '')[:500],
            data.get('line_start', 0)
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Send email alert for critical findings
        if data.get('severity') == 'critical' and email_notifier.enabled:
            recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
            if recipients and recipients[0]:
                finding = {
                    'title': data.get('title', ''),
                    'description': data.get('description', ''),
                    'severity': data.get('severity', 'critical'),
                    'scanner': data.get('scanner_name', 'unknown'),
                    'file': data.get('file_path', ''),
                    'line': data.get('line_start', 0)
                }
                asyncio.run_coroutine_threadsafe(
                    email_notifier.send_critical_alert(finding, data.get('tenant_id', 'default'), recipients),
                    loop
                )
                logger.info(f"📧 Critical alert email sent for finding: {data.get('title', '')[:50]}")
        
        logger.info(f"✅ Finding added: {data.get('title', '')[:50]}")
        return jsonify({'status': 'success'}), 201
        
    except Exception as e:
        logger.error(f"❌ Error adding finding: {e}")
        return jsonify({'error': str(e)}), 500

# ============ API POUR LE DASHBOARD ============

@app.route('/api/overview')
def get_overview():
    """Get security overview metrics from database with REAL trend data"""
    try:
        conn = get_db()
        if not conn:
            logger.error("No database connection")
            return jsonify({
                'error': 'Database unavailable',
                'current': {'critical_open': 0, 'high_open': 0, 'medium': 0, 'low': 0},
                'trends': [],
                'compliance': [],
                'recent_scans': [],
                'critical_findings': []
            }), 503
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open') as critical_open,
                COUNT(*) FILTER (WHERE severity = 'high' AND status = 'open') as high_open,
                COUNT(*) FILTER (WHERE severity = 'medium' AND status = 'open') as medium,
                COUNT(*) FILTER (WHERE severity = 'low' AND status = 'open') as low
            FROM findings
        """)
        result = cur.fetchone()
        
        cur.execute("""
            SELECT 
                DATE(detected_at) as date,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low
            FROM findings
            WHERE detected_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(detected_at)
            ORDER BY date ASC
        """)
        trends_data = cur.fetchall()
        
        trend_list = []
        for t in trends_data:
            if t['date']:
                trend_list.append({
                    'date': t['date'].isoformat(),
                    'critical': t['critical'] or 0,
                    'high': t['high'] or 0,
                    'medium': t['medium'] or 0,
                    'low': t['low'] or 0
                })
        
        cur.execute("""
            SELECT scan_id, repo_url, status, created_at, findings_summary
            FROM scans
            ORDER BY created_at DESC
            LIMIT 10
        """)
        scans = cur.fetchall()
        
        recent_scans = []
        for scan in scans:
            recent_scans.append({
                'scan_id': scan['scan_id'],
                'repo_url': scan['repo_url'] or 'unknown',
                'status': scan['status'] or 'unknown',
                'start_time': scan['created_at'].isoformat() if scan['created_at'] else None,
                'summary': scan['findings_summary'] if scan['findings_summary'] else {}
            })
        
        cur.execute("""
            SELECT finding_id, title, severity, file_path, line_start, scanner_name
            FROM findings
            WHERE severity IN ('critical', 'high') AND status = 'open'
            ORDER BY detected_at DESC
            LIMIT 5
        """)
        critical = cur.fetchall()
        
        cur.close()
        conn.close()
        
        critical_findings = []
        for f in critical:
            scanner_icon = {
                'semgrep': '🔍', 'gitleaks': '🔐', 'trivy': '🐳',
                'checkov': '🏗️', 'dependency-check': '📦'
            }.get(f.get('scanner_name', ''), '🔧')
            
            critical_findings.append({
                'finding_id': str(f['finding_id']),
                'title': f['title'] or 'No title',
                'severity': f['severity'],
                'scanner': f"{scanner_icon} {f.get('scanner_name', 'unknown')}",
                'file': f['file_path'] or 'unknown',
                'line': f['line_start'] or 0
            })
        
        current_data = {
            'critical_open': result['critical_open'] or 0,
            'high_open': result['high_open'] or 0,
            'medium': result['medium'] or 0,
            'low': result['low'] or 0,
            'avg_age_hours': 48
        }
        
        logger.info(f"✅ REAL DATA: critical={current_data['critical_open']}, "
                   f"high={current_data['high_open']}, "
                   f"medium={current_data['medium']}, "
                   f"low={current_data['low']}, "
                   f"trend_points={len(trend_list)}")
        
        return jsonify({
            'current': current_data,
            'trends': trend_list,
            'compliance': [
                {'framework': 'SOC2', 'compliance_score': 85},
                {'framework': 'PCI-DSS', 'compliance_score': 72},
                {'framework': 'HIPAA', 'compliance_score': 90},
                {'framework': 'ISO27001', 'compliance_score': 78}
            ],
            'scans': {
                'total_scans_24h': len(recent_scans),
                'successful_24h': sum(1 for s in recent_scans if s['status'] == 'completed'),
                'failed_24h': sum(1 for s in recent_scans if s['status'] == 'failed')
            },
            'recent_scans': recent_scans,
            'critical_findings': critical_findings,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in get_overview: {e}")
        return jsonify({
            'current': {'critical_open': 0, 'high_open': 0, 'medium': 0, 'low': 0},
            'trends': [],
            'compliance': [],
            'recent_scans': [],
            'critical_findings': [],
            'error': str(e)
        }), 500

def mock_overview_data():
    """Return mock data when database is unavailable"""
    return {
        'current': {'critical_open': 3, 'high_open': 7, 'medium': 12, 'low': 25, 'avg_age_hours': 48},
        'trends': [],
        'compliance': [
            {'framework': 'SOC2', 'compliance_score': 85},
            {'framework': 'PCI-DSS', 'compliance_score': 72},
            {'framework': 'HIPAA', 'compliance_score': 90}
        ],
        'scans': {'total_scans_24h': 15, 'successful_24h': 14, 'failed_24h': 1},
        'recent_scans': [],
        'critical_findings': [],
        'timestamp': datetime.now().isoformat()
    }

@app.route('/api/findings/open')
def get_open_findings():
    """Get open findings for remediation queue with scanner info"""
    try:
        conn = get_db()
        if not conn:
            return jsonify([])
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT 
                finding_id::text,
                title, 
                severity, 
                scanner_name,
                finding_type as type,
                file_path,
                line_start,
                detected_at,
                status
            FROM findings
            WHERE status = 'open'
            ORDER BY 
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                detected_at ASC
            LIMIT 50
        """)
        
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        if not rows:
            logger.info("No open findings found")
            return jsonify([])
        
        result = []
        now = datetime.now().replace(tzinfo=None)
        
        scanner_icons = {
            'semgrep': '🔍',
            'gitleaks': '🔐',
            'trivy': '🐳',
            'checkov': '🏗️',
            'dependency-check': '📦',
            'grype': '🐙',
            'tfsec': '🏗️'
        }
        
        for row in rows:
            age_hours = 0
            if row['detected_at']:
                detected = row['detected_at'].replace(tzinfo=None)
                age = now - detected
                age_hours = int(age.total_seconds() / 3600)
            
            scanner = row.get('scanner_name', 'unknown').lower()
            icon = scanner_icons.get(scanner, '🔧')
            
            result.append({
                'finding_id': row['finding_id'],
                'title': row['title'] or 'No title',
                'severity': row['severity'],
                'scanner': f"{icon} {scanner}",
                'type': row['type'] or 'unknown',
                'file': row['file_path'] or 'unknown',
                'line': row['line_start'] or 0,
                'age_hours': age_hours,
                'status': row['status']
            })
        
        logger.info(f"Found {len(result)} open findings")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in get_open_findings: {e}")
        return jsonify([])

# ============ FIXED REMEDIATE FUNCTION ============
@app.route('/api/remediate/<finding_id>', methods=['POST'])
def remediate_finding(finding_id):
    """Remediate a finding - FIXED: removed status_changed_at column"""
    try:
        conn = get_db()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database not available'}), 500
        
        cur = conn.cursor()
        
        cur.execute("""
            UPDATE findings 
            SET status = 'fixed', 
                fixed_at = NOW()
            WHERE finding_id::text = %s AND status = 'open'
            RETURNING finding_id, title
        """, (finding_id,))
        
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({'status': 'error', 'message': 'Finding not found or already fixed'}), 404
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"✅ Finding remediated: {result[0]}")
        
        return jsonify({
            'status': 'completed',
            'message': 'Finding has been fixed'
        })
        
    except Exception as e:
        logger.error(f"Error remediating finding: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/remediation/logs')
def get_remediation_logs():
    """Get remediation logs"""
    try:
        conn = get_db()
        if not conn:
            return jsonify([])
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'remediation_logs'
            )
        """)
        table_exists = cur.fetchone()['exists']
        
        if not table_exists:
            cur.close()
            conn.close()
            return jsonify([])
        
        cur.execute("""
            SELECT * FROM remediation_logs 
            ORDER BY created_at DESC 
            LIMIT 50
        """)
        
        logs = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify(logs)
        
    except Exception as e:
        logger.error(f"Error getting remediation logs: {e}")
        return jsonify([])

# ============ SCAN DEPUIS LE DASHBOARD ============

async def run_scan_background_async(scan_id, repo_url, scan_types, tenant_id):
    """Exécuter le scan en arrière-plan avec de vrais scanners (version asynchrone)"""
    import tempfile
    import subprocess
    import shutil
    import uuid
    
    logger.info(f"🔍 Background scan started for {scan_id} - {repo_url}")
    
    conn = get_db()
    if not conn:
        return
    
    cur = conn.cursor()
    repo_path = None
    
    try:
        repo_path = tempfile.mkdtemp()
        subprocess.run(["git", "clone", "--depth", "1", repo_url, repo_path], 
                      capture_output=True, timeout=120)
        logger.info(f"📁 Repository cloned to {repo_path}")
        
        findings = []
        
        if 'sast' in scan_types:
            try:
                result = subprocess.run(
                    ["semgrep", "--config", "auto", "--json", repo_path],
                    capture_output=True, text=True, timeout=300, encoding='utf-8', errors='ignore'
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    for r in data.get('results', []):
                        severity_raw = r.get('extra', {}).get('severity', 'medium').lower()
                        severity_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
                        severity = severity_map.get(severity_raw, severity_raw)
                        if severity not in ['critical', 'high', 'medium', 'low', 'info']:
                            severity = 'medium'
                        
                        findings.append({
                            'title': r.get('check_id', 'Unknown')[:200],
                            'description': r.get('extra', {}).get('message', '')[:500],
                            'severity': severity,
                            'scanner': 'semgrep',
                            'type': 'sast',
                            'file': r.get('path', '')[:200],
                            'line': r.get('start', {}).get('line', 0)
                        })
                logger.info(f"   🔍 Semgrep: {len([f for f in findings if f.get('scanner') == 'semgrep'])} findings")
            except Exception as e:
                logger.error(f"Semgrep error: {e}")
        
        if 'secrets' in scan_types:
            try:
                result = subprocess.run(
                    ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-git"],
                    capture_output=True, text=True, timeout=180, encoding='utf-8', errors='ignore'
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    items = data if isinstance(data, list) else data.get('findings', [])
                    for f in items:
                        findings.append({
                            'title': f"Secret: {f.get('RuleID', 'unknown')}"[:200],
                            'description': f.get('Description', '')[:500],
                            'severity': 'critical',
                            'scanner': 'gitleaks',
                            'type': 'secret',
                            'file': f.get('File', '')[:200],
                            'line': f.get('StartLine', 0)
                        })
                logger.info(f"   🔐 Gitleaks: {len([f for f in findings if f.get('scanner') == 'gitleaks'])} findings")
            except Exception as e:
                logger.error(f"Gitleaks error: {e}")
        
        for finding in findings:
            finding_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO findings (
                    finding_id, scan_id, tenant_id, title, description,
                    severity, scanner_name, finding_type, file_path, line_start,
                    status, detected_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', NOW())
            """, (
                finding_id, scan_id, tenant_id,
                finding['title'], finding['description'],
                finding['severity'], finding['scanner'], finding['type'],
                finding['file'], finding['line']
            ))
        
        cur.execute("""
            UPDATE scans 
            SET status = 'completed',
                completed_at = NOW(),
                findings_summary = jsonb_build_object(
                    'critical', COALESCE((SELECT COUNT(*) FROM findings WHERE scan_id = %s AND severity = 'critical'), 0),
                    'high', COALESCE((SELECT COUNT(*) FROM findings WHERE scan_id = %s AND severity = 'high'), 0),
                    'medium', COALESCE((SELECT COUNT(*) FROM findings WHERE scan_id = %s AND severity = 'medium'), 0),
                    'low', COALESCE((SELECT COUNT(*) FROM findings WHERE scan_id = %s AND severity = 'low'), 0),
                    'total', COALESCE((SELECT COUNT(*) FROM findings WHERE scan_id = %s), 0)
                )
            WHERE scan_id = %s
        """, (scan_id, scan_id, scan_id, scan_id, scan_id, scan_id))
        conn.commit()
        
        # Send email summary for completed scan
        if findings and email_notifier.enabled:
            recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
            if recipients and recipients[0]:
                summary = {
                    'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
                    'high': sum(1 for f in findings if f.get('severity') == 'high'),
                    'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
                    'low': sum(1 for f in findings if f.get('severity') == 'low'),
                    'total': len(findings)
                }
                await email_notifier.send_scan_complete(scan_id, repo_url, summary, recipients)
                logger.info(f"📧 Scan completion email sent for {scan_id}")
        
        logger.info(f"✅ Scan {scan_id} completed with {len(findings)} findings")
        
    except Exception as e:
        logger.error(f"❌ Background scan error: {e}")
        try:
            cur.execute("UPDATE scans SET status = 'failed', error_message = %s WHERE scan_id = %s", 
                       (str(e), scan_id))
            conn.commit()
        except:
            pass
    
    finally:
        cur.close()
        conn.close()
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)

def run_scan_background(scan_id, repo_url, scan_types, tenant_id):
    """Wrapper synchrone pour exécuter le scan asynchrone"""
    try:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        new_loop.run_until_complete(run_scan_background_async(scan_id, repo_url, scan_types, tenant_id))
        new_loop.close()
    except Exception as e:
        logger.error(f"Background scan error: {e}")

@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    """Lancer un scan depuis le dashboard - NON-BLOCKING VERSION"""
    try:
        data = request.json
        repo_url = data.get('repo_url')
        scan_types = data.get('scan_types', ['sast'])
        tenant_id = data.get('tenant_id', 'default')
        
        logger.info(f"🚀 Starting scan for {repo_url}")
        
        scan_id = str(uuid.uuid4())
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO scans (scan_id, tenant_id, repo_url, scan_types, status, created_at)
            VALUES (%s, %s, %s, %s, 'running', NOW())
        """, (scan_id, tenant_id, repo_url, json.dumps(scan_types)))
        conn.commit()
        cur.close()
        conn.close()
        
        thread = threading.Thread(
            target=run_scan_background, 
            args=(scan_id, repo_url, scan_types, tenant_id),
            daemon=True
        )
        thread.start()
        
        return jsonify({'status': 'success', 'scan_id': scan_id, 'message': 'Scan started in background'})
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

# ============ RAPPORTS PDF ============

@app.route('/api/report/pdf/<scan_id>')
def generate_pdf_report(scan_id):
    """Générer un rapport PDF pour un scan"""
    try:
        from pdf_generator import PDFReportGenerator
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
        scan = cur.fetchone()
        
        if not scan:
            return jsonify({'error': 'Scan non trouvé'}), 404
        
        cur.execute("""
            SELECT finding_id, title, description, severity, scanner_name, file_path, line_start
            FROM findings WHERE scan_id = %s
        """, (scan_id,))
        findings = cur.fetchall()
        
        cur.execute("SELECT * FROM tenants WHERE tenant_id = %s", (scan['tenant_id'],))
        tenant = cur.fetchone()
        
        cur.close()
        conn.close()
        
        generator = PDFReportGenerator()
        pdf_buffer = generator.generate_report(
            scan_id=scan_id,
            scan_data=scan,
            findings=findings,
            summary=scan.get('summary', {}),
            tenant_info=tenant or {}
        )
        
        return Response(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=security_report_{scan_id[:8]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        return jsonify({'error': str(e)}), 500

# ============ HISTORIQUE DES SCANS ============

@app.route('/api/scans/history')
def get_scan_history():
    """Récupérer l'historique des scans avec pagination"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        offset = (page - 1) * per_page
        
        cur.execute("""
            SELECT scan_id, repo_url, status, created_at, completed_at, 
                   findings_summary, scan_types, metadata
            FROM scans
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        scans = cur.fetchall()
        
        cur.execute("SELECT COUNT(*) FROM scans")
        total = cur.fetchone()['count']
        
        cur.close()
        conn.close()
        
        return jsonify({
            'scans': scans,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Error in scan history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/history/stats')
def get_scan_stats():
    """Récupérer les statistiques des scans"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                COUNT(*) as total_scans,
                COUNT(*) FILTER (WHERE status = 'completed') as successful,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE status = 'running') as running,
                AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) as avg_duration
            FROM scans
        """)
        stats = cur.fetchone()
        
        cur.execute("""
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count
            FROM scans
            WHERE created_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        """)
        daily = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'stats': stats,
            'daily': daily
        })
        
    except Exception as e:
        logger.error(f"Error in scan stats: {e}")
        return jsonify({'error': str(e)}), 500

# ============ FIXED FILTERS API ============

@app.route('/api/findings/filter')
def filter_findings():
    """Filtrer les findings avec critères avancés - VERSION COMPLETE FONCTIONNELLE"""
    try:
        conn = get_db()
        if not conn:
            logger.error("No database connection for filter")
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Base query
        query = """
            SELECT 
                finding_id::text, 
                title, 
                severity, 
                scanner_name, 
                finding_type, 
                file_path, 
                line_start, 
                detected_at, 
                status,
                description
            FROM findings 
            WHERE 1=1
        """
        params = []
        
        # Get filter parameters
        severity = request.args.get('severity')
        scanner = request.args.get('scanner')
        status = request.args.get('status')
        date_range = request.args.get('date_range')
        search = request.args.get('search')
        
        # Apply severity filter
        if severity and severity != 'all':
            query += " AND severity = %s"
            params.append(severity.lower())
            logger.info(f"Filtering by severity: {severity}")
        
        # Apply scanner filter
        if scanner and scanner != 'all':
            query += " AND scanner_name = %s"
            params.append(scanner.lower())
            logger.info(f"Filtering by scanner: {scanner}")
        
        # Apply status filter
        if status and status != 'all':
            query += " AND status = %s"
            params.append(status.lower())
            logger.info(f"Filtering by status: {status}")
        
        # Apply date range filter
        if date_range == 'today':
            query += " AND detected_at::date = CURRENT_DATE"
            logger.info("Filtering by today")
        elif date_range == 'week':
            query += " AND detected_at > NOW() - INTERVAL '7 days'"
            logger.info("Filtering by last 7 days")
        elif date_range == 'month':
            query += " AND detected_at > NOW() - INTERVAL '30 days'"
            logger.info("Filtering by last 30 days")
        
        # Apply search filter
        if search and search.strip():
            query += " AND (title ILIKE %s OR description ILIKE %s OR file_path ILIKE %s)"
            search_param = f"%{search.strip()}%"
            params.extend([search_param, search_param, search_param])
            logger.info(f"Filtering by search: {search}")
        
        # Add ORDER BY and LIMIT
        query += """ 
            ORDER BY 
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END, 
                detected_at DESC 
            LIMIT 100
        """
        
        logger.info(f"Filter query: {query}")
        logger.info(f"Filter params: {params}")
        
        cur.execute(query, params)
        findings = cur.fetchall()
        
        # Convert datetime objects to ISO format for JSON serialization
        for finding in findings:
            if finding.get('detected_at'):
                finding['detected_at'] = finding['detected_at'].isoformat()
        
        cur.close()
        conn.close()
        
        logger.info(f"Filter returned {len(findings)} findings")
        return jsonify(findings)
        
    except Exception as e:
        logger.error(f"Error filtering findings: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============ SCAN SCHEDULER ============

@app.route('/api/scheduler/scans')
def get_scheduled_scans():
    """Récupérer la liste des scans planifiés"""
    return jsonify(scan_scheduler.get_scheduled_scans())

@app.route('/api/scheduler/scans', methods=['POST'])
def add_scheduled_scan():
    """Ajouter un scan planifié"""
    data = request.json
    scan_scheduler.add_scheduled_scan(data)
    return jsonify({'status': 'success'})

@app.route('/api/scheduler/scans/<scan_id>', methods=['DELETE'])
def delete_scheduled_scan(scan_id):
    """Supprimer un scan planifié"""
    scan_scheduler.remove_scheduled_scan(scan_id)
    return jsonify({'status': 'success'})

# ============ GRAFANA WEBHOOK ============

@app.route('/api/webhooks/grafana', methods=['POST'])
def grafana_webhook():
    """Webhook endpoint for Grafana alerts"""
    try:
        data = request.json
        logger.info(f"📨 Received Grafana alert: {data.get('title', 'Unknown')}")
        
        recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
        
        if recipients and recipients[0] and email_notifier.enabled:
            if data.get('alerts'):
                for alert in data.get('alerts', []):
                    asyncio.run_coroutine_threadsafe(
                        email_notifier.send_grafana_alert(alert, recipients),
                        loop
                    )
                    logger.info(f"📧 Grafana alert email sent for: {alert.get('labels', {}).get('alertname', 'Unknown')}")
        
        return jsonify({'status': 'ok', 'message': 'Webhook processed'}), 200
    except Exception as e:
        logger.error(f"Error processing Grafana webhook: {e}")
        return jsonify({'error': str(e)}), 500

# ============ STATISTIQUES EN TEMPS RÉEL ============

@socketio.on('subscribe_stats')
def handle_subscribe_stats():
    """S'abonner aux mises à jour des statistiques"""
    emit('stats_update', get_realtime_stats())
    
    def update_stats():
        import time
        while True:
            time.sleep(5)
            socketio.emit('stats_update', get_realtime_stats())
    
    socketio.start_background_task(update_stats)

def get_realtime_stats():
    """Récupérer les statistiques en temps réel"""
    try:
        conn = get_db()
        if not conn:
            return {}
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT scan_id, repo_url, status, created_at
            FROM scans ORDER BY created_at DESC LIMIT 1
        """)
        last_scan = cur.fetchone()
        
        if last_scan and last_scan.get('created_at'):
            last_scan['created_at'] = last_scan['created_at'].isoformat()
        
        cur.execute("""
            SELECT 
                COUNT(*) as scans_5min,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_5min
            FROM scans
            WHERE created_at > NOW() - INTERVAL '5 minutes'
        """)
        recent_stats = cur.fetchone()
        
        cur.execute("""
            SELECT 
                severity, COUNT(*) as count
            FROM findings
            WHERE status = 'open'
            GROUP BY severity
        """)
        severity_counts = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return {
            'last_scan': last_scan,
            'recent_stats': recent_stats,
            'severity_counts': severity_counts,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting realtime stats: {e}")
        return {}

# ============ WEBSOCKET ============

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected to WebSocket")
    emit('connected', {'data': 'Connected to security dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected from WebSocket")

@socketio.on('ping')
def handle_ping():
    """Handle ping to keep connection alive"""
    pass

def broadcast_updates():
    """Broadcast updates to connected clients"""
    while True:
        socketio.sleep(30)
        socketio.emit('refresh', {'data': 'Refresh dashboard'})
        logger.debug("Broadcast refresh signal")

socketio.start_background_task(broadcast_updates)

# Démarrer le scan scheduler
try:
    scan_scheduler.start()
    logger.info("✅ Scan Scheduler started")
except Exception as e:
    logger.error(f"❌ Failed to start scan scheduler: {e}")

if __name__ == '__main__':
    logger.info("Starting dashboard server with REAL trend data...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)