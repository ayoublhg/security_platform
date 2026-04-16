#!/usr/bin/env python3
"""
Unified Security Dashboard - Version corrigée avec toutes les fonctionnalités
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

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

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

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
        
        # Vérifier si le scan existe
        scan_id = data.get('scan_id')
        cur.execute("SELECT 1 FROM scans WHERE scan_id = %s", (scan_id,))
        if not cur.fetchone():
            # Créer un scan fictif si nécessaire
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
        
        logger.info(f"✅ Finding added: {data.get('title', '')[:50]}")
        return jsonify({'status': 'success'}), 201
        
    except Exception as e:
        logger.error(f"❌ Error adding finding: {e}")
        return jsonify({'error': str(e)}), 500

# ============ API POUR LE DASHBOARD ============

@app.route('/api/overview')
def get_overview():
    """Get security overview metrics from database"""
    try:
        conn = get_db()
        if not conn:
            logger.error("No database connection")
            return jsonify(mock_overview_data())
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # RÉELLES données de la base - COUNT UNIQUEMENT LES 'open'
        cur.execute("""
            SELECT 
                COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open') as critical_open,
                COUNT(*) FILTER (WHERE severity = 'high' AND status = 'open') as high_open,
                COUNT(*) FILTER (WHERE severity = 'medium' AND status = 'open') as medium,
                COUNT(*) FILTER (WHERE severity = 'low' AND status = 'open') as low
            FROM findings
        """)
        result = cur.fetchone()
        
        # Récupérer les scans récents
        cur.execute("""
            SELECT scan_id, repo_url, status, created_at, findings_summary
            FROM scans
            ORDER BY created_at DESC
            LIMIT 10
        """)
        scans = cur.fetchall()
        
        # Récupérer les findings critiques (open)
        cur.execute("""
            SELECT finding_id, title, severity, file_path, line_start
            FROM findings
            WHERE severity IN ('critical', 'high') AND status = 'open'
            ORDER BY detected_at DESC
            LIMIT 5
        """)
        critical = cur.fetchall()
        
        cur.close()
        conn.close()
        
        # Formater les scans récents
        recent_scans = []
        for scan in scans:
            recent_scans.append({
                'scan_id': scan['scan_id'],
                'repo_url': scan['repo_url'] or 'unknown',
                'status': scan['status'] or 'unknown',
                'start_time': scan['created_at'].isoformat() if scan['created_at'] else None,
                'summary': scan['findings_summary'] if scan['findings_summary'] else {}
            })
        
        # Formater les findings critiques
        critical_findings = []
        for f in critical:
            critical_findings.append({
                'finding_id': str(f['finding_id']),
                'title': f['title'] or 'No title',
                'severity': f['severity'],
                'file': f['file_path'] or 'unknown',
                'line': f['line_start'] or 0
            })
        
        # VRAIES données
        current_data = {
            'critical_open': result['critical_open'] or 0,
            'high_open': result['high_open'] or 0,
            'medium': result['medium'] or 0,
            'low': result['low'] or 0,
            'avg_age_hours': 48
        }
        
        logger.info(f"✅ REAL DATA FROM DB: critical={current_data['critical_open']}, "
                   f"high={current_data['high_open']}, "
                   f"medium={current_data['medium']}, "
                   f"low={current_data['low']}")
        
        return jsonify({
            'current': current_data,
            'trends': generate_trend_data(),
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
        return jsonify(mock_overview_data())

def generate_trend_data():
    """Generate trend data for charts"""
    trends = []
    today = datetime.now()
    for i in range(7, 0, -1):
        date = today - timedelta(days=i)
        trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'critical': 2,
            'high': 5,
            'total': 10
        })
    return trends

def mock_overview_data():
    """Return mock data when database is unavailable"""
    return {
        'current': {'critical_open': 3, 'high_open': 7, 'medium': 12, 'low': 25, 'avg_age_hours': 48},
        'trends': generate_trend_data(),
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
    """Get open findings for remediation queue"""
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
                finding_type as type,
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
            LIMIT 20
        """)
        
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        if not rows:
            logger.info("No open findings found")
            return jsonify([])
        
        result = []
        now = datetime.now().replace(tzinfo=None)
        
        for row in rows:
            age_hours = 0
            if row['detected_at']:
                detected = row['detected_at'].replace(tzinfo=None)
                age = now - detected
                age_hours = int(age.total_seconds() / 3600)
            
            result.append({
                'finding_id': row['finding_id'],
                'title': row['title'] or 'No title',
                'severity': row['severity'],
                'type': row['type'] or 'unknown',
                'age_hours': age_hours,
                'status': row['status']
            })
        
        logger.info(f"Found {len(result)} open findings")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in get_open_findings: {e}")
        return jsonify([])

@app.route('/api/remediate/<finding_id>', methods=['POST'])
def remediate_finding(finding_id):
    """Remediate a finding"""
    try:
        conn = get_db()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database not available'}), 500
        
        cur = conn.cursor()
        
        # Chercher par ID exact
        cur.execute("""
            UPDATE findings 
            SET status = 'fixed', 
                fixed_at = NOW(),
                status_changed_at = NOW()
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
            'message': f'Finding has been fixed'
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
        
        # Check if table exists
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
        # 1. Cloner le dépôt (bloquant mais nécessaire)
        repo_path = tempfile.mkdtemp()
        subprocess.run(["git", "clone", "--depth", "1", repo_url, repo_path], 
                      capture_output=True, timeout=120)
        logger.info(f"📁 Repository cloned to {repo_path}")
        
        findings = []
        
        # 2. Scanner avec Semgrep (SAST)
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
                        severity_map = {
                            'error': 'high',
                            'warning': 'medium',
                            'note': 'low'
                        }
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
                logger.info(f"   🔍 Semgrep: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Semgrep error: {e}")
        
        # 3. Scanner avec Gitleaks (Secrets)
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
                logger.info(f"   🔐 Gitleaks: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Gitleaks error: {e}")
        
        # 4. Ajouter les findings à la base
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
        
        # 5. Mettre à jour le statut du scan ET le résumé
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
        
        # Envoyer notification email si des findings critiques
        critical_findings = [f for f in findings if f['severity'] == 'critical']
        if critical_findings and email_notifier.enabled:
            recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
            if recipients:
                for finding in critical_findings[:5]:
                    await email_notifier.send_critical_alert(finding, tenant_id, recipients)
        
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
    asyncio.run(run_scan_background_async(scan_id, repo_url, scan_types, tenant_id))

@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    """Lancer un scan depuis le dashboard"""
    try:
        data = request.json
        repo_url = data.get('repo_url')
        scan_types = data.get('scan_types', ['sast'])
        tenant_id = data.get('tenant_id', 'default')
        
        logger.info(f"🚀 Starting scan for {repo_url}")
        
        import uuid
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
        
        # LANCER LE SCAN EN ARRIÈRE-PLAN
        thread = threading.Thread(target=run_scan_background, args=(scan_id, repo_url, scan_types, tenant_id))
        thread.daemon = True
        thread.start()
        
        return jsonify({'status': 'success', 'scan_id': scan_id})
        
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
        
        # Récupérer les données du scan
        cur.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
        scan = cur.fetchone()
        
        if not scan:
            return jsonify({'error': 'Scan non trouvé'}), 404
        
        # Récupérer les findings
        cur.execute("""
            SELECT finding_id, title, description, severity, scanner_name, file_path, line_start
            FROM findings WHERE scan_id = %s
        """, (scan_id,))
        findings = cur.fetchall()
        
        # Récupérer les informations du tenant
        cur.execute("SELECT * FROM tenants WHERE tenant_id = %s", (scan['tenant_id'],))
        tenant = cur.fetchone()
        
        cur.close()
        conn.close()
        
        # Générer le PDF
        generator = PDFReportGenerator()
        pdf_buffer = generator.generate_report(
            scan_id=scan_id,
            scan_data=scan,
            findings=findings,
            summary=scan.get('summary', {}),
            tenant_info=tenant or {}
        )
        
        # Retourner le PDF
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
        
        # Récupérer les scans
        cur.execute("""
            SELECT scan_id, repo_url, status, created_at, completed_at, 
                   findings_summary, scan_types, metadata
            FROM scans
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        scans = cur.fetchall()
        
        # Récupérer le nombre total
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
        
        # Statistiques globales
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
        
        # Scans par jour (30 jours)
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

# ============ FILTRES AVANCÉS ============

@app.route('/api/findings/filter')
def filter_findings():
    """Filtrer les findings avec critères avancés"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        param_count = 1
        
        severity = request.args.get('severity')
        if severity:
            query += f" AND severity = ${param_count}"
            params.append(severity)
            param_count += 1
        
        scanner = request.args.get('scanner')
        if scanner:
            query += f" AND scanner_name = ${param_count}"
            params.append(scanner)
            param_count += 1
        
        status = request.args.get('status')
        if status:
            query += f" AND status = ${param_count}"
            params.append(status)
            param_count += 1
        
        date_range = request.args.get('date_range')
        if date_range == 'today':
            query += f" AND detected_at::date = CURRENT_DATE"
        elif date_range == 'week':
            query += f" AND detected_at > NOW() - INTERVAL '7 days'"
        elif date_range == 'month':
            query += f" AND detected_at > NOW() - INTERVAL '30 days'"
        
        search = request.args.get('search')
        if search:
            query += f" AND (title ILIKE $${param_count} OR description ILIKE $${param_count} OR file_path ILIKE $${param_count})"
            params.append(f"%{search}%")
            param_count += 1
        
        query += " ORDER BY severity DESC, detected_at DESC LIMIT 100"
        
        cur.execute(query, params)
        findings = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify(findings)
        
    except Exception as e:
        logger.error(f"Error filtering findings: {e}")
        return jsonify([]), 500

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

# ============ STATISTIQUES EN TEMPS RÉEL ============

@socketio.on('subscribe_stats')
def handle_subscribe_stats():
    """S'abonner aux mises à jour des statistiques"""
    emit('stats_update', get_realtime_stats())
    
    # Mettre à jour périodiquement
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
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Dernier scan
        cur.execute("""
            SELECT scan_id, repo_url, status, created_at
            FROM scans ORDER BY created_at DESC LIMIT 1
        """)
        last_scan = cur.fetchone()
        
        # Statistiques des 5 dernières minutes
        cur.execute("""
            SELECT 
                COUNT(*) as scans_5min,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_5min
            FROM scans
            WHERE created_at > NOW() - INTERVAL '5 minutes'
        """)
        recent_stats = cur.fetchone()
        
        # Vulnérabilités par sévérité
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

def broadcast_updates():
    """Broadcast updates to connected clients"""
    while True:
        socketio.sleep(30)
        socketio.emit('refresh', {'data': 'Refresh dashboard'})
        logger.debug("Broadcast refresh signal")

# Start background task
socketio.start_background_task(broadcast_updates)

# Démarrer le scan scheduler (CORRIGÉ - sans before_first_request)
try:
    scan_scheduler.start()
    logger.info("✅ Scan Scheduler started")
except Exception as e:
    logger.error(f"❌ Failed to start scan scheduler: {e}")

if __name__ == '__main__':
    logger.info("Starting dashboard server...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)