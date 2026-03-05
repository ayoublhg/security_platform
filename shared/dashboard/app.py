#!/usr/bin/env python3
"""
Unified Security Dashboard
Combines data from Platform and Security components
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import asyncpg
import redis
import json
import aiohttp
import asyncio
from datetime import datetime, timedelta
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Database connection pool
db_pool = None
redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)

def init_db():
    """Initialize database connection pool"""
    global db_pool
    try:
        db_pool = asyncpg.create_pool(
            user=os.getenv('POSTGRES_USER', 'postgres'),
            password=os.getenv('POSTGRES_PASSWORD', 'secure_password'),
            database=os.getenv('POSTGRES_DB', 'security_platform'),
            host='postgres',
            port=5432,
            min_size=5,
            max_size=10
        )
        logger.info("✅ Dashboard connected to PostgreSQL")
    except Exception as e:
        logger.error(f"❌ Failed to connect to PostgreSQL: {e}")

@app.before_request
async def before_request():
    """Initialize DB before first request"""
    global db_pool
    if db_pool is None:
        init_db()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/overview')
async def get_overview():
    """Get security overview metrics"""
    
    # Mock data for now (since tables may not exist yet)
    return jsonify({
        'current': {
            'critical_open': 3,
            'high_open': 7,
            'medium': 12,
            'low': 25,
            'avg_age_hours': 48
        },
        'trends': [
            {'date': '2024-01-01', 'critical': 2, 'high': 5, 'total': 10},
            {'date': '2024-01-02', 'critical': 3, 'high': 6, 'total': 12},
            {'date': '2024-01-03', 'critical': 1, 'high': 4, 'total': 8}
        ],
        'compliance': [
            {'framework': 'SOC2', 'compliance_score': 85},
            {'framework': 'PCI-DSS', 'compliance_score': 72},
            {'framework': 'HIPAA', 'compliance_score': 90}
        ],
        'scans': {
            'total_scans_24h': 15,
            'successful_24h': 14,
            'failed_24h': 1
        },
        'timestamp': datetime.now().isoformat()
    })
@app.route('/api/findings/open')
def get_open_findings():
    """Get open findings for remediation queue"""
    try:
        conn = get_db()
        if not conn:
            # Return mock data if database unavailable
            return jsonify([
                {
                    'finding_id': 'mock-1',
                    'title': 'Critical SQL Injection',
                    'severity': 'critical',
                    'type': 'sast',
                    'found_at': (datetime.now() - timedelta(days=2)).isoformat(),
                    'age_hours': 48,
                    'status': 'open'
                },
                {
                    'finding_id': 'mock-2',
                    'title': 'XSS Vulnerability',
                    'severity': 'high',
                    'type': 'sast',
                    'found_at': (datetime.now() - timedelta(days=5)).isoformat(),
                    'age_hours': 120,
                    'status': 'open'
                },
                {
                    'finding_id': 'mock-3',
                    'title': 'Hardcoded AWS Key',
                    'severity': 'critical',
                    'type': 'secret',
                    'found_at': (datetime.now() - timedelta(days=1)).isoformat(),
                    'age_hours': 24,
                    'status': 'open'
                }
            ])
        
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT finding_id, title, severity, finding_type, detected_at, status
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
            LIMIT 10
        """)
        
        findings = cur.fetchall()
        cur.close()
        conn.close()
        
        result = []
        for f in findings:
            age_hours = 0
            if f['detected_at']:
                age = datetime.now() - f['detected_at']
                age_hours = int(age.total_seconds() / 3600)
            
            result.append({
                'finding_id': f['finding_id'],
                'title': f['title'] or 'No title',
                'severity': f['severity'],
                'type': f['finding_type'] or 'unknown',
                'found_at': f['detected_at'].isoformat() if f['detected_at'] else None,
                'age_hours': age_hours,
                'status': f['status']
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in get_open_findings: {e}")
        return jsonify([])

@app.route('/api/remediate/<finding_id>', methods=['POST'])
async def trigger_remediation(finding_id):
    """Trigger remediation for a finding"""
    
    data = request.json
    strategy = data.get('strategy', 'auto')
    
    # Mock response
    return jsonify({
        'status': 'completed',
        'message': f'Remediation triggered for {finding_id}'
    })

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'data': 'Connected to security dashboard'})

@socketio.on('subscribe_tenant')
def handle_subscribe(data):
    """Subscribe to tenant updates"""
    tenant_id = data.get('tenant_id')
    emit('subscribed', {'tenant': tenant_id})

def broadcast_updates():
    """Broadcast updates to connected clients (runs in thread)"""
    while True:
        socketio.sleep(30)
        socketio.emit('refresh', {'data': 'Refresh dashboard'})

# Start background task
socketio.start_background_task(broadcast_updates)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)