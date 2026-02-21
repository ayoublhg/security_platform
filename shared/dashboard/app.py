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
from datetime import datetime, timedelta
import plotly
import plotly.graph_objs as go
import pandas as pd

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection pool
db_pool = None
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

@app.before_first_request
async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(
        user="postgres",
        password="secure_password",
        database="security_platform",
        host="postgres",
        min_size=5,
        max_size=10
    )

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/overview')
async def get_overview():
    """Get security overview metrics"""
    
    async with db_pool.acquire() as conn:
        # Get current stats
        current = await conn.fetchrow("""
            SELECT 
                COUNT(*) FILTER (WHERE status = 'open' AND severity = 'critical') as critical_open,
                COUNT(*) FILTER (WHERE status = 'open' AND severity = 'high') as high_open,
                COUNT(*) FILTER (WHERE status = 'open') as total_open,
                AVG(EXTRACT(EPOCH FROM (NOW() - found_at))/3600) FILTER (WHERE status = 'open') as avg_age_hours
            FROM findings
        """)
        
        # Get trends
        trends = await conn.fetch("""
            SELECT 
                DATE(found_at) as date,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) as total
            FROM findings
            WHERE found_at >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(found_at)
            ORDER BY date DESC
        """)
        
        # Get compliance status
        compliance = await conn.fetch("""
            SELECT 
                framework,
                compliance_score,
                report_date
            FROM compliance_reports cr1
            WHERE report_date = (
                SELECT MAX(report_date)
                FROM compliance_reports cr2
                WHERE cr2.framework = cr1.framework
            )
        """)
        
        # Get scan stats
        scans = await conn.fetchrow("""
            SELECT 
                COUNT(*) as total_scans_24h,
                COUNT(*) FILTER (WHERE status = 'completed') as successful_24h,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_24h
            FROM scans
            WHERE start_time >= NOW() - INTERVAL '24 hours'
        """)
    
    return jsonify({
        'current': dict(current),
        'trends': [dict(row) for row in trends],
        'compliance': [dict(row) for row in compliance],
        'scans': dict(scans),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/tenant/<tenant_id>')
async def get_tenant_dashboard(tenant_id):
    """Get tenant-specific dashboard data"""
    
    async with db_pool.acquire() as conn:
        # Tenant info
        tenant = await conn.fetchrow(
            "SELECT * FROM tenants WHERE tenant_id = $1",
            tenant_id
        )
        
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        # Tenant findings
        findings = await conn.fetch("""
            SELECT 
                severity,
                COUNT(*) as count
            FROM findings
            WHERE tenant_id = $1 AND status = 'open'
            GROUP BY severity
        """, tenant_id)
        
        # Recent scans
        scans = await conn.fetch("""
            SELECT 
                scan_id,
                repo_url,
                start_time,
                status,
                summary
            FROM scans
            WHERE tenant_id = $1
            ORDER BY start_time DESC
            LIMIT 10
        """, tenant_id)
        
        # Compliance score trend
        compliance = await conn.fetch("""
            SELECT 
                report_date,
                framework,
                compliance_score
            FROM compliance_reports
            WHERE tenant_id = $1
                AND report_date >= NOW() - INTERVAL '90 days'
            ORDER BY report_date DESC
        """, tenant_id)
    
    return jsonify({
        'tenant': dict(tenant),
        'findings': [dict(row) for row in findings],
        'recent_scans': [dict(row) for row in scans],
        'compliance_trend': [dict(row) for row in compliance]
    })

@app.route('/api/compliance/report')
async def generate_compliance_report():
    """Generate comprehensive compliance report"""
    
    framework = request.args.get('framework', 'SOC2')
    tenant_id = request.args.get('tenant_id', 'default')
    
    async with db_pool.acquire() as conn:
        # Get all open findings for tenant
        findings = await conn.fetch("""
            SELECT f.*, 
                   cr.compliance_score,
                   cr.controls_passed,
                   cr.controls_failed
            FROM findings f
            LEFT JOIN compliance_reports cr 
                ON cr.tenant_id = f.tenant_id 
                AND cr.framework = $1
            WHERE f.tenant_id = $2
                AND f.status = 'open'
            ORDER BY f.severity DESC
        """, framework, tenant_id)
        
        # Get remediation history
        remediation = await conn.fetch("""
            SELECT 
                DATE(remediated_at) as date,
                COUNT(*) as fixed_count
            FROM findings
            WHERE tenant_id = $1
                AND remediated_at IS NOT NULL
                AND remediated_at >= NOW() - INTERVAL '90 days'
            GROUP BY DATE(remediated_at)
            ORDER BY date
        """, tenant_id)
    
    # Create visualizations
    fig_findings = go.Figure(data=[
        go.Bar(
            x=['Critical', 'High', 'Medium', 'Low'],
            y=[
                sum(1 for f in findings if f['severity'] == 'critical'),
                sum(1 for f in findings if f['severity'] == 'high'),
                sum(1 for f in findings if f['severity'] == 'medium'),
                sum(1 for f in findings if f['severity'] == 'low')
            ],
            marker_color=['red', 'orange', 'yellow', 'green']
        )
    ])
    
    fig_trend = go.Figure(data=[
        go.Scatter(
            x=[r['date'] for r in remediation],
            y=[r['fixed_count'] for r in remediation],
            mode='lines+markers',
            name='Fixed per day'
        )
    ])
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'framework': framework,
        'tenant_id': tenant_id,
        'summary': {
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f['severity'] == 'critical'),
            'high': sum(1 for f in findings if f['severity'] == 'high'),
            'medium': sum(1 for f in findings if f['severity'] == 'medium'),
            'low': sum(1 for f in findings if f['severity'] == 'low'),
            'avg_compliance_score': findings[0]['compliance_score'] if findings else 0
        },
        'findings': [dict(f) for f in findings],
        'remediation_trend': [dict(r) for r in remediation],
        'charts': {
            'findings_distribution': json.dumps(fig_findings, cls=plotly.utils.PlotlyJSONEncoder),
            'remediation_trend': json.dumps(fig_trend, cls=plotly.utils.PlotlyJSONEncoder)
        }
    }
    
    return jsonify(report)

@app.route('/api/remediate/<finding_id>', methods=['POST'])
async def trigger_remediation(finding_id):
    """Trigger remediation for a finding"""
    
    data = request.json
    strategy = data.get('strategy', 'auto')
    
    # Call remediation engine
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://auto-remediation:8003/api/remediate",
            json={
                'finding_id': finding_id,
                'strategy': strategy
            }
        ) as resp:
            result = await resp.json()
    
    # Log audit
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO audit_log (tenant_id, action, resource_type, resource_id, details)
            VALUES ($1, $2, $3, $4, $5)
        """, data.get('tenant_id'), 'remediation_triggered', 'finding', 
            finding_id, json.dumps({'strategy': strategy}))
    
    return jsonify(result)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'data': 'Connected to security dashboard'})

@socketio.on('subscribe_tenant')
def handle_subscribe(data):
    """Subscribe to tenant updates"""
    tenant_id = data.get('tenant_id')
    join_room(f"tenant_{tenant_id}")
    emit('subscribed', {'tenant': tenant_id})

async def broadcast_update():
    """Broadcast updates to connected clients"""
    while True:
        await asyncio.sleep(5)
        
        # Get latest metrics
        async with db_pool.acquire() as conn:
            critical = await conn.fetchval(
                "SELECT COUNT(*) FROM findings WHERE status = 'open' AND severity = 'critical'"
            )
            
            if critical > 0:
                socketio.emit('critical_alert', {
                    'count': critical,
                    'message': f'{critical} critical findings require attention'
                })

if __name__ == '__main__':
    asyncio.create_task(broadcast_update())
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)