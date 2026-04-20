/**
 * Enterprise Security Platform - Main Dashboard JavaScript
 */

// Global state
let dashboardState = {
    currentTenant: 'default',
    currentView: 'dashboard',
    filters: {
        severity: 'all',
        status: 'all',
        scanner: 'all'
    },
    refreshInterval: 30000, // 30 seconds
    charts: {}
};

// Socket.IO connection
const socket = io();

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    console.log('Dashboard initializing...');
    
    // Initialize event listeners
    initializeEventListeners();
    
    // Load initial data
    loadDashboardData();
    
    // Start auto-refresh
    startAutoRefresh();
    
    // Initialize WebSocket handlers
    initializeWebSocket();
});

// WebSocket handlers
function initializeWebSocket() {
    socket.on('connect', () => {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
        
        // Subscribe to tenant
        socket.emit('subscribe_tenant', { tenant_id: dashboardState.currentTenant });
    });
    
    socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
    });
    
    socket.on('scan_update', (data) => {
        console.log('Scan update received:', data);
        handleScanUpdate(data);
    });
    
    socket.on('finding_update', (data) => {
        console.log('Finding update received:', data);
        handleFindingUpdate(data);
    });
    
    socket.on('critical_alert', (data) => {
        console.log('Critical alert received:', data);
        showNotification(data.message, 'danger');
        loadDashboardData(); // Refresh data
    });
    
    socket.on('remediation_update', (data) => {
        console.log('Remediation update:', data);
        loadRemediationQueue();
    });
    
    socket.on('stats_update', (data) => {
        console.log('Stats update:', data);
        updateStats(data);
    });
    
    socket.on('refresh', () => {
        console.log('Refresh requested');
        loadDashboardData();
    });
}

// Event listeners
function initializeEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = e.target.dataset.view;
            navigateTo(view);
        });
    });
    
    // Filter changes
    document.getElementById('severity-filter')?.addEventListener('change', (e) => {
        dashboardState.filters.severity = e.target.value;
        loadFindings();
    });
    
    document.getElementById('status-filter')?.addEventListener('change', (e) => {
        dashboardState.filters.status = e.target.value;
        loadFindings();
    });
    
    // Refresh button
    document.getElementById('refresh-btn')?.addEventListener('click', () => {
        loadDashboardData();
    });
    
    // New scan button
    document.getElementById('new-scan-btn')?.addEventListener('click', () => {
        showNewScanModal();
    });
}

// Navigation
function navigateTo(view) {
    dashboardState.currentView = view;
    
    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-view="${view}"]`).classList.add('active');
    
    // Hide all views
    document.querySelectorAll('.view').forEach(el => {
        el.style.display = 'none';
    });
    
    // Show selected view
    document.getElementById(`${view}-view`).style.display = 'block';
    
    // Load view-specific data
    switch(view) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'scans':
            loadScans();
            break;
        case 'findings':
            loadFindings();
            break;
        case 'compliance':
            loadCompliance();
            break;
        case 'reports':
            loadReports();
            break;
    }
}

// Data loading functions
async function loadDashboardData() {
    showLoading(true);
    
    try {
        const response = await fetch('/api/overview');
        const data = await response.json();
        
        updateStats(data.current);
        updateTrendChart(data.trends);
        updateComplianceChart(data.compliance);
        updateRecentScans(data.recent_scans);
        updateCriticalFindings(data.critical_findings);
        
        // Load remediation queue
        await loadRemediationQueue();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showNotification('Failed to load dashboard data', 'danger');
    } finally {
        showLoading(false);
    }
}

async function loadScans() {
    showLoading(true);
    
    try {
        const response = await fetch('/api/scans?limit=50');
        const scans = await response.json();
        
        updateScansTable(scans);
        
    } catch (error) {
        console.error('Error loading scans:', error);
        showNotification('Failed to load scans', 'danger');
    } finally {
        showLoading(false);
    }
}

async function loadFindings() {
    showLoading(true);
    
    try {
        const params = new URLSearchParams(dashboardState.filters);
        params.append('limit', '100');
        
        const response = await fetch(`/api/findings?${params}`);
        const findings = await response.json();
        
        updateFindingsTable(findings);
        
    } catch (error) {
        console.error('Error loading findings:', error);
        showNotification('Failed to load findings', 'danger');
    } finally {
        showLoading(false);
    }
}

async function loadRemediationQueue() {
    try {
        const response = await fetch('/api/remediation/queue');
        const queue = await response.json();
        
        updateRemediationQueue(queue);
        
    } catch (error) {
        console.error('Error loading remediation queue:', error);
    }
}

async function loadCompliance() {
    showLoading(true);
    
    try {
        const response = await fetch('/api/compliance/summary');
        const data = await response.json();
        
        updateComplianceSummary(data);
        
    } catch (error) {
        console.error('Error loading compliance data:', error);
        showNotification('Failed to load compliance data', 'danger');
    } finally {
        showLoading(false);
    }
}

async function loadReports() {
    showLoading(true);
    
    try {
        const response = await fetch('/api/reports');
        const reports = await response.json();
        
        updateReportsList(reports);
        
    } catch (error) {
        console.error('Error loading reports:', error);
        showNotification('Failed to load reports', 'danger');
    } finally {
        showLoading(false);
    }
}

// UI Update functions
function updateStats(stats) {
    document.getElementById('critical-count').textContent = stats.critical_open || 0;
    document.getElementById('high-count').textContent = stats.high_open || 0;
    document.getElementById('medium-count').textContent = stats.medium || 0;
    document.getElementById('low-count').textContent = stats.low || 0;
}

function updateTrendChart(trends) {
    if (!trends || trends.length === 0) return;
    
    const trace1 = {
        x: trends.map(t => t.date),
        y: trends.map(t => t.critical),
        type: 'scatter',
        mode: 'lines+markers',
        name: 'Critical',
        line: { color: '#e74c3c' }
    };
    
    const trace2 = {
        x: trends.map(t => t.date),
        y: trends.map(t => t.high),
        type: 'scatter',
        mode: 'lines+markers',
        name: 'High',
        line: { color: '#e67e22' }
    };
    
    const trace3 = {
        x: trends.map(t => t.date),
        y: trends.map(t => t.medium),
        type: 'scatter',
        mode: 'lines+markers',
        name: 'Medium',
        line: { color: '#f1c40f' }
    };
    
    const layout = {
        margin: { t: 20, r: 20, b: 40, l: 50 },
        showlegend: true,
        legend: { orientation: 'h', y: 1.1 },
        xaxis: { title: 'Date' },
        yaxis: { title: 'Findings' }
    };
    
    Plotly.newPlot('trend-chart', [trace1, trace2, trace3], layout);
}

function updateComplianceChart(compliance) {
    if (!compliance || compliance.length === 0) return;
    
    const data = [{
        values: compliance.map(c => c.compliance_score),
        labels: compliance.map(c => c.framework),
        type: 'pie',
        hole: 0.4,
        marker: {
            colors: ['#27ae60', '#f1c40f', '#e74c3c', '#3498db']
        }
    }];
    
    const layout = {
        margin: { t: 10, b: 10, l: 10, r: 10 },
        showlegend: true
    };
    
    Plotly.newPlot('compliance-chart', data, layout);
}

function updateRecentScans(scans) {
    const tbody = document.getElementById('recent-scans');
    if (!tbody) return;
    
    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center">No recent scans</td></tr>';
        return;
    }
    
    let html = '';
    scans.forEach(scan => {
        html += `
            <tr onclick="viewScan('${scan.scan_id}')" style="cursor: pointer;">
                <td>
                    <span class="status-indicator status-${scan.status}"></span>
                    ${scan.status}
                </td>
                <td>${scan.repo_url.split('/').pop()}</td>
                <td>${new Date(scan.start_time).toLocaleString()}</td>
                <td>
                    <span class="badge badge-critical">${scan.summary?.critical || 0}</span>
                    <span class="badge badge-high">${scan.summary?.high || 0}</span>
                    <span class="badge badge-medium">${scan.summary?.medium || 0}</span>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function updateCriticalFindings(findings) {
    const container = document.getElementById('critical-findings');
    if (!container) return;
    
    if (!findings || findings.length === 0) {
        container.innerHTML = '<div class="list-group-item">No critical findings</div>';
        return;
    }
    
    let html = '';
    findings.slice(0, 5).forEach(finding => {
        html += `
            <div class="list-group-item" onclick="viewFinding('${finding.finding_id}')" style="cursor: pointer;">
                <div class="d-flex justify-content-between">
                    <strong>${finding.title}</strong>
                    <span class="badge badge-critical">${finding.severity}</span>
                </div>
                <small>${finding.file}:${finding.line}</small>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function updateRemediationQueue(queue) {
    const tbody = document.getElementById('remediation-queue');
    if (!tbody) return;
    
    if (!queue || queue.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No pending remediations</td></tr>';
        return;
    }
    
    let html = '';
    queue.forEach(item => {
        html += `
            <tr>
                <td><code>${item.finding_id.substring(0, 8)}</code></td>
                <td><span class="badge badge-${item.severity}">${item.severity}</span></td>
                <td>${item.type}</td>
                <td>${Math.round((new Date() - new Date(item.found_at)) / 3600000)}h</td>
                <td>
                    <span class="badge badge-${item.status === 'pending' ? 'warning' : 'info'}">
                        ${item.status}
                    </span>
                </td>
                <td>
                    <button class="btn btn-primary btn-sm" onclick="remediate('${item.finding_id}')">
                        Remediate
                    </button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function updateScansTable(scans) {
    const tbody = document.getElementById('scans-table');
    if (!tbody) return;
    
    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">No scans found</td></tr>';
        return;
    }
    
    let html = '';
    scans.forEach(scan => {
        html += `
            <tr onclick="viewScan('${scan.scan_id}')" style="cursor: pointer;">
                <td>
                    <span class="status-indicator status-${scan.status}"></span>
                    ${scan.status}
                </td>
                <td>${scan.repo_url}</td>
                <td>${new Date(scan.start_time).toLocaleString()}</td>
                <td>
                    <span class="badge badge-critical">${scan.summary?.critical || 0}</span>
                    <span class="badge badge-high">${scan.summary?.high || 0}</span>
                    <span class="badge badge-medium">${scan.summary?.medium || 0}</span>
                </td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); viewScan('${scan.scan_id}')">
                        View
                    </button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function updateFindingsTable(findings) {
    const tbody = document.getElementById('findings-table');
    if (!tbody) return;
    
    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No findings found</td></tr>';
        return;
    }
    
    let html = '';
    findings.forEach(finding => {
        html += `
            <tr onclick="viewFinding('${finding.finding_id}')" style="cursor: pointer;">
                <td><span class="badge badge-${finding.severity}">${finding.severity}</span></td>
                <td>${finding.title.substring(0, 50)}${finding.title.length > 50 ? '...' : ''}</td>
                <td>${finding.scanner}</td>
                <td>${finding.file || 'N/A'}:${finding.line || 'N/A'}</td>
                <td>
                    <span class="badge badge-${finding.status === 'open' ? 'danger' : 'success'}">
                        ${finding.status}
                    </span>
                </td>
                <td>
                    <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); remediate('${finding.finding_id}')">
                        Fix
                    </button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function updateComplianceSummary(data) {
    // Update compliance scores
    if (data.scores) {
        Object.entries(data.scores).forEach(([framework, score]) => {
            const element = document.getElementById(`compliance-${framework.toLowerCase()}`);
            if (element) {
                element.textContent = `${score}%`;
            }
        });
    }
    
    // Update findings by framework
    if (data.findings_by_framework) {
        // TODO: Update chart
    }
}

function updateReportsList(reports) {
    const tbody = document.getElementById('reports-table');
    if (!tbody) return;
    
    if (!reports || reports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center">No reports found</td></tr>';
        return;
    }
    
    let html = '';
    reports.forEach(report => {
        html += `
            <tr>
                <td>${report.report_type}</td>
                <td>${report.framework || 'N/A'}</td>
                <td>${new Date(report.generated_at).toLocaleString()}</td>
                <td>
                    <a href="${report.html_path}" class="btn btn-sm btn-secondary" target="_blank">HTML</a>
                    <a href="${report.pdf_path}" class="btn btn-sm btn-secondary" target="_blank">PDF</a>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Action functions
async function remediate(findingId) {
    if (!confirm('Start remediation for this finding?')) return;
    
    try {
        const response = await fetch(`/api/remediate/${findingId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ strategy: 'auto' })
        });
        
        const result = await response.json();
        
        if (result.status === 'completed') {
            showNotification('✅ Remediation completed', 'success');
        } else {
            showNotification(`ℹ️ ${result.message}`, 'info');
        }
        
        // Refresh data
        loadDashboardData();
        
    } catch (error) {
        console.error('Error triggering remediation:', error);
        showNotification('Failed to trigger remediation', 'danger');
    }
}

function viewScan(scanId) {
    window.location.href = `/scan/${scanId}`;
}

function viewFinding(findingId) {
    window.location.href = `/finding/${findingId}`;
}

function showNewScanModal() {
    // TODO: Implement modal
    alert('New scan modal - to be implemented');
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        statusEl.innerHTML = connected 
            ? '<i class="fas fa-circle text-success"></i> Connected'
            : '<i class="fas fa-circle text-danger"></i> Disconnected';
    }
}

function showNotification(message, type = 'info') {
    const toast = document.getElementById('toast-container') || createToastContainer();
    
    const toastEl = document.createElement('div');
    toastEl.className = `toast toast-${type}`;
    toastEl.innerHTML = `
        <div class="toast-content">
            ${message}
            <button class="toast-close" onclick="this.parentElement.parentElement.remove()">&times;</button>
        </div>
    `;
    
    toast.appendChild(toastEl);
    
    setTimeout(() => {
        toastEl.remove();
    }, 5000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
    return container;
}

function showLoading(show) {
    const loader = document.getElementById('loading-spinner');
    if (loader) {
        loader.style.display = show ? 'block' : 'none';
    }
}

function startAutoRefresh() {
    setInterval(() => {
        if (dashboardState.currentView === 'dashboard') {
            loadDashboardData();
        }
    }, dashboardState.refreshInterval);
}

function handleScanUpdate(data) {
    // Update scan status in UI if visible
    if (dashboardState.currentView === 'scans') {
        loadScans();
    } else if (dashboardState.currentView === 'dashboard') {
        loadDashboardData();
    }
}

function handleFindingUpdate(data) {
    // Update findings if visible
    if (dashboardState.currentView === 'findings') {
        loadFindings();
    } else if (dashboardState.currentView === 'dashboard') {
        loadDashboardData();
    }
}

// Export functions for HTML onclick handlers
window.remediate = remediate;
window.viewScan = viewScan;
window.viewFinding = viewFinding;