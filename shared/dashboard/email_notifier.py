#!/usr/bin/env python3
"""
Système de notifications par email - Enhanced with Grafana integration
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional
import asyncio
import requests

logger = logging.getLogger(__name__)

class EmailNotifier:
    """Gère l'envoi d'emails de notification"""
    
    def __init__(self):
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.from_email = os.getenv('FROM_EMAIL', self.smtp_user)
        self.enabled = bool(self.smtp_user and self.smtp_password)
        
        # Grafana webhook URL (for alerts)
        self.grafana_webhook = os.getenv('GRAFANA_WEBHOOK', '')
        
        if not self.enabled:
            logger.warning("Email notifications disabled: SMTP credentials not configured")
    
    async def send_grafana_alert(self, alert: Dict, recipients: List[str]):
        """Envoyer une alerte Grafana"""
        if not self.enabled:
            return
        
        severity = alert.get('labels', {}).get('severity', 'warning')
        alertname = alert.get('labels', {}).get('alertname', 'Unknown Alert')
        
        severity_colors = {
            'critical': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        }
        
        color = severity_colors.get(severity, '#6c757d')
        
        subject = f"[{severity.upper()}] {alertname} - Security Platform"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .alert {{ background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid {color}; }}
                .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }}
                .critical {{ background-color: #dc3545; }}
                .warning {{ background-color: #ffc107; color: black; }}
                .info {{ background-color: #17a2b8; }}
                .footer {{ background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 Alerte Grafana</h1>
                <p>{alertname}</p>
            </div>
            <div class="content">
                <div class="alert">
                    <h3>{alert.get('annotations', {}).get('summary', alertname)}</h3>
                    <p><strong>Sévérité:</strong> <span class="severity {severity}">{severity.upper()}</span></p>
                    <p><strong>Description:</strong> {alert.get('annotations', {}).get('description', 'N/A')}</p>
                    <p><strong>Valeur:</strong> {alert.get('value', 'N/A')}</p>
                    <p><strong>Heure:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                </div>
                
                <h3>Actions recommandées:</h3>
                <ul>
                    <li>Connectez-vous au tableau de bord pour plus de détails</li>
                    <li>Vérifiez les logs du système</li>
                    <li>Analysez les métriques Prometheus</li>
                </ul>
                
                <p><a href="http://localhost:3000">Voir Grafana</a> | 
                   <a href="http://localhost:5000">Voir Dashboard Sécurité</a></p>
            </div>
            <div class="footer">
                <p>Enterprise Security Platform - Alerte automatique</p>
            </div>
        </body>
        </html>
        """
        
        await self._send_email(recipients, subject, html_body)
    
    async def send_metrics_report(self, metrics: Dict, recipients: List[str]):
        """Envoyer un rapport périodique des métriques"""
        if not self.enabled:
            return
        
        subject = f"📈 Rapport Métriques - {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #667eea; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .metric {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 3px solid #667eea; }}
                .metric-value {{ font-size: 18px; font-weight: bold; color: #667eea; }}
                .footer {{ background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Rapport des Métriques</h1>
                <p>{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
            </div>
            <div class="content">
                <h3>Métriques clés:</h3>
                
                <div class="metric">
                    <strong>📦 Total des scans:</strong>
                    <span class="metric-value">{metrics.get('total_scans', 0)}</span>
                </div>
                
                <div class="metric">
                    <strong>✅ Taux de succès:</strong>
                    <span class="metric-value">{metrics.get('success_rate', 0)}%</span>
                </div>
                
                <div class="metric">
                    <strong>🔍 Dernier scan:</strong>
                    <span class="metric-value">{metrics.get('last_scan_time', 'N/A')}</span>
                </div>
                
                <div class="metric">
                    <strong>⏱️ Durée moyenne des scans:</strong>
                    <span class="metric-value">{metrics.get('avg_duration', 0)}s</span>
                </div>
                
                <h3>Vulnérabilités:</h3>
                <ul>
                    <li>Critiques: <strong style="color:#dc3545">{metrics.get('critical_findings', 0)}</strong></li>
                    <li>Élevées: <strong style="color:#fd7e14">{metrics.get('high_findings', 0)}</strong></li>
                    <li>Moyennes: <strong style="color:#ffc107">{metrics.get('medium_findings', 0)}</strong></li>
                    <li>Faibles: <strong style="color:#28a745">{metrics.get('low_findings', 0)}</strong></li>
                </ul>
                
                <h3>Activité par scanner:</h3>
                <ul>
                    {''.join([f"<li><strong>{scanner}:</strong> {count} vulnérabilités</li>" for scanner, count in metrics.get('scanner_stats', {}).items()])}
                </ul>
            </div>
            <div class="footer">
                <p>Enterprise Security Platform - Rapport automatique</p>
            </div>
        </body>
        </html>
        """
        
        await self._send_email(recipients, subject, html_body)
    
    async def send_system_health(self, health_data: Dict, recipients: List[str]):
        """Envoyer un rapport de santé du système"""
        if not self.enabled:
            return
        
        subject = f"🏥 Rapport Santé Système - {datetime.now().strftime('%d/%m/%Y')}"
        
        status_emoji = "✅" if health_data.get('status') == 'healthy' else "⚠️"
        status_color = "#28a745" if health_data.get('status') == 'healthy' else "#ffc107"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: {status_color}; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .service {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 3px solid #28a745; }}
                .service-down {{ border-left-color: #dc3545; }}
                .footer {{ background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{status_emoji} Rapport de Santé Système</h1>
            </div>
            <div class="content">
                <h3>Services:</h3>
                {''.join([f'<div class="service {"" if healthy else "service-down"}">✅ <strong>{name}:</strong> {"En ligne" if healthy else "Hors ligne"}</div>' for name, healthy in health_data.get('services', {}).items()])}
                
                <h3>Métriques système:</h3>
                <ul>
                    <li>Uptime: {health_data.get('uptime', 'N/A')}</li>
                    <li>Mémoire utilisée: {health_data.get('memory_used', 'N/A')}</li>
                    <li>CPU: {health_data.get('cpu_usage', 'N/A')}%</li>
                    <li>Conteneurs actifs: {health_data.get('active_containers', 0)}</li>
                </ul>
            </div>
            <div class="footer">
                <p>Enterprise Security Platform - Rapport santé automatique</p>
            </div>
        </body>
        </html>
        """
        
        await self._send_email(recipients, subject, html_body)
    
    async def send_critical_alert(self, finding: Dict, tenant_id: str, recipients: List[str]):
        """Envoyer une alerte pour une vulnérabilité critique"""
        if not self.enabled:
            return
        
        subject = f"🚨 ALERTE CRITIQUE - {finding.get('title', 'Vulnérabilité détectée')}"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #dc3545; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .finding {{ background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; }}
                .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }}
                .critical {{ background-color: #dc3545; }}
                .footer {{ background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 Alerte de Sécurité Critique</h1>
            </div>
            <div class="content">
                <p>Bonjour,</p>
                <p>Une vulnérabilité <strong>CRITIQUE</strong> a été détectée dans votre infrastructure.</p>
                
                <div class="finding">
                    <h3>{finding.get('title', 'Vulnérabilité critique')}</h3>
                    <p><strong>Severité:</strong> <span class="severity critical">CRITICAL</span></p>
                    <p><strong>Scanner:</strong> {finding.get('scanner', 'N/A')}</p>
                    <p><strong>Fichier:</strong> {finding.get('file', 'N/A')}:{finding.get('line', 0)}</p>
                    <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
                </div>
                
                <p><strong>Action requise:</strong> Correction immédiate requise dans les 24 heures.</p>
                <p><a href="http://localhost:5000">Voir le dashboard</a></p>
            </div>
            <div class="footer">
                <p>Enterprise Security Platform - {datetime.now().year}</p>
                <p>Ce message a été généré automatiquement.</p>
            </div>
        </body>
        </html>
        """
        
        await self._send_email(recipients, subject, html_body)
    
    async def send_daily_summary(self, tenant_id: str, stats: Dict, recipients: List[str]):
        """Envoyer un résumé quotidien"""
        if not self.enabled:
            return
        
        subject = f"📊 Résumé Sécurité - {datetime.now().strftime('%d/%m/%Y')}"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #667eea; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .stats {{ display: flex; gap: 10px; margin: 20px 0; }}
                .stat {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; flex: 1; }}
                .stat-value {{ font-size: 24px; font-weight: bold; }}
                .stat-critical {{ color: #dc3545; }}
                .stat-high {{ color: #fd7e14; }}
                .stat-medium {{ color: #ffc107; }}
                .footer {{ background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Résumé Quotidien de Sécurité</h1>
                <p>{datetime.now().strftime('%d/%m/%Y')}</p>
            </div>
            <div class="content">
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value stat-critical">{stats.get('critical', 0)}</div>
                        <div>Critiques</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value stat-high">{stats.get('high', 0)}</div>
                        <div>Élevées</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value stat-medium">{stats.get('medium', 0)}</div>
                        <div>Moyennes</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{stats.get('total', 0)}</div>
                        <div>Total</div>
                    </div>
                </div>
                
                <h3>Activité des dernières 24h</h3>
                <ul>
                    <li>Scans effectués: {stats.get('scans_today', 0)}</li>
                    <li>Nouvelles vulnérabilités: {stats.get('new_findings', 0)}</li>
                    <li>Vulnérabilités corrigées: {stats.get('fixed_findings', 0)}</li>
                </ul>
                
                <p><a href="http://localhost:5000">Accéder au tableau de bord complet</a></p>
            </div>
            <div class="footer">
                <p>Enterprise Security Platform - {datetime.now().year}</p>
            </div>
        </body>
        </html>
        """
        
        await self._send_email(recipients, subject, html_body)
    
    async def send_scan_complete(self, scan_id: str, repo_url: str, summary: Dict, recipients: List[str]):
        """Envoyer une notification de scan terminé"""
        if not self.enabled:
            return
        
        subject = f"✅ Scan terminé - {repo_url.split('/')[-1]}"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #28a745; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; margin: 10px 0; }}
                .footer {{ background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>✅ Scan Terminé</h1>
            </div>
            <div class="content">
                <p>Le scan du dépôt <strong>{repo_url}</strong> est terminé.</p>
                
                <div class="summary">
                    <h3>Résultats:</h3>
                    <ul>
                        <li>Critiques: {summary.get('critical', 0)}</li>
                        <li>Élevées: {summary.get('high', 0)}</li>
                        <li>Moyennes: {summary.get('medium', 0)}</li>
                        <li>Faibles: {summary.get('low', 0)}</li>
                        <li>Total: {summary.get('total', 0)}</li>
                    </ul>
                </div>
                
                <p><a href="http://localhost:5000/scans/{scan_id}">Voir les détails du scan</a></p>
            </div>
            <div class="footer">
                <p>Enterprise Security Platform</p>
            </div>
        </body>
        </html>
        """
        
        await self._send_email(recipients, subject, html_body)
    
    async def _send_email(self, recipients: List[str], subject: str, html_body: str):
        """Envoyer un email"""
        if not self.enabled or not recipients:
            return
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(recipients)
            
            part = MIMEText(html_body, 'html')
            msg.attach(part)
            
            # Exécution synchrone dans un thread séparé
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_sync, msg)
            
            logger.info(f"Email sent to {', '.join(recipients)}")
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
    
    def _send_sync(self, msg):
        """Envoi synchrone de l'email"""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
                logger.debug(f"Email sent successfully via {self.smtp_host}")
        except Exception as e:
            logger.error(f"SMTP send error: {e}")
            raise