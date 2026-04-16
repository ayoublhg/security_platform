#!/usr/bin/env python3
"""
Système de notifications par email
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
        
        if not self.enabled:
            logger.warning("Email notifications disabled: SMTP credentials not configured")
    
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
        
        # CORRECTION 1: Lien href corrigé
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
            
            # CORRECTION 2: Exécution synchrone dans un thread séparé
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