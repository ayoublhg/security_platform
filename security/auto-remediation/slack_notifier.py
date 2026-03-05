#!/usr/bin/env python3
"""
Slack Notifier for Security Alerts
Sends notifications to Slack channels
"""

import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import aiohttp
import json

logger = logging.getLogger(__name__)

class SlackNotifier:
    """Slack integration for security notifications"""
    
    def __init__(self):
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL', '')
        self.token = os.getenv('SLACK_TOKEN', '')
        self.default_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        
    async def send_alert(self, finding: Dict, channel: Optional[str] = None) -> bool:
        """Send a security alert to Slack"""
        channel = channel or self.default_channel
        
        # Create message based on severity
        severity = finding.get('severity', 'medium').lower()
        
        if severity == 'critical':
            return await self._send_critical_alert(finding, channel)
        elif severity == 'high':
            return await self._send_high_alert(finding, channel)
        else:
            return await self._send_standard_alert(finding, channel)
    
    async def _send_critical_alert(self, finding: Dict, channel: str) -> bool:
        """Send critical severity alert"""
        message = {
            'channel': channel,
            'attachments': [{
                'color': 'danger',
                'title': f"🚨 CRITICAL: {finding.get('title', 'Security finding')}",
                'fields': [
                    {
                        'title': 'Severity',
                        'value': 'CRITICAL',
                        'short': True
                    },
                    {
                        'title': 'Scanner',
                        'value': finding.get('scanner', 'N/A'),
                        'short': True
                    },
                    {
                        'title': 'File',
                        'value': finding.get('file', 'N/A'),
                        'short': True
                    },
                    {
                        'title': 'Line',
                        'value': str(finding.get('line', 'N/A')),
                        'short': True
                    }
                ],
                'footer': 'Enterprise Security Platform',
                'ts': int(datetime.now().timestamp())
            }]
        }
        
        # Add CVE if present
        if finding.get('metadata', {}).get('cve'):
            message['attachments'][0]['fields'].append({
                'title': 'CVE',
                'value': finding['metadata']['cve'],
                'short': True
            })
        
        return await self._post_message(message)
    
    async def _send_high_alert(self, finding: Dict, channel: str) -> bool:
        """Send high severity alert"""
        message = {
            'channel': channel,
            'attachments': [{
                'color': 'warning',
                'title': f"⚠️ HIGH: {finding.get('title', 'Security finding')}",
                'fields': [
                    {
                        'title': 'Severity',
                        'value': 'HIGH',
                        'short': True
                    },
                    {
                        'title': 'Scanner',
                        'value': finding.get('scanner', 'N/A'),
                        'short': True
                    },
                    {
                        'title': 'Location',
                        'value': f"{finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}",
                        'short': False
                    }
                ],
                'footer': 'Enterprise Security Platform',
                'ts': int(datetime.now().timestamp())
            }]
        }
        
        return await self._post_message(message)
    
    async def _send_standard_alert(self, finding: Dict, channel: str) -> bool:
        """Send standard severity alert"""
        message = {
            'channel': channel,
            'text': f"🔍 {finding.get('severity', 'MEDIUM').upper()}: {finding.get('title', 'Security finding')}",
            'attachments': [{
                'color': 'good',
                'fields': [
                    {
                        'title': 'Scanner',
                        'value': finding.get('scanner', 'N/A'),
                        'short': True
                    },
                    {
                        'title': 'Location',
                        'value': f"{finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}",
                        'short': True
                    }
                ],
                'footer': 'Enterprise Security Platform'
            }]
        }
        
        return await self._post_message(message)
    
    async def send_scan_complete(self, scan_id: str, summary: Dict, 
                                   channel: Optional[str] = None) -> bool:
        """Send scan completion notification"""
        channel = channel or self.default_channel
        
        total = summary.get('total', 0)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        
        if critical > 0:
            color = 'danger'
            emoji = '🚨'
        elif high > 0:
            color = 'warning'
            emoji = '⚠️'
        else:
            color = 'good'
            emoji = '✅'
        
        message = {
            'channel': channel,
            'attachments': [{
                'color': color,
                'title': f"{emoji} Security Scan Complete",
                'fields': [
                    {
                        'title': 'Scan ID',
                        'value': scan_id,
                        'short': True
                    },
                    {
                        'title': 'Total Findings',
                        'value': str(total),
                        'short': True
                    },
                    {
                        'title': 'Critical',
                        'value': str(critical),
                        'short': True
                    },
                    {
                        'title': 'High',
                        'value': str(high),
                        'short': True
                    },
                    {
                        'title': 'Medium',
                        'value': str(summary.get('medium', 0)),
                        'short': True
                    },
                    {
                        'title': 'Low',
                        'value': str(summary.get('low', 0)),
                        'short': True
                    }
                ],
                'footer': 'Enterprise Security Platform',
                'ts': int(datetime.now().timestamp())
            }]
        }
        
        return await self._post_message(message)
    
    async def send_remediation_status(self, finding_id: str, status: str,
                                        details: Dict, channel: Optional[str] = None) -> bool:
        """Send remediation status update"""
        channel = channel or self.default_channel
        
        status_emoji = {
            'started': '🔄',
            'completed': '✅',
            'failed': '❌',
            'approved': '👍',
            'rejected': '👎'
        }
        
        emoji = status_emoji.get(status, '📋')
        
        message = {
            'channel': channel,
            'attachments': [{
                'color': 'info',
                'title': f"{emoji} Remediation {status.title()}: {finding_id}",
                'fields': [
                    {
                        'title': 'Finding ID',
                        'value': finding_id,
                        'short': True
                    },
                    {
                        'title': 'Status',
                        'value': status,
                        'short': True
                    }
                ],
                'footer': 'Enterprise Security Platform'
            }]
        }
        
        # Add PR/ticket links
        if details.get('pr_url'):
            message['attachments'][0]['fields'].append({
                'title': 'Pull Request',
                'value': details['pr_url'],
                'short': False
            })
        
        if details.get('ticket_url'):
            message['attachments'][0]['fields'].append({
                'title': 'Jira Ticket',
                'value': details['ticket_url'],
                'short': False
            })
        
        return await self._post_message(message)
    
    async def _post_message(self, message: Dict) -> bool:
        """Post message to Slack"""
        if not self.webhook_url and not self.token:
            logger.warning("Slack not configured")
            return False
        
        try:
            if self.webhook_url:
                # Use webhook
                async with aiohttp.ClientSession() as session:
                    async with session.post(self.webhook_url, json=message) as resp:
                        return resp.status == 200
            else:
                # Use token (not implemented in this example)
                logger.warning("Slack token method not implemented")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False
    
    async def send_daily_summary(self, stats: Dict, channel: Optional[str] = None) -> bool:
        """Send daily security summary"""
        channel = channel or self.default_channel
        
        message = {
            'channel': channel,
            'attachments': [{
                'color': 'info',
                'title': '📊 Daily Security Summary',
                'fields': [
                    {
                        'title': 'New Findings',
                        'value': str(stats.get('new_findings', 0)),
                        'short': True
                    },
                    {
                        'title': 'Remediated',
                        'value': str(stats.get('remediated', 0)),
                        'short': True
                    },
                    {
                        'title': 'Open Critical',
                        'value': str(stats.get('open_critical', 0)),
                        'short': True
                    },
                    {
                        'title': 'Open High',
                        'value': str(stats.get('open_high', 0)),
                        'short': True
                    },
                    {
                        'title': 'Scans Run',
                        'value': str(stats.get('scans_run', 0)),
                        'short': True
                    },
                    {
                        'title': 'Compliance Score',
                        'value': f"{stats.get('compliance_score', 0)}%",
                        'short': True
                    }
                ],
                'footer': 'Enterprise Security Platform',
                'ts': int(datetime.now().timestamp())
            }]
        }
        
        return await self._post_message(message)