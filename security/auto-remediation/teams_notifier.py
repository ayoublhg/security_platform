#!/usr/bin/env python3
"""
Microsoft Teams Notifier for Security Alerts
Sends notifications to Teams channels
"""

import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import aiohttp
import json

logger = logging.getLogger(__name__)

class TeamsNotifier:
    """Microsoft Teams integration for security notifications"""
    
    def __init__(self):
        self.webhook_url = os.getenv('TEAMS_WEBHOOK_URL', '')
        self.default_channel = os.getenv('TEAMS_CHANNEL', 'Security')
        
    async def send_alert(self, finding: Dict, channel: Optional[str] = None) -> bool:
        """Send a security alert to Teams"""
        severity = finding.get('severity', 'medium').lower()
        
        # Create Teams message card
        card = self._create_alert_card(finding, severity)
        return await self._post_to_teams(card)
    
    def _create_alert_card(self, finding: Dict, severity: str) -> Dict:
        """Create Teams adaptive card for alert"""
        
        # Set color based on severity
        colors = {
            'critical': 'FF0000',
            'high': 'FFA500',
            'medium': 'FFFF00',
            'low': '00FF00',
            'info': '0000FF'
        }
        color = colors.get(severity, '808080')
        
        # Create card
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Large",
                                "weight": "Bolder",
                                "text": f"🚨 Security Alert: {severity.upper()}",
                                "color": self._get_teams_color(severity)
                            },
                            {
                                "type": "TextBlock",
                                "text": finding.get('title', 'Security finding'),
                                "wrap": True,
                                "size": "Medium"
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {
                                        "title": "Severity:",
                                        "value": severity.upper()
                                    },
                                    {
                                        "title": "Scanner:",
                                        "value": finding.get('scanner', 'N/A')
                                    },
                                    {
                                        "title": "File:",
                                        "value": finding.get('file', 'N/A')
                                    },
                                    {
                                        "title": "Line:",
                                        "value": str(finding.get('line', 'N/A'))
                                    }
                                ]
                            },
                            {
                                "type": "TextBlock",
                                "text": finding.get('description', 'No description'),
                                "wrap": True,
                                "size": "Small"
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "View in Dashboard",
                                "url": f"{os.getenv('PLATFORM_URL', 'http://localhost:5000')}/findings/{finding.get('id', '')}"
                            }
                        ]
                    }
                }
            ]
        }
        
        # Add CVE if present
        if finding.get('metadata', {}).get('cve'):
            card["attachments"][0]["content"]["body"][2]["facts"].append({
                "title": "CVE:",
                "value": finding['metadata']['cve']
            })
        
        return card
    
    def _create_remediation_card(self, finding_id: str, status: str, 
                                   details: Dict) -> Dict:
        """Create Teams card for remediation status"""
        
        status_icons = {
            'started': '🔄',
            'completed': '✅',
            'failed': '❌',
            'approved': '👍',
            'rejected': '👎'
        }
        
        icon = status_icons.get(status, '📋')
        
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Medium",
                                "weight": "Bolder",
                                "text": f"{icon} Remediation {status.title()}"
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {
                                        "title": "Finding ID:",
                                        "value": finding_id
                                    },
                                    {
                                        "title": "Status:",
                                        "value": status
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        
        # Add links
        if details.get('pr_url'):
            card["attachments"][0]["content"]["actions"] = [
                {
                    "type": "Action.OpenUrl",
                    "title": "View Pull Request",
                    "url": details['pr_url']
                }
            ]
        elif details.get('ticket_url'):
            card["attachments"][0]["content"]["actions"] = [
                {
                    "type": "Action.OpenUrl",
                    "title": "View Jira Ticket",
                    "url": details['ticket_url']
                }
            ]
        
        return card
    
    def _create_scan_complete_card(self, scan_id: str, summary: Dict) -> Dict:
        """Create Teams card for scan completion"""
        
        total = summary.get('total', 0)
        critical = summary.get('critical', 0)
        
        if critical > 0:
            color = "attention"
            icon = "🚨"
        else:
            color = "good"
            icon = "✅"
        
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Large",
                                "weight": "Bolder",
                                "text": f"{icon} Security Scan Complete",
                                "color": color
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {
                                        "title": "Scan ID:",
                                        "value": scan_id
                                    },
                                    {
                                        "title": "Total Findings:",
                                        "value": str(total)
                                    },
                                    {
                                        "title": "Critical:",
                                        "value": str(critical)
                                    },
                                    {
                                        "title": "High:",
                                        "value": str(summary.get('high', 0))
                                    },
                                    {
                                        "title": "Medium:",
                                        "value": str(summary.get('medium', 0))
                                    },
                                    {
                                        "title": "Low:",
                                        "value": str(summary.get('low', 0))
                                    }
                                ]
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "View Results",
                                "url": f"{os.getenv('PLATFORM_URL', 'http://localhost:5000')}/scans/{scan_id}"
                            }
                        ]
                    }
                }
            ]
        }
        
        return card
    
    def _get_teams_color(self, severity: str) -> str:
        """Map severity to Teams color"""
        mapping = {
            'critical': 'attention',
            'high': 'warning',
            'medium': 'accent',
            'low': 'good',
            'info': 'default'
        }
        return mapping.get(severity, 'default')
    
    async def _post_to_teams(self, card: Dict) -> bool:
        """Post card to Teams webhook"""
        if not self.webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=card) as resp:
                    if resp.status == 200:
                        logger.info("Teams notification sent")
                        return True
                    else:
                        logger.error(f"Teams API error: {resp.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False
    
    async def send_scan_complete(self, scan_id: str, summary: Dict) -> bool:
        """Send scan completion notification"""
        card = self._create_scan_complete_card(scan_id, summary)
        return await self._post_to_teams(card)
    
    async def send_remediation_status(self, finding_id: str, status: str,
                                        details: Dict) -> bool:
        """Send remediation status update"""
        card = self._create_remediation_card(finding_id, status, details)
        return await self._post_to_teams(card)