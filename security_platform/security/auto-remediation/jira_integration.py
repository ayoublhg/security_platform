#!/usr/bin/env python3
"""
Jira Integration for Auto-Remediation
Creates tickets and manages Jira operations
"""

import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from jira import JIRA, JIRAError

logger = logging.getLogger(__name__)

class JiraIntegration:
    """Jira API integration for auto-remediation"""
    
    def __init__(self):
        self.url = os.getenv('JIRA_URL', '')
        self.username = os.getenv('JIRA_USER', '')
        self.token = os.getenv('JIRA_TOKEN', '')
        self.project = os.getenv('JIRA_PROJECT', 'SEC')
        
        if not all([self.url, self.username, self.token]):
            logger.warning("Jira credentials not fully configured")
            self.client = None
        else:
            try:
                self.client = JIRA(
                    server=self.url,
                    basic_auth=(self.username, self.token)
                )
                logger.info("Jira client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Jira client: {e}")
                self.client = None
    
    async def create_ticket(self, finding: Dict, severity: str) -> Optional[Dict]:
        """Create a Jira ticket for a finding"""
        if not self.client:
            logger.error("Jira client not initialized")
            return None
        
        try:
            # Map severity to priority
            priority_map = {
                'critical': 'Highest',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'info': 'Lowest'
            }
            priority = priority_map.get(severity, 'Medium')
            
            # Map severity to issue type
            issue_type = 'Bug' if severity in ['critical', 'high'] else 'Task'
            
            issue_dict = {
                'project': {'key': self.project},
                'summary': f"[{severity.upper()}] {finding.get('title', 'Security finding')}",
                'description': self._create_description(finding),
                'issuetype': {'name': issue_type},
                'priority': {'name': priority},
                'labels': ['security', 'auto-generated', finding.get('scanner', '')]
            }
            
            # Add custom fields if available
            if finding.get('file'):
                issue_dict['customfield_10000'] = finding.get('file')
            if finding.get('line'):
                issue_dict['customfield_10001'] = str(finding.get('line'))
            
            issue = self.client.create_issue(fields=issue_dict)
            
            logger.info(f"Created Jira ticket {issue.key}")
            
            return {
                'ticket_key': issue.key,
                'ticket_url': f"{self.url}/browse/{issue.key}",
                'priority': priority,
                'status': 'Open'
            }
            
        except JIRAError as e:
            logger.error(f"Jira API error: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {e}")
            return None
    
    async def update_ticket(self, ticket_key: str, finding: Dict) -> bool:
        """Update an existing Jira ticket"""
        if not self.client:
            return False
        
        try:
            issue = self.client.issue(ticket_key)
            
            # Add comment
            comment = f"""
New information detected:
- Scanner: {finding.get('scanner', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}
- File: {finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}
- Timestamp: {finding.get('timestamp', datetime.now().isoformat())}
            """
            
            self.client.add_comment(issue, comment)
            
            # Update priority if severity changed
            if finding.get('severity'):
                priority_map = {
                    'critical': 'Highest',
                    'high': 'High',
                    'medium': 'Medium',
                    'low': 'Low'
                }
                new_priority = priority_map.get(finding['severity'], 'Medium')
                issue.update(priority={'name': new_priority})
            
            logger.info(f"Updated Jira ticket {ticket_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update Jira ticket: {e}")
            return False
    
    async def add_comment(self, ticket_key: str, comment: str) -> bool:
        """Add a comment to a ticket"""
        if not self.client:
            return False
        
        try:
            issue = self.client.issue(ticket_key)
            self.client.add_comment(issue, comment)
            return True
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            return False
    
    async def transition_ticket(self, ticket_key: str, 
                                 transition_name: str) -> bool:
        """Transition ticket to new state"""
        if not self.client:
            return False
        
        try:
            issue = self.client.issue(ticket_key)
            transitions = self.client.transitions(issue)
            
            for t in transitions:
                if t['name'].lower() == transition_name.lower():
                    self.client.transition_issue(issue, t['id'])
                    logger.info(f"Transitioned {ticket_key} to {transition_name}")
                    return True
            
            logger.warning(f"Transition {transition_name} not found")
            return False
            
        except Exception as e:
            logger.error(f"Failed to transition ticket: {e}")
            return False
    
    async def find_existing_ticket(self, finding_id: str) -> Optional[str]:
        """Find if a ticket already exists for this finding"""
        if not self.client:
            return None
        
        try:
            # Search for tickets with finding ID
            jql = f'project = {self.project} AND summary ~ "{finding_id}"'
            issues = self.client.search_issues(jql)
            
            if issues:
                return issues[0].key
            return None
            
        except Exception as e:
            logger.error(f"Failed to search tickets: {e}")
            return None
    
    def _create_description(self, finding: Dict) -> str:
        """Create detailed ticket description"""
        return f"""
h2. Security Finding Details

|| Field || Value ||
| Finding ID | {finding.get('id', 'N/A')} |
| Scanner | {finding.get('scanner', 'N/A')} |
| Severity | {finding.get('severity', 'medium')} |
| File | {finding.get('file', 'N/A')} |
| Line | {finding.get('line', 'N/A')} |
| Detected | {finding.get('timestamp', datetime.now().isoformat())} |

h3. Description
{finding.get('description', 'No description provided')}

h3. Remediation Guidance
{finding.get('metadata', {}).get('remediation', 'Follow standard security fix process')}

h3. Technical Details
{self._format_technical_details(finding)}

h3. Additional Resources
- [Security Fix Guidelines|{os.getenv('SECURITY_WIKI_URL', '#')}]
- [CVE Details|https://nvd.nist.gov/vuln/detail/{finding.get('metadata', {}).get('cve', '')}]

*This ticket was automatically generated by the Security Platform*
"""
    
    def _format_technical_details(self, finding: Dict) -> str:
        """Format technical details for ticket"""
        details = []
        metadata = finding.get('metadata', {})
        
        for key, value in metadata.items():
            if key not in ['description', 'remediation']:
                if isinstance(value, dict):
                    details.append(f"* *{key}*: (see sub-tasks)")
                else:
                    details.append(f"* *{key}*: {value}")
        
        return '\n'.join(details) if details else 'No additional technical details'
    
    async def get_ticket_status(self, ticket_key: str) -> Optional[Dict]:
        """Get current status of a ticket"""
        if not self.client:
            return None
        
        try:
            issue = self.client.issue(ticket_key)
            return {
                'key': issue.key,
                'status': issue.fields.status.name,
                'resolution': issue.fields.resolution.name if issue.fields.resolution else None,
                'assignee': issue.fields.assignee.displayName if issue.fields.assignee else None,
                'updated': issue.fields.updated
            }
        except Exception as e:
            logger.error(f"Failed to get ticket status: {e}")
            return None