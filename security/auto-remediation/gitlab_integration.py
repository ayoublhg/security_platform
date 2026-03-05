#!/usr/bin/env python3
"""
GitLab Integration for Auto-Remediation
Creates MRs, comments, and manages GitLab operations
"""

import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import gitlab
from gitlab.v4.objects import Project

logger = logging.getLogger(__name__)

class GitLabIntegration:
    """GitLab API integration for auto-remediation"""
    
    def __init__(self, url: Optional[str] = None, token: Optional[str] = None):
        self.url = url or os.getenv('GITLAB_URL', 'https://gitlab.com')
        self.token = token or os.getenv('GITLAB_TOKEN', '')
        
        if not self.token:
            logger.warning("GitLab token not configured")
            self.client = None
        else:
            self.client = gitlab.Gitlab(self.url, private_token=self.token)
    
    async def create_remediation_mr(self, finding: Dict, project_path: str,
                                      fix_content: str) -> Optional[Dict]:
        """Create a merge request with remediation fix"""
        if not self.client:
            logger.error("GitLab client not initialized")
            return None
        
        try:
            project = self.client.projects.get(project_path)
            
            # Create branch
            branch_name = f"fix/security-{finding.get('id', 'unknown')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            source_branch = project.branches.get(project.default_branch)
            project.branches.create({'branch': branch_name, 'ref': source_branch.name})
            
            # Get file to fix
            file_path = finding.get('file', '')
            if file_path:
                await self._update_file(project, file_path, fix_content, branch_name, finding)
            
            # Create MR
            mr = project.mergerequests.create({
                'source_branch': branch_name,
                'target_branch': project.default_branch,
                'title': f"[SECURITY] Fix: {finding.get('title', 'Security issue')}",
                'description': self._create_mr_body(finding),
                'labels': 'security,auto-generated'
            })
            
            logger.info(f"Created MR !{mr.iid} in {project_path}")
            
            return {
                'mr_iid': mr.iid,
                'mr_url': mr.web_url,
                'branch': branch_name,
                'created_at': mr.created_at
            }
            
        except Exception as e:
            logger.error(f"Failed to create MR: {e}")
            return None
    
    async def create_comment(self, project_path: str, mr_iid: int,
                              comment: str) -> bool:
        """Create a comment on a merge request"""
        try:
            project = self.client.projects.get(project_path)
            mr = project.mergerequests.get(mr_iid)
            mr.notes.create({'body': comment})
            return True
        except Exception as e:
            logger.error(f"Failed to create comment: {e}")
            return False
    
    async def add_labels(self, project_path: str, mr_iid: int,
                          labels: List[str]) -> bool:
        """Add labels to a merge request"""
        try:
            project = self.client.projects.get(project_path)
            mr = project.mergerequests.get(mr_iid)
            current_labels = mr.labels or []
            mr.labels = list(set(current_labels + labels))
            mr.save()
            return True
        except Exception as e:
            logger.error(f"Failed to add labels: {e}")
            return False
    
    async def get_file_content(self, project_path: str, file_path: str,
                                branch: str = 'main') -> Optional[str]:
        """Get content of a file from GitLab"""
        try:
            project = self.client.projects.get(project_path)
            file = project.files.get(file_path=file_path, ref=branch)
            return file.decode()
        except Exception as e:
            logger.error(f"Failed to get file content: {e}")
            return None
    
    async def _update_file(self, project: Project, file_path: str,
                            new_content: str, branch: str, finding: Dict) -> bool:
        """Update a file in the repository"""
        try:
            # Get current file
            file = project.files.get(file_path=file_path, ref=branch)
            
            # Update file
            file.content = new_content
            file.save(branch=branch, commit_message=f"fix: {finding.get('title', 'Security fix')}")
            
            logger.info(f"Updated {file_path} in branch {branch}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update file: {e}")
            return False
    
    def _create_mr_body(self, finding: Dict) -> str:
        """Create MR description body"""
        return f"""
## 🔒 Security Remediation

This merge request was automatically generated by the Enterprise Security Platform.

### Finding Details
- **ID**: {finding.get('id', 'N/A')}
- **Title**: {finding.get('title', 'N/A')}
- **Severity**: {finding.get('severity', 'medium')}
- **Scanner**: {finding.get('scanner', 'N/A')}
- **File**: {finding.get('file', 'N/A')}
- **Line**: {finding.get('line', 'N/A')}

### Description
{finding.get('description', 'No description provided')}

### Remediation
{finding.get('metadata', {}).get('remediation', 'Please review and fix this security issue.')}

---
*This merge request was automatically generated. Please review carefully before merging.*
"""
    
    async def create_issue(self, project_path: str, finding: Dict) -> Optional[Dict]:
        """Create a GitLab issue for a finding"""
        try:
            project = self.client.projects.get(project_path)
            
            issue = project.issues.create({
                'title': f"Security: {finding.get('title', 'Security issue')}",
                'description': self._create_issue_body(finding),
                'labels': ['security', finding.get('severity', 'medium')]
            })
            
            logger.info(f"Created issue #{issue.iid} in {project_path}")
            
            return {
                'issue_iid': issue.iid,
                'issue_url': issue.web_url
            }
            
        except Exception as e:
            logger.error(f"Failed to create issue: {e}")
            return None
    
    def _create_issue_body(self, finding: Dict) -> str:
        """Create issue description body"""
        return f"""
## 🔒 Security Finding

A security issue has been detected by {finding.get('scanner', 'automated scan')}.

### Details
- **Severity**: {finding.get('severity', 'medium')}
- **Location**: {finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}
- **Description**: {finding.get('description', 'N/A')}

### Remediation Steps
1. Review the finding
2. Apply fix
3. Update the status

---
*This issue was automatically generated.*
"""