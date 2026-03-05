#!/usr/bin/env python3
"""
GitHub Integration for Auto-Remediation
Creates PRs, comments, and manages GitHub operations
"""

import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import base64
from github import Github, GithubException
from github.Repository import Repository
from github.PullRequest import PullRequest

logger = logging.getLogger(__name__)

class GitHubIntegration:
    """GitHub API integration for auto-remediation"""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv('GITHUB_TOKEN', '')
        if not self.token:
            logger.warning("GitHub token not configured")
            self.client = None
        else:
            self.client = Github(self.token)
    
    async def create_remediation_pr(self, finding: Dict, repo_name: str, 
                                     fix_content: str) -> Optional[Dict]:
        """Create a pull request with remediation fix"""
        if not self.client:
            logger.error("GitHub client not initialized")
            return None
        
        try:
            repo = self.client.get_repo(repo_name)
            
            # Create branch
            branch_name = f"fix/security-{finding.get('id', 'unknown')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            base_branch = repo.get_branch(repo.default_branch)
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_branch.commit.sha)
            
            # Get file to fix
            file_path = finding.get('file', '')
            if file_path:
                await self._update_file(repo, file_path, fix_content, branch_name, finding)
            
            # Create PR
            pr = repo.create_pull(
                title=f"[SECURITY] Fix: {finding.get('title', 'Security issue')}",
                body=self._create_pr_body(finding),
                head=branch_name,
                base=repo.default_branch
            )
            
            # Add labels
            pr.add_to_labels('security', 'auto-generated', finding.get('severity', 'medium'))
            
            logger.info(f"Created PR #{pr.number} in {repo_name}")
            
            return {
                'pr_number': pr.number,
                'pr_url': pr.html_url,
                'branch': branch_name,
                'created_at': pr.created_at.isoformat()
            }
            
        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create PR: {e}")
            return None
    
    async def create_comment(self, repo_name: str, issue_number: int, 
                             comment: str) -> bool:
        """Create a comment on an issue or PR"""
        try:
            repo = self.client.get_repo(repo_name)
            issue = repo.get_issue(number=issue_number)
            issue.create_comment(comment)
            logger.info(f"Created comment on {repo_name}#{issue_number}")
            return True
        except Exception as e:
            logger.error(f"Failed to create comment: {e}")
            return False
    
    async def add_labels(self, repo_name: str, issue_number: int, 
                         labels: List[str]) -> bool:
        """Add labels to an issue or PR"""
        try:
            repo = self.client.get_repo(repo_name)
            issue = repo.get_issue(number=issue_number)
            issue.add_to_labels(*labels)
            return True
        except Exception as e:
            logger.error(f"Failed to add labels: {e}")
            return False
    
    async def get_file_content(self, repo_name: str, file_path: str, 
                                branch: str = 'main') -> Optional[str]:
        """Get content of a file from GitHub"""
        try:
            repo = self.client.get_repo(repo_name)
            content = repo.get_contents(file_path, ref=branch)
            if content:
                return base64.b64decode(content.content).decode('utf-8')
            return None
        except Exception as e:
            logger.error(f"Failed to get file content: {e}")
            return None
    
    async def _update_file(self, repo: Repository, file_path: str, 
                            new_content: str, branch: str, finding: Dict) -> bool:
        """Update a file in the repository"""
        try:
            # Get current file
            contents = repo.get_contents(file_path, ref=branch)
            
            # Update file
            repo.update_file(
                path=file_path,
                message=f"fix: {finding.get('title', 'Security fix')}",
                content=new_content,
                sha=contents.sha,
                branch=branch
            )
            
            logger.info(f"Updated {file_path} in branch {branch}")
            return True
            
        except GithubException as e:
            logger.error(f"Failed to update file: {e}")
            return False
    
    def _create_pr_body(self, finding: Dict) -> str:
        """Create PR description body"""
        return f"""
## 🔒 Security Remediation

This PR was automatically generated by the Enterprise Security Platform.

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

### Additional Context
- **CVE**: {finding.get('metadata', {}).get('cve', 'N/A')}
- **CWE**: {finding.get('metadata', {}).get('cwe', 'N/A')}
- **Detected**: {finding.get('timestamp', datetime.now().isoformat())}

---
*This PR was automatically generated. Please review carefully before merging.*
"""
    
    async def create_issue(self, repo_name: str, finding: Dict) -> Optional[Dict]:
        """Create a GitHub issue for a finding"""
        try:
            repo = self.client.get_repo(repo_name)
            
            issue = repo.create_issue(
                title=f"Security: {finding.get('title', 'Security issue')}",
                body=self._create_issue_body(finding),
                labels=['security', finding.get('severity', 'medium')]
            )
            
            logger.info(f"Created issue #{issue.number} in {repo_name}")
            
            return {
                'issue_number': issue.number,
                'issue_url': issue.html_url
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

### References
- [Security Guidelines](https://docs.example.com/security)
- [CVE Details](https://nvd.nist.gov/vuln/detail/{finding.get('metadata', {}).get('cve', '')})

---
*This issue was automatically generated.*
"""
    
    async def get_remediation_history(self, repo_name: str, 
                                        finding_id: str) -> List[Dict]:
        """Get remediation history for a finding"""
        try:
            repo = self.client.get_repo(repo_name)
            
            # Search for PRs with finding ID
            prs = repo.get_pulls(state='all')
            history = []
            
            for pr in prs:
                if finding_id in pr.title or finding_id in pr.body:
                    history.append({
                        'pr_number': pr.number,
                        'pr_url': pr.html_url,
                        'state': pr.state,
                        'created_at': pr.created_at.isoformat(),
                        'merged_at': pr.merged_at.isoformat() if pr.merged_at else None
                    })
            
            return history
            
        except Exception as e:
            logger.error(f"Failed to get remediation history: {e}")
            return []