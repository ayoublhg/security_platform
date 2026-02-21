#!/usr/bin/env python3
"""
Intelligent Auto-Remediation Engine with Approval Workflows
"""

import asyncio
import aiohttp
import json
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import hashlib
import hmac
import base64
import logging
from github import Github
from jira import JIRA
import slack_sdk
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class RemediationStrategy(str, Enum):
    AUTO_FIX = "auto_fix"
    CREATE_PR = "create_pr"
    CREATE_TICKET = "create_ticket"
    ESCALATE = "escalate"
    IGNORE = "ignore"

class RemediationRequest(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    repository: str
    file_path: Optional[str]
    line_number: Optional[int]
    content: Optional[str]
    tenant_id: str
    metadata: Dict

class RemediationResult(BaseModel):
    request_id: str
    strategy: RemediationStrategy
    status: str  # pending, approved, rejected, completed, failed
    action_url: Optional[str]
    ticket_id: Optional[str]
    message: str
    timestamp: datetime

class AutoRemediationEngine:
    """Intelligent remediation with multiple strategies"""
    
    def __init__(self):
        # Initialize integrations
        self.github = Github(os.getenv('GITHUB_TOKEN'))
        self.jira = JIRA(
            server=os.getenv('JIRA_URL'),
            basic_auth=(os.getenv('JIRA_USER'), os.getenv('JIRA_TOKEN'))
        )
        self.slack = slack_sdk.WebClient(token=os.getenv('SLACK_TOKEN'))
        
        # Configuration
        self.remediation_rules = self.load_remediation_rules()
        self.approval_required = ['critical', 'high']
        self.auto_fix_allowed = ['secrets', 'dependencies']
        
        # State tracking
        self.active_remediations = {}
        self.remediation_history = []
        
    def load_remediation_rules(self) -> Dict:
        """Load remediation rules from YAML"""
        return {
            'secrets': {
                'hardcoded_password': {
                    'strategy': RemediationStrategy.CREATE_PR,
                    'fix': 'remove_and_rotate',
                    'approval_required': True
                },
                'aws_key': {
                    'strategy': RemediationStrategy.CREATE_PR,
                    'fix': 'rotate_and_vault',
                    'approval_required': True
                },
                'api_token': {
                    'strategy': RemediationStrategy.CREATE_PR,
                    'fix': 'move_to_env',
                    'approval_required': True
                }
            },
            'dependencies': {
                'critical_vuln': {
                    'strategy': RemediationStrategy.CREATE_PR,
                    'fix': 'update_package',
                    'approval_required': True
                },
                'high_vuln': {
                    'strategy': RemediationStrategy.CREATE_PR,
                    'fix': 'update_package',
                    'approval_required': False
                }
            },
            'misconfiguration': {
                'public_s3': {
                    'strategy': RemediationStrategy.AUTO_FIX,
                    'fix': 'make_private',
                    'approval_required': True
                },
                'open_security_group': {
                    'strategy': RemediationStrategy.AUTO_FIX,
                    'fix': 'restrict_access',
                    'approval_required': True
                }
            },
            'code_quality': {
                'sql_injection': {
                    'strategy': RemediationStrategy.CREATE_TICKET,
                    'fix': 'use_parameterized_queries',
                    'approval_required': False
                },
                'xss': {
                    'strategy': RemediationStrategy.CREATE_TICKET,
                    'fix': 'sanitize_input',
                    'approval_required': False
                }
            }
        }
    
    async def remediate(self, request: RemediationRequest) -> RemediationResult:
        """Main remediation entry point"""
        
        # Generate unique ID
        request_id = hashlib.md5(
            f"{request.finding_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]
        
        # Determine strategy
        strategy = self.determine_strategy(request)
        
        # Check if approval needed
        if request.severity in self.approval_required:
            strategy = RemediationStrategy.CREATE_TICKET
            message = "Approval required. Created ticket for review."
        
        # Execute remediation
        result = await self.execute_remediation(request_id, request, strategy)
        
        # Track
        self.active_remediations[request_id] = result
        self.remediation_history.append(result)
        
        return result
    
    def determine_strategy(self, request: RemediationRequest) -> RemediationStrategy:
        """Determine the best remediation strategy"""
        
        finding_type = request.finding_type
        severity = request.severity
        
        # Critical severity always requires approval
        if severity == 'critical':
            return RemediationStrategy.CREATE_TICKET
        
        # Check rules
        for category, rules in self.remediation_rules.items():
            if finding_type in rules:
                rule = rules[finding_type]
                if rule.get('approval_required', False):
                    return RemediationStrategy.CREATE_PR
                else:
                    return rule['strategy']
        
        # Default
        return RemediationStrategy.CREATE_TICKET
    
    async def execute_remediation(self, request_id: str, request: RemediationRequest,
                                    strategy: RemediationStrategy) -> RemediationResult:
        """Execute specific remediation strategy"""
        
        if strategy == RemediationStrategy.AUTO_FIX:
            return await self.auto_fix(request_id, request)
        elif strategy == RemediationStrategy.CREATE_PR:
            return await self.create_pr(request_id, request)
        elif strategy == RemediationStrategy.CREATE_TICKET:
            return await self.create_ticket(request_id, request)
        elif strategy == RemediationStrategy.ESCALATE:
            return await self.escalate(request_id, request)
        else:
            return RemediationResult(
                request_id=request_id,
                strategy=strategy,
                status="ignored",
                message="No action taken",
                timestamp=datetime.now()
            )
    
    async def auto_fix(self, request_id: str, request: RemediationRequest) -> RemediationResult:
        """Attempt automatic fix"""
        
        try:
            if 'secret' in request.finding_type:
                result = await self.fix_secret(request)
            elif 'dependency' in request.finding_type:
                result = await self.fix_dependency(request)
            elif 'misconfiguration' in request.finding_type:
                result = await self.fix_misconfiguration(request)
            else:
                result = None
            
            if result and result['success']:
                return RemediationResult(
                    request_id=request_id,
                    strategy=RemediationStrategy.AUTO_FIX,
                    status="completed",
                    action_url=result.get('url'),
                    message=f"Auto-fix applied: {result.get('message')}",
                    timestamp=datetime.now()
                )
            else:
                # Fallback to PR
                return await self.create_pr(request_id, request)
                
        except Exception as e:
            logger.error(f"Auto-fix failed: {e}")
            return await self.create_ticket(request_id, request)
    
    async def fix_secret(self, request: RemediationRequest) -> Dict:
        """Fix hardcoded secret"""
        
        # Extract repo info
        repo_name = request.repository.split('/')[-1]
        repo = self.github.get_repo(f"{request.tenant_id}/{repo_name}")
        
        # Create branch
        branch_name = f"fix/secret-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        source_branch = repo.get_branch("main")
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source_branch.commit.sha)
        
        # Get file content
        contents = repo.get_contents(request.file_path, ref="main")
        content = contents.decoded_content.decode()
        
        # Redact secret
        new_content = self.redact_secret(content, request.content)
        
        # Update file
        repo.update_file(
            path=request.file_path,
            message=f"fix: remove hardcoded secret - {request.finding_id}",
            content=new_content,
            sha=contents.sha,
            branch=branch_name
        )
        
        # Create PR
        pr = repo.create_pull(
            title=f"[SECURITY] Fix hardcoded secret",
            body=f"""
            ## 🔐 Security Fix
            
            **Issue**: Hardcoded secret detected
            **Finding ID**: {request.finding_id}
            **Severity**: {request.severity}
            
            **Changes Made**:
            - Removed hardcoded secret
            - Secret should be stored in environment variables/secrets manager
            
            **Reviewers**: @security-team
            
            Auto-generated by Security Platform
            """,
            head=branch_name,
            base="main"
        )
        
        # Add labels
        pr.add_to_labels("security", "auto-fix")
        
        # Notify Slack
        self.slack.chat_postMessage(
            channel="#security-alerts",
            text=f"🔧 Auto-fix PR created for secret exposure: {pr.html_url}"
        )
        
        return {
            "success": True,
            "url": pr.html_url,
            "message": f"PR #{pr.number} created"
        }
    
    def redact_secret(self, content: str, secret: str) -> str:
        """Redact secret from content"""
        # Replace with placeholder
        patterns = [
            (r'(password\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1"CHANGE_ME"'),
            (r'(api_key\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1"CHANGE_ME"'),
            (r'(token\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1"CHANGE_ME"'),
            (r'(secret\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1"CHANGE_ME"')
        ]
        
        new_content = content
        for pattern, replacement in patterns:
            new_content = re.sub(pattern, replacement, new_content, flags=re.IGNORECASE)
        
        return new_content
    
    async def fix_dependency(self, request: RemediationRequest) -> Dict:
        """Fix vulnerable dependency"""
        
        repo_name = request.repository.split('/')[-1]
        repo = self.github.get_repo(f"{request.tenant_id}/{repo_name}")
        
        # Determine package manager
        if 'package.json' in request.file_path:
            return await self.fix_npm_dependency(request, repo)
        elif 'requirements.txt' in request.file_path:
            return await self.fix_python_dependency(request, repo)
        elif 'pom.xml' in request.file_path:
            return await self.fix_maven_dependency(request, repo)
        
        return {"success": False}
    
    async def fix_npm_dependency(self, request: RemediationRequest, repo) -> Dict:
        """Fix NPM dependency"""
        
        # Parse package.json
        contents = repo.get_contents("package.json", ref="main")
        package = json.loads(contents.decoded_content.decode())
        
        # Find vulnerable package
        vuln_package = request.metadata.get('package')
        fixed_version = request.metadata.get('fixed_version')
        
        if vuln_package and fixed_version:
            # Update in dependencies
            if vuln_package in package.get('dependencies', {}):
                package['dependencies'][vuln_package] = fixed_version
            
            # Update in devDependencies
            if vuln_package in package.get('devDependencies', {}):
                package['devDependencies'][vuln_package] = fixed_version
            
            # Create branch
            branch_name = f"fix/dependency-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            source_branch = repo.get_branch("main")
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source_branch.commit.sha)
            
            # Update file
            repo.update_file(
                path="package.json",
                message=f"fix: update {vuln_package} to {fixed_version}",
                content=json.dumps(package, indent=2),
                sha=contents.sha,
                branch=branch_name
            )
            
            # Update lock file if exists
            try:
                lock_contents = repo.get_contents("package-lock.json", ref="main")
                # In real implementation, you'd run npm install
                # This is simplified
                repo.update_file(
                    path="package-lock.json",
                    message="chore: update lockfile",
                    content=lock_contents.decoded_content,
                    sha=lock_contents.sha,
                    branch=branch_name
                )
            except:
                pass
            
            # Create PR
            pr = repo.create_pull(
                title=f"[SECURITY] Update vulnerable dependency {vuln_package}",
                body=f"""
                ## 🛡️ Security Update
                
                **Vulnerability**: {request.finding_id}
                **Package**: {vuln_package}
                **Fixed Version**: {fixed_version}
                **Severity**: {request.severity}
                
                **Changes**:
                - Updated {vuln_package} from {request.metadata.get('current_version')} to {fixed_version}
                
                **Testing Required**:
                - Run `npm install` and test application
                - Verify no breaking changes
                
                Auto-generated by Security Platform
                """,
                head=branch_name,
                base="main"
            )
            
            pr.add_to_labels("security", "dependency-update")
            
            return {
                "success": True,
                "url": pr.html_url,
                "message": f"PR #{pr.number} created for dependency update"
            }
        
        return {"success": False}
    
    async def create_pr(self, request_id: str, request: RemediationRequest) -> RemediationResult:
        """Create a PR with fix"""
        
        result = await self.auto_fix(request_id, request)
        if result.status == "completed":
            return result
        
        # If auto-fix not possible, create manual PR template
        repo_name = request.repository.split('/')[-1]
        repo = self.github.get_repo(f"{request.tenant_id}/{repo_name}")
        
        branch_name = f"security/{request.finding_id}"
        
        # Create branch
        try:
            source_branch = repo.get_branch("main")
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source_branch.commit.sha)
        except:
            branch_name = f"security/{request_id}"
        
        # Create template file with instructions
        template_content = f"""
# Security Fix Required

## Finding: {request.finding_id}
**Type**: {request.finding_type}
**Severity**: {request.severity}
**File**: {request.file_path}
**Line**: {request.line_number}

## Issue Description
{request.metadata.get('description', 'No description provided')}

## Remediation Steps
1. Review the security finding
2. Apply appropriate fix
3. Test changes
4. Request review from security team

## Additional Context
- Detected: {datetime.now().isoformat()}
- Scanner: {request.metadata.get('scanner')}
- CVE: {request.metadata.get('cve', 'N/A')}

---
*This PR was automatically generated by the Security Platform*
"""
        
        # Create file with instructions
        repo.create_file(
            path=f"security-fixes/{request_id}.md",
            message=f"docs: add remediation instructions for {request.finding_id}",
            content=template_content,
            branch=branch_name
        )
        
        # Create PR
        pr = repo.create_pull(
            title=f"[SECURITY] Fix: {request.finding_type} - {request_id}",
            body=f"""
            ## 🔒 Security Remediation Required
            
            **Finding ID**: {request.finding_id}
            **Severity**: {request.severity}
            
            Please review and fix this security issue.
            
            See `security-fixes/{request_id}.md` for details.
            
            **Required Reviewers**: @security-team
            
            Auto-generated by Security Platform
            """,
            head=branch_name,
            base="main"
        )
        
        pr.add_to_labels("security", "needs-fix")
        
        return RemediationResult(
            request_id=request_id,
            strategy=RemediationStrategy.CREATE_PR,
            status="pending",
            action_url=pr.html_url,
            message=f"PR #{pr.number} created with remediation instructions",
            timestamp=datetime.now()
        )
    
    async def create_ticket(self, request_id: str, request: RemediationRequest) -> RemediationResult:
        """Create Jira ticket for manual remediation"""
        
        # Create Jira issue
        issue_dict = {
            'project': {'key': 'SEC'},
            'summary': f"[{request.severity.upper()}] {request.finding_type} - {request.repository}",
            'description': self.create_ticket_description(request),
            'issuetype': {'name': 'Task'},
            'priority': {'name': self.map_severity_to_priority(request.severity)},
            'labels': ['security', 'auto-generated', request.finding_type]
        }
        
        issue = self.jira.create_issue(fields=issue_dict)
        
        # Add comment with details
        self.jira.add_comment(
            issue.key,
            f"Finding ID: {request.finding_id}\n"
            f"Repository: {request.repository}\n"
            f"File: {request.file_path}:{request.line_number}\n"
            f"Detected: {datetime.now().isoformat()}"
        )
        
        # Notify Slack
        self.slack.chat_postMessage(
            channel="#security-tickets",
            text=f"🎫 New security ticket created: {issue.permalink()}"
        )
        
        return RemediationResult(
            request_id=request_id,
            strategy=RemediationStrategy.CREATE_TICKET,
            status="pending",
            ticket_id=issue.key,
            message=f"Jira ticket {issue.key} created",
            timestamp=datetime.now()
        )
    
    def create_ticket_description(self, request: RemediationRequest) -> str:
        """Create detailed ticket description"""
        
        return f"""
h2. Security Finding Details

|| Field || Value ||
| Finding ID | {request.finding_id} |
| Type | {request.finding_type} |
| Severity | {request.severity} |
| Repository | {request.repository} |
| File | {request.file_path}:{request.line_number} |
| Detected | {datetime.now().isoformat()} |

h3. Description
{request.metadata.get('description', 'No description provided')}

h3. Remediation Guidance
{request.metadata.get('remediation', 'Follow standard security fix process')}

h3. Technical Details
{self.format_technical_details(request)}

h3. Compliance Impact
{request.metadata.get('compliance', 'Review compliance requirements')}

h3. Additional Resources
- [Security Fix Guidelines|https://wiki.company.com/security-fixes]
- [CVE Details|https://nvd.nist.gov/vuln/detail/{request.metadata.get('cve', '')}]

*This ticket was automatically generated by the Security Platform*
"""
    
    def format_technical_details(self, request: RemediationRequest) -> str:
        """Format technical details for ticket"""
        details = []
        
        for key, value in request.metadata.items():
            if key not in ['description', 'remediation', 'compliance']:
                details.append(f"* *{key}*: {value}")
        
        return '\n'.join(details)
    
    def map_severity_to_priority(self, severity: str) -> str:
        """Map severity to Jira priority"""
        mapping = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Lowest'
        }
        return mapping.get(severity, 'Medium')
    
    async def escalate(self, request_id: str, request: RemediationRequest) -> RemediationResult:
        """Escalate to security team"""
        
        # Create urgent Jira ticket
        issue_dict = {
            'project': {'key': 'SECOPS'},
            'summary': f"[URGENT][{request.severity.upper()}] {request.finding_type} - {request.repository}",
            'description': self.create_ticket_description(request),
            'issuetype': {'name': 'Incident'},
            'priority': {'name': 'Highest'},
            'labels': ['security', 'escalated', 'urgent']
        }
        
        issue = self.jira.create_issue(fields=issue_dict)
        
        # Send urgent Slack message
        self.slack.chat_postMessage(
            channel="#security-urgent",
            text=f"🚨 *URGENT SECURITY ESCALATION*\n"
                 f"Finding: {request.finding_id}\n"
                 f"Severity: {request.severity}\n"
                 f"Repository: {request.repository}\n"
                 f"Jira: {issue.permalink()}\n"
                 f"*Immediate attention required!*"
        )
        
        # Send email to security team
        # (implementation depends on email service)
        
        return RemediationResult(
            request_id=request_id,
            strategy=RemediationStrategy.ESCALATE,
            status="escalated",
            ticket_id=issue.key,
            message=f"Escalated to security team via {issue.key}",
            timestamp=datetime.now()
        )
    
    async def get_remediation_status(self, finding_id: str) -> Optional[RemediationResult]:
        """Get status of remediation for a finding"""
        for result in self.remediation_history:
            if result.request_id == finding_id:
                return result
        return None
    
    async def approve_remediation(self, request_id: str, approver: str) -> bool:
        """Approve pending remediation"""
        if request_id in self.active_remediations:
            result = self.active_remediations[request_id]
            result.status = "approved"
            result.message += f" - Approved by {approver}"
            
            # Execute approved remediation
            await self.execute_remediation(
                request_id,
                result.request,
                result.strategy
            )
            
            return True
        return False