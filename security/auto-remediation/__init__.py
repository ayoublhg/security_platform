"""Auto-remediation module for automatic security fixes."""
from .github_integration import GitHubIntegration
from .gitlab_integration import GitLabIntegration
from .jira_integration import JiraIntegration
from .slack_notifier import SlackNotifier
from .teams_notifier import TeamsNotifier
from .fix_templates import FixTemplates
from .approval_workflow import ApprovalWorkflow

__all__ = [
    'GitHubIntegration',
    'GitLabIntegration',
    'JiraIntegration',
    'SlackNotifier',
    'TeamsNotifier',
    'FixTemplates',
    'ApprovalWorkflow'
]