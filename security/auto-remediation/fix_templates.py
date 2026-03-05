#!/usr/bin/env python3
"""
Fix Templates for Common Security Issues
Provides remediation templates for various vulnerability types
"""

import logging
import re
from typing import Dict, List, Optional, Any
import json

logger = logging.getLogger(__name__)

class FixTemplates:
    """Templates for common security fixes"""
    
    def __init__(self):
        self.templates = {
            'hardcoded_secret': self._fix_hardcoded_secret,
            'vulnerable_dependency': self._fix_vulnerable_dependency,
            'sql_injection': self._fix_sql_injection,
            'xss': self._fix_xss,
            'insecure_config': self._fix_insecure_config,
            'public_s3_bucket': self._fix_public_s3_bucket,
            'open_security_group': self._fix_open_security_group,
            'unencrypted_data': self._fix_unencrypted_data,
            'weak_password': self._fix_weak_password,
            'missing_mfa': self._fix_missing_mfa
        }
    
    async def get_fix(self, finding_type: str, context: Dict) -> Optional[Dict]:
        """Get fix template for a finding type"""
        template_func = self.templates.get(finding_type)
        if template_func:
            return await template_func(context)
        return None
    
    async def _fix_hardcoded_secret(self, context: Dict) -> Dict:
        """Fix for hardcoded secrets"""
        file_path = context.get('file', '')
        content = context.get('content', '')
        secret_type = context.get('secret_type', 'password')
        
        # Patterns for different secret types
        patterns = {
            'password': [
                (r'(password\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1os.getenv("PASSWORD")'),
                (r'(passwd\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1os.getenv("PASSWORD")')
            ],
            'api_key': [
                (r'(api[_-]?key\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1os.getenv("API_KEY")'),
                (r'(api[_-]?token\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1os.getenv("API_TOKEN")')
            ],
            'aws_key': [
                (r'(AWS_ACCESS_KEY_ID\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1os.getenv("AWS_ACCESS_KEY_ID")'),
                (r'(AWS_SECRET_ACCESS_KEY\s*[=:]\s*)[\'"][^\'"]+[\'"]', r'\1os.getenv("AWS_SECRET_ACCESS_KEY")')
            ]
        }
        
        # Choose pattern based on secret type
        type_patterns = patterns.get(secret_type, patterns['password'])
        
        # Apply fix
        fixed_content = content
        changes = []
        
        for pattern, replacement in type_patterns:
            if re.search(pattern, fixed_content, re.IGNORECASE):
                old = re.search(pattern, fixed_content, re.IGNORECASE).group(0)
                fixed_content = re.sub(pattern, replacement, fixed_content, flags=re.IGNORECASE)
                changes.append({
                    'pattern': pattern,
                    'old': old,
                    'new': replacement.replace(r'\1', '') + 'os.getenv("...")'
                })
        
        # Add import if needed
        if 'import os' not in fixed_content:
            fixed_content = 'import os\n' + fixed_content
        
        return {
            'type': 'hardcoded_secret',
            'fixed_content': fixed_content,
            'changes': changes,
            'instructions': [
                f"Remove hardcoded {secret_type}",
                f"Add {secret_type} to environment variables or secrets manager",
                "Update deployment configuration to include the secret"
            ],
            'requires_approval': True
        }
    
    async def _fix_vulnerable_dependency(self, context: Dict) -> Dict:
        """Fix for vulnerable dependencies"""
        package = context.get('package', '')
        current_version = context.get('current_version', '')
        fixed_version = context.get('fixed_version', '')
        file_path = context.get('file', '')
        
        if 'package.json' in file_path:
            return await self._fix_npm_dependency(package, current_version, fixed_version, context)
        elif 'requirements.txt' in file_path:
            return await self._fix_pip_dependency(package, current_version, fixed_version, context)
        elif 'pom.xml' in file_path:
            return await self._fix_maven_dependency(package, current_version, fixed_version, context)
        else:
            return {
                'type': 'vulnerable_dependency',
                'instructions': [
                    f"Update {package} from {current_version} to {fixed_version}",
                    f"Check {file_path} for the dependency",
                    "Run tests after update"
                ],
                'requires_approval': True
            }
    
    async def _fix_npm_dependency(self, package: str, current: str, 
                                    fixed: str, context: Dict) -> Dict:
        """Fix NPM dependency in package.json"""
        content = context.get('content', '')
        
        try:
            package_json = json.loads(content)
            changes = []
            
            # Check dependencies
            if 'dependencies' in package_json and package in package_json['dependencies']:
                old = package_json['dependencies'][package]
                package_json['dependencies'][package] = fixed
                changes.append(f"Updated {package} from {old} to {fixed} in dependencies")
            
            if 'devDependencies' in package_json and package in package_json['devDependencies']:
                old = package_json['devDependencies'][package]
                package_json['devDependencies'][package] = fixed
                changes.append(f"Updated {package} from {old} to {fixed} in devDependencies")
            
            fixed_content = json.dumps(package_json, indent=2)
            
            return {
                'type': 'vulnerable_dependency',
                'fixed_content': fixed_content,
                'changes': changes,
                'instructions': [
                    f"Updated {package} to {fixed}",
                    "Run `npm install` to update lockfile",
                    "Test the application for breaking changes"
                ],
                'requires_approval': False
            }
            
        except Exception as e:
            logger.error(f"Failed to fix NPM dependency: {e}")
            return {
                'type': 'vulnerable_dependency',
                'instructions': [
                    f"Manually update {package} from {current} to {fixed} in package.json",
                    "Run `npm install` after updating"
                ],
                'requires_approval': True
            }
    
    async def _fix_pip_dependency(self, package: str, current: str,
                                    fixed: str, context: Dict) -> Dict:
        """Fix pip dependency in requirements.txt"""
        content = context.get('content', '')
        
        lines = content.split('\n')
        changes = []
        new_lines = []
        
        for line in lines:
            if line.startswith(package) or f"{package}==" in line:
                old_line = line
                new_line = f"{package}=={fixed}"
                new_lines.append(new_line)
                changes.append(f"Updated {old_line} to {new_line}")
            else:
                new_lines.append(line)
        
        fixed_content = '\n'.join(new_lines)
        
        return {
            'type': 'vulnerable_dependency',
            'fixed_content': fixed_content,
            'changes': changes,
            'instructions': [
                f"Updated {package} to {fixed}",
                "Run `pip install -r requirements.txt` to update",
                "Test the application"
            ],
            'requires_approval': False
        }
    
    async def _fix_maven_dependency(self, package: str, current: str,
                                      fixed: str, context: Dict) -> Dict:
        """Fix Maven dependency in pom.xml"""
        content = context.get('content', '')
        
        # Simple XML replacement
        pattern = f"<version>{current}</version>"
        replacement = f"<version>{fixed}</version>"
        
        if pattern in content:
            fixed_content = content.replace(pattern, replacement)
            return {
                'type': 'vulnerable_dependency',
                'fixed_content': fixed_content,
                'changes': [f"Updated {package} version from {current} to {fixed}"],
                'instructions': [
                    "Run `mvn clean install` to update",
                    "Test the application"
                ],
                'requires_approval': False
            }
        
        return {
            'type': 'vulnerable_dependency',
            'instructions': [
                f"Manually update {package} from {current} to {fixed} in pom.xml"
            ],
            'requires_approval': True
        }
    
    async def _fix_sql_injection(self, context: Dict) -> Dict:
        """Fix SQL injection vulnerabilities"""
        content = context.get('content', '')
        language = context.get('language', 'python')
        
        if language == 'python':
            # Replace string concatenation with parameterized queries
            patterns = [
                (r'cursor\.execute\([\'"](.*?)[\'"]\s*%', 
                 r'cursor.execute("\1", '),
                (r'cursor\.execute\(f[\'"]', 
                 r'cursor.execute("'),
                (r'%s[\'"]?\s*%', 
                 r'%s", ')
            ]
            
            fixed_content = content
            changes = []
            
            for pattern, replacement in patterns:
                if re.search(pattern, fixed_content):
                    fixed_content = re.sub(pattern, replacement, fixed_content)
                    changes.append("Converted to parameterized query")
            
            # Add import if needed
            if 'import sqlite3' in fixed_content and '?' not in fixed_content:
                changes.append("Use ? placeholders for parameters")
            
            return {
                'type': 'sql_injection',
                'fixed_content': fixed_content,
                'changes': changes,
                'instructions': [
                    "Use parameterized queries instead of string concatenation",
                    "Never trust user input",
                    "Use an ORM when possible"
                ],
                'requires_approval': True
            }
        
        return {
            'type': 'sql_injection',
            'instructions': [
                "Use parameterized queries or prepared statements",
                "Validate and sanitize all user input",
                "Use least privilege for database accounts"
            ],
            'requires_approval': True
        }
    
    async def _fix_xss(self, context: Dict) -> Dict:
        """Fix XSS vulnerabilities"""
        content = context.get('content', '')
        language = context.get('language', 'javascript')
        
        if language == 'javascript':
            # Replace innerHTML with textContent or sanitize
            patterns = [
                (r'\.innerHTML\s*=', '.textContent ='),
                (r'document\.write\(', '// document.write(')
            ]
            
            fixed_content = content
            changes = []
            
            for pattern, replacement in patterns:
                if re.search(pattern, fixed_content):
                    fixed_content = re.sub(pattern, replacement, fixed_content)
                    changes.append(f"Replaced {pattern} with safer alternative")
            
            return {
                'type': 'xss',
                'fixed_content': fixed_content,
                'changes': changes,
                'instructions': [
                    "Use textContent instead of innerHTML",
                    "Sanitize user input with libraries like DOMPurify",
                    "Use Content Security Policy headers"
                ],
                'requires_approval': True
            }
        
        return {
            'type': 'xss',
            'instructions': [
                "Escape all user input before rendering",
                "Use template engines with auto-escaping",
                "Implement Content Security Policy"
            ],
            'requires_approval': True
        }
    
    async def _fix_insecure_config(self, context: Dict) -> Dict:
        """Fix insecure configurations"""
        config_type = context.get('config_type', '')
        content = context.get('content', '')
        
        fixes = {
            'debug_true': ('debug\s*=\s*true', 'debug = false'),
            'cors_any': ('allow_origins\s*=\s*\["\*"\]', 'allow_origins=["https://example.com"]'),
            'no_auth': ('authentication\s*=\s*none', 'authentication = required')
        }
        
        fixed_content = content
        changes = []
        
        for key, (pattern, replacement) in fixes.items():
            if re.search(pattern, fixed_content, re.IGNORECASE):
                fixed_content = re.sub(pattern, replacement, fixed_content, flags=re.IGNORECASE)
                changes.append(f"Fixed {key} configuration")
        
        return {
            'type': 'insecure_config',
            'fixed_content': fixed_content,
            'changes': changes,
            'instructions': [
                "Disable debug mode in production",
                "Restrict CORS to trusted domains",
                "Enable authentication"
            ],
            'requires_approval': True
        }
    
    async def _fix_public_s3_bucket(self, context: Dict) -> Dict:
        """Fix public S3 bucket configuration"""
        content = context.get('content', '')
        
        # Terraform fix
        if 'terraform' in context.get('file', ''):
            patterns = [
                (r'acl\s*=\s*"public-read"', 'acl = "private"'),
                (r'acl\s*=\s*"public-read-write"', 'acl = "private"')
            ]
            
            fixed_content = content
            changes = []
            
            for pattern, replacement in patterns:
                if re.search(pattern, fixed_content):
                    fixed_content = re.sub(pattern, replacement, fixed_content)
                    changes.append("Changed bucket ACL to private")
            
            # Add bucket policy to block public access
            if 'aws_s3_bucket_public_access_block' not in fixed_content:
                fixed_content += '\n\nresource "aws_s3_bucket_public_access_block" "this" {\n  bucket = aws_s3_bucket.this.id\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n'
                changes.append("Added public access block configuration")
            
            return {
                'type': 'public_s3_bucket',
                'fixed_content': fixed_content,
                'changes': changes,
                'instructions': [
                    "Set bucket ACL to private",
                    "Enable block public access settings",
                    "Review bucket policies"
                ],
                'requires_approval': True
            }
        
        return {
            'type': 'public_s3_bucket',
            'instructions': [
                "Change bucket ACL from public-read to private",
                "Enable block all public access",
                "Review bucket policy for public grants"
            ],
            'requires_approval': True
        }
    
    async def _fix_open_security_group(self, context: Dict) -> Dict:
        """Fix open security group rules"""
        content = context.get('content', '')
        
        if 'terraform' in context.get('file', ''):
            # Find and fix 0.0.0.0/0 rules
            pattern = r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]'
            
            if re.search(pattern, content):
                fixed_content = re.sub(
                    pattern,
                    'cidr_blocks = ["YOUR_IP/32"]  # Restrict to specific IPs',
                    content
                )
                
                return {
                    'type': 'open_security_group',
                    'fixed_content': fixed_content,
                    'changes': ["Restricted CIDR blocks from 0.0.0.0/0 to specific IPs"],
                    'instructions': [
                        "Replace 0.0.0.0/0 with specific IP ranges",
                        "Use security groups for internal communication",
                        "Implement least privilege access"
                    ],
                    'requires_approval': True
                }
        
        return {
            'type': 'open_security_group',
            'instructions': [
                "Avoid using 0.0.0.0/0 in security group rules",
                "Restrict access to specific IP ranges",
                "Use security groups for instance-to-instance communication"
            ],
            'requires_approval': True
        }
    
    async def _fix_unencrypted_data(self, context: Dict) -> Dict:
        """Fix unencrypted data storage"""
        content = context.get('content', '')
        
        # Add encryption settings
        if 'aws_s3_bucket' in content:
            if 'server_side_encryption_configuration' not in content:
                fixed_content = content + '\n\nresource "aws_s3_bucket_server_side_encryption_configuration" "this" {\n  bucket = aws_s3_bucket.this.id\n\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n'
                
                return {
                    'type': 'unencrypted_data',
                    'fixed_content': fixed_content,
                    'changes': ["Added server-side encryption"],
                    'instructions': [
                        "Enable encryption at rest",
                        "Use AWS KMS for key management",
                        "Encrypt sensitive data in databases"
                    ],
                    'requires_approval': True
                }
        
        return {
            'type': 'unencrypted_data',
            'instructions': [
                "Enable encryption at rest for all storage",
                "Use TLS for data in transit",
                "Implement encryption for sensitive data"
            ],
            'requires_approval': True
        }
    
    async def _fix_weak_password(self, context: Dict) -> Dict:
        """Fix weak password policies"""
        content = context.get('content', '')
        
        # Update password policy
        patterns = [
            (r'minimum_length\s*=\s*\d+', 'minimum_length = 12'),
            (r'require_uppercase\s*=\s*false', 'require_uppercase = true'),
            (r'require_lowercase\s*=\s*false', 'require_lowercase = true'),
            (r'require_numbers\s*=\s*false', 'require_numbers = true'),
            (r'require_symbols\s*=\s*false', 'require_symbols = true')
        ]
        
        fixed_content = content
        changes = []
        
        for pattern, replacement in patterns:
            if re.search(pattern, fixed_content):
                fixed_content = re.sub(pattern, replacement, fixed_content)
                changes.append(f"Updated password policy: {replacement}")
        
        return {
            'type': 'weak_password',
            'fixed_content': fixed_content,
            'changes': changes,
            'instructions': [
                "Enforce minimum password length of 12 characters",
                "Require uppercase, lowercase, numbers, and symbols",
                "Implement account lockout after failed attempts",
                "Enable multi-factor authentication"
            ],
            'requires_approval': True
        }
    
    async def _fix_missing_mfa(self, context: Dict) -> Dict:
        """Fix missing MFA configuration"""
        content = context.get('content', '')
        
        # Add MFA policy
        if 'terraform' in context.get('file', ''):
            if 'aws_iam_policy' in content:
                mfa_policy = '''
resource "aws_iam_policy" "require_mfa" {
  name        = "RequireMFA"
  description = "Policy to require MFA for console access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}
'''
                fixed_content = content + mfa_policy
                
                return {
                    'type': 'missing_mfa',
                    'fixed_content': fixed_content,
                    'changes': ["Added MFA requirement policy"],
                    'instructions': [
                        "Enable MFA for all users",
                        "Require MFA for console access",
                        "Use conditional policies to enforce MFA"
                    ],
                    'requires_approval': True
                }
        
        return {
            'type': 'missing_mfa',
            'instructions': [
                "Enable multi-factor authentication for all users",
                "Require MFA for privileged actions",
                "Use conditional access policies"
            ],
            'requires_approval': True
        }