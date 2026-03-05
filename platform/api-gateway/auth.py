#!/usr/bin/env python3
"""
Authentication module with JWT and RBAC
"""

import jwt
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from fastapi import HTTPException, Request
import os

logger = logging.getLogger(__name__)

class AuthMiddleware:
    """JWT-based authentication with role-based access control"""
    
    def __init__(self):
        self.secret_key = os.getenv('JWT_SECRET', 'change-this-in-production')
        self.algorithm = "HS256"
        self.token_expiry_hours = 24
        
        # Role-based permissions
        self.permissions = {
            'admin': [
                'scan:create', 'scan:read', 'scan:delete',
                'tenant:create', 'tenant:read', 'tenant:update', 'tenant:delete',
                'finding:read', 'finding:update',
                'report:generate', 'report:read'
            ],
            'security_engineer': [
                'scan:create', 'scan:read',
                'tenant:read',
                'finding:read', 'finding:update',
                'report:generate', 'report:read'
            ],
            'developer': [
                'scan:read',
                'finding:read',
                'report:read'
            ],
            'auditor': [
                'scan:read',
                'finding:read',
                'report:read', 'report:generate'
            ],
            'viewer': [
                'scan:read',
                'finding:read'
            ]
        }
        
        # Default role for new users
        self.default_role = 'viewer'
        
    def create_token(self, user_id: str, role: str, tenant_id: str, 
                    email: Optional[str] = None) -> str:
        """Create JWT token"""
        payload = {
            'user_id': user_id,
            'role': role,
            'tenant_id': tenant_id,
            'email': email,
            'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours),
            'iat': datetime.utcnow(),
            'iss': 'security-platform'
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                issuer='security-platform'
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def refresh_token(self, token: str) -> str:
        """Refresh expired token"""
        try:
            # Decode without verification to get payload
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={'verify_exp': False}
            )
            
            # Create new token
            return self.create_token(
                payload['user_id'],
                payload['role'],
                payload['tenant_id'],
                payload.get('email')
            )
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise HTTPException(status_code=401, detail="Cannot refresh token")
    
    def check_permission(self, token: str, required_permission: str) -> bool:
        """Check if token has required permission"""
        try:
            payload = self.verify_token(token)
            role = payload.get('role', self.default_role)
            
            if role in self.permissions:
                return required_permission in self.permissions[role]
            
            return False
        except:
            return False
    
    def get_user_from_token(self, token: str) -> Optional[Dict]:
        """Extract user info from token"""
        try:
            payload = self.verify_token(token)
            return {
                'user_id': payload.get('user_id'),
                'role': payload.get('role'),
                'tenant_id': payload.get('tenant_id'),
                'email': payload.get('email')
            }
        except:
            return None
    
    async def authenticate_request(self, request: Request) -> Optional[Dict]:
        """Authenticate request from headers"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None
        
        # Extract token
        scheme, token = auth_header.split()
        if scheme.lower() != 'bearer':
            return None
        
        return self.get_user_from_token(token)

# Create global instance
auth = AuthMiddleware()