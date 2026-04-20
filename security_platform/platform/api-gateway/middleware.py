#!/usr/bin/env python3
"""
Middleware for API Gateway
"""

import time
import logging
from typing import Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import uuid

from .auth import auth
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

class GatewayMiddleware:
    """Middleware for request processing, authentication, and rate limiting"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.excluded_paths = [
            '/health',
            '/docs',
            '/redoc',
            '/openapi.json',
            '/api/v1/auth/login',
            '/api/v1/auth/refresh'
        ]
    
    async def __call__(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Start timer
        start_time = time.time()
        
        # Log request
        logger.info(f"Request {request_id}: {request.method} {request.url.path}")
        
        # Check if path is excluded
        if not self._is_excluded_path(request.url.path):
            # Authenticate
            user = await auth.authenticate_request(request)
            if not user:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Authentication required"}
                )
            
            # Store user in request state
            request.state.user = user
            
            # Rate limiting
            # Check IP
            client_ip = request.client.host
            allowed, info = await self.rate_limiter.check_ip_limit(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "details": info
                    },
                    headers={
                        "X-RateLimit-Limit": str(info.get('limit', '')),
                        "X-RateLimit-Remaining": str(info.get('remaining', '')),
                        "X-RateLimit-Reset": str(info.get('reset', ''))
                    }
                )
            
            # Check tenant
            allowed, info = await self.rate_limiter.check_tenant_limit(
                user['tenant_id']
            )
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Tenant rate limit exceeded",
                        "details": info
                    }
                )
        
        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Request {request_id} failed: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error"}
            )
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Add headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        
        # Log response
        logger.info(
            f"Response {request_id}: {response.status_code} "
            f"({process_time:.3f}s)"
        )
        
        return response
    
    def _is_excluded_path(self, path: str) -> bool:
        """Check if path is excluded from authentication"""
        return any(path.startswith(excluded) for excluded in self.excluded_paths)