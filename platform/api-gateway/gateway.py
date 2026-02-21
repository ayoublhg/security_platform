#!/usr/bin/env python3
"""
Enterprise API Gateway with Rate Limiting, Auth, and Monitoring
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import jwt
import redis
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional
import aioredis
import logging

app = FastAPI(title="Security Platform Gateway", version="2.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis client for rate limiting
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self):
        self.strategies = {
            'tenant': self.check_tenant_limit,
            'ip': self.check_ip_limit,
            'user': self.check_user_limit,
            'global': self.check_global_limit
        }
    
    async def check_tenant_limit(self, tenant_id: str) -> bool:
        """Tenant-based rate limiting"""
        key = f"ratelimit:tenant:{tenant_id}"
        current = redis_client.get(key)
        
        if current and int(current) > 1000:  # 1000 requests per hour
            return False
        
        redis_client.incr(key)
        redis_client.expire(key, 3600)  # 1 hour
        return True
    
    async def check_ip_limit(self, ip: str) -> bool:
        """IP-based rate limiting"""
        key = f"ratelimit:ip:{ip}"
        current = redis_client.get(key)
        
        if current and int(current) > 100:  # 100 requests per minute
            return False
        
        redis_client.incr(key)
        redis_client.expire(key, 60)  # 1 minute
        return True
    
    async def check_user_limit(self, user_id: str) -> bool:
        """User-based rate limiting"""
        key = f"ratelimit:user:{user_id}"
        current = redis_client.get(key)
        
        if current and int(current) > 500:  # 500 requests per hour
            return False
        
        redis_client.incr(key)
        redis_client.expire(key, 3600)
        return True
    
    async def check_global_limit(self) -> bool:
        """Global rate limiting"""
        key = "ratelimit:global"
        current = redis_client.get(key)
        
        if current and int(current) > 10000:  # 10k requests per hour
            return False
        
        redis_client.incr(key)
        redis_client.expire(key, 3600)
        return True

class AuthMiddleware:
    """JWT-based authentication with RBAC"""
    
    def __init__(self):
        self.secret_key = "your-secret-key-change-in-production"
        self.algorithm = "HS256"
        
        # Role-based permissions
        self.permissions = {
            'admin': ['create:scan', 'read:scan', 'delete:scan', 'manage:tenant'],
            'security_engineer': ['create:scan', 'read:scan'],
            'developer': ['read:scan'],
            'auditor': ['read:scan', 'read:reports']
        }
    
    def create_token(self, user_id: str, role: str, tenant_id: str) -> str:
        """Create JWT token"""
        payload = {
            'user_id': user_id,
            'role': role,
            'tenant_id': tenant_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(401, "Invalid token")
    
    def check_permission(self, token: str, required_permission: str) -> bool:
        """Check if token has required permission"""
        payload = self.verify_token(token)
        role = payload.get('role', 'developer')
        
        if role in self.permissions:
            return required_permission in self.permissions[role]
        
        return False

# Initialize
rate_limiter = RateLimiter()
auth = AuthMiddleware()

@app.middleware("http")
async def gateway_middleware(request: Request, call_next):
    """Main gateway middleware"""
    
    # Start timer
    start_time = time.time()
    
    # Extract identifiers
    tenant_id = request.headers.get('X-Tenant-ID', 'default')
    client_ip = request.client.host
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Rate limiting checks
    if not await rate_limiter.check_tenant_limit(tenant_id):
        return JSONResponse(
            status_code=429,
            content={"error": "Tenant rate limit exceeded"}
        )
    
    if not await rate_limiter.check_ip_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"error": "IP rate limit exceeded"}
        )
    
    # Authentication (skip for public endpoints)
    if not request.url.path.startswith('/public'):
        try:
            user_info = auth.verify_token(auth_token)
            request.state.user = user_info
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.detail}
            )
    
    # Process request
    response = await call_next(request)
    
    # Add metrics
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"Tenant: {tenant_id} Time: {process_time:.3f}s "
        f"Status: {response.status_code}"
    )
    
    return response

@app.post("/api/v1/auth/login")
async def login(request: Request):
    """Login endpoint"""
    data = await request.json()
    
    # Validate credentials (simplified - use proper auth in production)
    if data.get('api_key') == 'valid_key':
        token = auth.create_token(
            user_id=data.get('user_id', 'unknown'),
            role=data.get('role', 'developer'),
            tenant_id=data.get('tenant_id', 'default')
        )
        return {"token": token, "expires_in": 86400}
    
    raise HTTPException(401, "Invalid credentials")

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "orchestrator": await check_service("orchestrator:8000"),
            "database": await check_database(),
            "redis": await check_redis()
        }
    }

@app.get("/api/v1/metrics")
async def get_metrics(request: Request):
    """Get gateway metrics"""
    
    # Check admin permission
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not auth.check_permission(token, 'manage:tenant'):
        raise HTTPException(403, "Insufficient permissions")
    
    metrics = {
        "total_requests": redis_client.get("ratelimit:global") or 0,
        "active_tenants": len(redis_client.keys("ratelimit:tenant:*")),
        "rate_limit_hits": redis_client.get("ratelimit:hits") or 0,
        "average_response_time": redis_client.get("metrics:avg_response_time") or 0
    }
    
    return metrics

async def check_service(host: str) -> bool:
    """Check service health"""
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{host}/health", timeout=2) as resp:
                return resp.status == 200
    except:
        return False

async def check_database() -> bool:
    """Check database connection"""
    try:
        import asyncpg
        conn = await asyncpg.connect(
            user="postgres",
            password="secure_password",
            database="security_platform",
            host="localhost"
        )
        await conn.close()
        return True
    except:
        return False

async def check_redis() -> bool:
    """Check Redis connection"""
    try:
        redis_client.ping()
        return True
    except:
        return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)