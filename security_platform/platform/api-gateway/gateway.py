#!/usr/bin/env python3
"""
Enterprise API Gateway with Rate Limiting, Auth, Monitoring, and Prometheus Metrics
"""

from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import jwt
import redis.asyncio as redis
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging
import os

# ============ PROMETHEUS METRICS ============
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

# Métriques pour l'API Gateway
http_requests_total = Counter(
    'gateway_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

http_request_duration_seconds = Histogram(
    'gateway_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
)

rate_limiter_hits = Counter(
    'gateway_rate_limiter_hits_total',
    'Total rate limiter hits',
    ['limit_type']
)

active_connections = Counter(
    'gateway_active_connections',
    'Active connections'
)

# ============ FIN PROMETHEUS ============

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Security Platform Gateway", version="2.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def check_tenant_limit(self, tenant_id: str) -> bool:
        """Tenant-based rate limiting"""
        key = f"ratelimit:tenant:{tenant_id}"
        current = await self.redis.get(key)
        
        if current and int(current) > 1000:
            rate_limiter_hits.labels(limit_type='tenant').inc()
            return False
        
        await self.redis.incr(key)
        await self.redis.expire(key, 3600)
        return True
    
    async def check_ip_limit(self, ip: str) -> bool:
        """IP-based rate limiting"""
        key = f"ratelimit:ip:{ip}"
        current = await self.redis.get(key)
        
        if current and int(current) > 100:
            rate_limiter_hits.labels(limit_type='ip').inc()
            return False
        
        await self.redis.incr(key)
        await self.redis.expire(key, 60)
        return True

class AuthMiddleware:
    """JWT-based authentication with RBAC"""
    
    def __init__(self):
        self.secret_key = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
        self.algorithm = "HS256"
        
        self.permissions = {
            'admin': ['create:scan', 'read:scan', 'delete:scan', 'manage:tenant'],
            'security_engineer': ['create:scan', 'read:scan'],
            'developer': ['read:scan'],
            'auditor': ['read:scan', 'read:reports']
        }
    
    def create_token(self, user_id: str, role: str, tenant_id: str) -> str:
        payload = {
            'user_id': user_id,
            'role': role,
            'tenant_id': tenant_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(401, "Invalid token")

# Initialize
redis_client = None
rate_limiter = None
auth = AuthMiddleware()

# Middleware pour les métriques
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware pour collecter les métriques Prometheus"""
    start_time = time.time()
    
    active_connections.inc()
    response = await call_next(request)
    active_connections.dec()
    
    duration = time.time() - start_time
    
    http_requests_total.labels(
        method=request.method,
        endpoint=request.url.path,
        status_code=response.status_code
    ).inc()
    
    http_request_duration_seconds.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)
    
    response.headers["X-Process-Time"] = str(duration)
    return response

@app.on_event("startup")
async def startup():
    global redis_client, rate_limiter
    redis_client = await redis.from_url("redis://redis:6379", decode_responses=True)
    rate_limiter = RateLimiter(redis_client)
    logger.info("✅ API Gateway connected to Redis")

@app.on_event("shutdown")
async def shutdown():
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("✅ API Gateway disconnected from Redis")

# ============ PROMETHEUS METRICS ENDPOINT ============
@app.get("/metrics")
async def metrics():
    """Endpoint Prometheus pour récupérer les métriques"""
    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST
    )

@app.middleware("http")
async def gateway_middleware(request: Request, call_next):
    """Main gateway middleware"""
    start_time = time.time()
    
    tenant_id = request.headers.get('X-Tenant-ID', 'default')
    client_ip = request.client.host
    
    if rate_limiter:
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
    
    try:
        response = await call_next(request)
    except Exception as e:
        logger.error(f"Request error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"}
        )
    
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"Tenant: {tenant_id} Time: {process_time:.3f}s "
        f"Status: {response.status_code}"
    )
    
    return response

@app.get("/")
async def root():
    return {
        "service": "API Gateway",
        "version": "2.0.0",
        "status": "running",
        "endpoints": ["/health", "/metrics", "/docs", "/api/v1/scans", "/api/v1/tenants"]
    }

@app.get("/health")
async def health_check():
    redis_status = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_status = True
        except:
            pass
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "redis": redis_status
    }

@app.get("/api/v1/health/services")
async def services_health():
    import aiohttp
    
    services = {
        "orchestrator": False,
        "redis": False
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://orchestrator:8000/health", timeout=2) as resp:
                services["orchestrator"] = resp.status == 200
    except Exception as e:
        logger.debug(f"Orchestrator health check failed: {e}")
    
    if redis_client:
        try:
            await redis_client.ping()
            services["redis"] = True
        except Exception as e:
            logger.debug(f"Redis health check failed: {e}")
    
    return services

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)