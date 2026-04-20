#!/usr/bin/env python3
"""
Rate Limiting module for API Gateway
"""

import time
import logging
from typing import Dict, Optional, Tuple
import aioredis
from fastapi import HTTPException

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter with multiple strategies"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.limits = {
            'tenant': {
                'default': 1000,  # requests per hour
                'window': 3600     # 1 hour
            },
            'ip': {
                'default': 100,    # requests per minute
                'window': 60        # 1 minute
            },
            'user': {
                'default': 500,     # requests per hour
                'window': 3600       # 1 hour
            },
            'endpoint': {
                'default': 100,      # requests per minute
                'window': 60
            }
        }
        
    async def check_limit(self, key_type: str, key: str, 
                          limit: Optional[int] = None) -> Tuple[bool, Dict]:
        """Check if request is within rate limit"""
        try:
            # Get limit config
            config = self.limits.get(key_type, self.limits['ip'])
            max_requests = limit or config['default']
            window = config['window']
            
            redis_key = f"ratelimit:{key_type}:{key}"
            
            # Get current count
            current = await self.redis.get(redis_key)
            current_count = int(current) if current else 0
            
            # Check if exceeded
            if current_count >= max_requests:
                ttl = await self.redis.ttl(redis_key)
                return False, {
                    'limit': max_requests,
                    'remaining': 0,
                    'reset': ttl,
                    'key_type': key_type
                }
            
            # Increment count
            await self.redis.incr(redis_key)
            
            # Set expiry on first request
            if current_count == 0:
                await self.redis.expire(redis_key, window)
            
            # Get updated TTL
            ttl = await self.redis.ttl(redis_key)
            
            return True, {
                'limit': max_requests,
                'remaining': max_requests - (current_count + 1),
                'reset': ttl,
                'key_type': key_type
            }
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Allow request on error (fail open)
            return True, {}
    
    async def check_tenant_limit(self, tenant_id: str) -> Tuple[bool, Dict]:
        """Check tenant-based rate limit"""
        return await self.check_limit('tenant', tenant_id)
    
    async def check_ip_limit(self, ip: str) -> Tuple[bool, Dict]:
        """Check IP-based rate limit"""
        return await self.check_limit('ip', ip)
    
    async def check_user_limit(self, user_id: str) -> Tuple[bool, Dict]:
        """Check user-based rate limit"""
        return await self.check_limit('user', user_id)
    
    async def check_endpoint_limit(self, endpoint: str) -> Tuple[bool, Dict]:
        """Check endpoint-based rate limit"""
        return await self.check_limit('endpoint', endpoint)
    
    async def get_remaining(self, key_type: str, key: str) -> int:
        """Get remaining requests"""
        try:
            config = self.limits.get(key_type, self.limits['ip'])
            redis_key = f"ratelimit:{key_type}:{key}"
            
            current = await self.redis.get(redis_key)
            current_count = int(current) if current else 0
            
            return max(0, config['default'] - current_count)
            
        except Exception as e:
            logger.error(f"Failed to get remaining: {e}")
            return 0
    
    async def reset_limit(self, key_type: str, key: str) -> bool:
        """Reset rate limit for a key"""
        try:
            redis_key = f"ratelimit:{key_type}:{key}"
            await self.redis.delete(redis_key)
            return True
        except Exception as e:
            logger.error(f"Failed to reset limit: {e}")
            return False
    
    async def get_stats(self) -> Dict:
        """Get rate limiting statistics"""
        try:
            keys = await self.redis.keys("ratelimit:*")
            stats = {
                'total_keys': len(keys),
                'by_type': {}
            }
            
            for key in keys:
                key_type = key.split(':')[1]
                if key_type not in stats['by_type']:
                    stats['by_type'][key_type] = 0
                stats['by_type'][key_type] += 1
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}