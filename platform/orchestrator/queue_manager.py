#!/usr/bin/env python3
"""
Queue Manager - Handles scan queuing and prioritization
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import aioredis
from enum import Enum

logger = logging.getLogger(__name__)

class ScanPriority(Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

class QueueManager:
    """Manages scan queues with priorities"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.queues = {
            'critical': asyncio.Queue(),
            'high': asyncio.Queue(),
            'medium': asyncio.Queue(),
            'low': asyncio.Queue()
        }
        self.priority_map = {
            'critical': ScanPriority.CRITICAL,
            'high': ScanPriority.HIGH,
            'medium': ScanPriority.MEDIUM,
            'low': ScanPriority.LOW
        }
        
    async def enqueue(self, scan_id: str, tenant_id: str, 
                      priority: str = 'medium') -> bool:
        """Add scan to queue"""
        try:
            priority = priority.lower()
            if priority not in self.queues:
                priority = 'medium'
            
            scan_data = {
                'scan_id': scan_id,
                'tenant_id': tenant_id,
                'priority': priority,
                'enqueued_at': datetime.utcnow().isoformat()
            }
            
            # Add to memory queue
            await self.queues[priority].put(scan_data)
            
            # Store in Redis for persistence
            await self.redis.rpush(
                f"queue:{priority}",
                json.dumps(scan_data)
            )
            
            logger.info(f"Scan {scan_id} enqueued with priority {priority}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enqueue scan {scan_id}: {e}")
            return False
    
    async def dequeue(self) -> Optional[Dict]:
        """Get next scan from queue (priority order)"""
        # Check queues in priority order
        for priority in ['critical', 'high', 'medium', 'low']:
            if not self.queues[priority].empty():
                try:
                    scan_data = await self.queues[priority].get()
                    
                    # Remove from Redis
                    await self.redis.lrem(f"queue:{priority}", 1, json.dumps(scan_data))
                    
                    return scan_data
                except Exception as e:
                    logger.error(f"Failed to dequeue from {priority}: {e}")
        
        return None
    
    async def get_queue_lengths(self) -> Dict[str, int]:
        """Get current queue lengths"""
        lengths = {}
        for priority in self.queues:
            lengths[priority] = self.queues[priority].qsize()
        return lengths
    
    async def requeue_failed(self, scan_data: Dict) -> bool:
        """Requeue a failed scan"""
        priority = scan_data.get('priority', 'medium')
        scan_data['requeued_at'] = datetime.utcnow().isoformat()
        scan_data['retry_count'] = scan_data.get('retry_count', 0) + 1
        
        # Max 3 retries
        if scan_data['retry_count'] > 3:
            logger.warning(f"Scan {scan_data['scan_id']} exceeded max retries")
            return False
        
        return await self.enqueue(
            scan_data['scan_id'],
            scan_data['tenant_id'],
            priority
        )
    
    async def get_queue_status(self) -> Dict:
        """Get detailed queue status"""
        status = {
            'queues': {},
            'total': 0,
            'processing': 0,
            'waiting': 0
        }
        
        for priority, queue in self.queues.items():
            status['queues'][priority] = {
                'waiting': queue.qsize(),
                'processing': await self._get_processing_count(priority)
            }
            status['total'] += queue.qsize()
            status['waiting'] += queue.qsize()
        
        return status
    
    async def _get_processing_count(self, priority: str) -> int:
        """Get number of scans being processed"""
        # This would need to be tracked separately
        # For now, return 0
        return 0
    
    async def recover_from_redis(self):
        """Recover queues from Redis on startup"""
        try:
            for priority in self.queues:
                # Get all items from Redis list
                items = await self.redis.lrange(f"queue:{priority}", 0, -1)
                
                for item in items:
                    try:
                        scan_data = json.loads(item)
                        await self.queues[priority].put(scan_data)
                        logger.info(f"Recovered scan {scan_data['scan_id']} from Redis")
                    except Exception as e:
                        logger.error(f"Failed to recover scan from Redis: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to recover queues from Redis: {e}")
    
    async def clear_queues(self):
        """Clear all queues (for testing)"""
        for priority in self.queues:
            while not self.queues[priority].empty():
                try:
                    self.queues[priority].get_nowait()
                except:
                    pass
            
            await self.redis.delete(f"queue:{priority}")
        
        logger.info("All queues cleared")