#!/usr/bin/env python3
"""
WebSocket handler for real-time dashboard updates
"""

import asyncio
import json
import logging
from typing import Dict, Set, Any
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room

logger = logging.getLogger(__name__)

class WebSocketHandler:
    """Handles WebSocket connections and real-time updates"""
    
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self.connected_clients: Set[str] = set()
        self.tenant_rooms: Dict[str, Set[str]] = {}
        self.subscriptions: Dict[str, Set[str]] = {}  # client_id -> subscribed topics
    
    def register_handlers(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            client_id = self._get_client_id()
            self.connected_clients.add(client_id)
            self.subscriptions[client_id] = set()
            logger.info(f"Client connected: {client_id}")
            emit('connected', {'client_id': client_id})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            client_id = self._get_client_id()
            self.connected_clients.discard(client_id)
            
            # Remove from tenant rooms
            for tenant_id, clients in list(self.tenant_rooms.items()):
                clients.discard(client_id)
                if not clients:
                    del self.tenant_rooms[tenant_id]
            
            # Remove subscriptions
            self.subscriptions.pop(client_id, None)
            logger.info(f"Client disconnected: {client_id}")
        
        @self.socketio.on('subscribe')
        def handle_subscribe(data):
            """Handle subscription to topics"""
            client_id = self._get_client_id()
            topic = data.get('topic')
            
            if topic:
                self.subscriptions[client_id].add(topic)
                emit('subscribed', {'topic': topic})
                logger.info(f"Client {client_id} subscribed to {topic}")
        
        @self.socketio.on('unsubscribe')
        def handle_unsubscribe(data):
            """Handle unsubscription from topics"""
            client_id = self._get_client_id()
            topic = data.get('topic')
            
            if topic and topic in self.subscriptions.get(client_id, set()):
                self.subscriptions[client_id].discard(topic)
                emit('unsubscribed', {'topic': topic})
        
        @self.socketio.on('join_tenant')
        def handle_join_tenant(data):
            """Join tenant-specific room"""
            client_id = self._get_client_id()
            tenant_id = data.get('tenant_id')
            
            if tenant_id:
                room = f"tenant_{tenant_id}"
                join_room(room)
                
                if tenant_id not in self.tenant_rooms:
                    self.tenant_rooms[tenant_id] = set()
                self.tenant_rooms[tenant_id].add(client_id)
                
                emit('joined_tenant', {'tenant_id': tenant_id})
                logger.info(f"Client {client_id} joined tenant {tenant_id}")
        
        @self.socketio.on('leave_tenant')
        def handle_leave_tenant(data):
            """Leave tenant-specific room"""
            client_id = self._get_client_id()
            tenant_id = data.get('tenant_id')
            
            if tenant_id:
                room = f"tenant_{tenant_id}"
                leave_room(room)
                
                if tenant_id in self.tenant_rooms:
                    self.tenant_rooms[tenant_id].discard(client_id)
                
                emit('left_tenant', {'tenant_id': tenant_id})
    
    def _get_client_id(self) -> str:
        """Get client ID from request"""
        from flask import request
        return request.sid
    
    # ============ Broadcast methods ============
    
    def broadcast_scan_update(self, scan_data: Dict):
        """Broadcast scan update to all clients"""
        self.socketio.emit('scan_update', scan_data)
        logger.debug(f"Broadcast scan update: {scan_data.get('scan_id')}")
    
    def broadcast_finding_update(self, finding_data: Dict):
        """Broadcast finding update to all clients"""
        self.socketio.emit('finding_update', finding_data)
        
        # Also send to tenant room if available
        tenant_id = finding_data.get('tenant_id')
        if tenant_id:
            self.socketio.emit('finding_update', finding_data,
                                 room=f"tenant_{tenant_id}")
    
    def broadcast_critical_alert(self, alert_data: Dict):
        """Broadcast critical alert to all clients"""
        self.socketio.emit('critical_alert', alert_data)
        logger.warning(f"Critical alert broadcast: {alert_data}")
    
    def broadcast_remediation_update(self, remediation_data: Dict):
        """Broadcast remediation update"""
        self.socketio.emit('remediation_update', remediation_data)
    
    def broadcast_compliance_update(self, compliance_data: Dict):
        """Broadcast compliance score update"""
        self.socketio.emit('compliance_update', compliance_data)
    
    def broadcast_stats_update(self, stats_data: Dict):
        """Broadcast statistics update"""
        self.socketio.emit('stats_update', stats_data)
    
    def send_to_tenant(self, tenant_id: str, event: str, data: Any):
        """Send event to a specific tenant room"""
        self.socketio.emit(event, data, room=f"tenant_{tenant_id}")
    
    def send_to_client(self, client_id: str, event: str, data: Any):
        """Send event to a specific client"""
        self.socketio.emit(event, data, room=client_id)
    
    def get_subscribed_clients(self, topic: str) -> int:
        """Get number of clients subscribed to a topic"""
        count = 0
        for clients in self.subscriptions.values():
            if topic in clients:
                count += 1
        return count
    
    def get_stats(self) -> Dict:
        """Get WebSocket statistics"""
        return {
            'connected_clients': len(self.connected_clients),
            'tenant_rooms': len(self.tenant_rooms),
            'total_subscriptions': sum(len(s) for s in self.subscriptions.values()),
            'topics': self._get_topic_stats()
        }
    
    def _get_topic_stats(self) -> Dict[str, int]:
        """Get subscription counts by topic"""
        topics = {}
        for clients in self.subscriptions.values():
            for topic in clients:
                topics[topic] = topics.get(topic, 0) + 1
        return topics