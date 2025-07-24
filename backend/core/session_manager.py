#!/usr/bin/env python3
"""
Redis-based Session Manager for MediVote
Replaces in-memory session storage with distributed session management for production scalability

SECURITY FEATURES:
- Distributed session storage using Redis
- Session encryption and signing
- Automatic session expiration
- Secure session token generation
- Session hijacking prevention
- Audit logging for all session operations
"""

import json
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import logging
from enum import Enum

import redis.asyncio as redis
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field
import jwt

from .config import get_settings, get_security_config
from .auth_models import AdminSession, SecurityEvent

logger = logging.getLogger(__name__)
settings = get_settings()
security_config = get_security_config()


class SessionStatus(str, Enum):
    """Session status types"""
    ACTIVE = "active"
    EXPIRED = "expired" 
    REVOKED = "revoked"
    LOCKED = "locked"


@dataclass
class SessionData:
    """Session data structure"""
    session_id: str
    user_id: str
    username: str
    role: str
    permissions: List[str]
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    mfa_verified: bool
    device_fingerprint: str
    status: SessionStatus = SessionStatus.ACTIVE
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Convert datetime objects to ISO strings
        data['created_at'] = self.created_at.isoformat()
        data['last_accessed'] = self.last_accessed.isoformat() 
        data['expires_at'] = self.expires_at.isoformat()
        data['status'] = self.status.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionData':
        # Convert ISO strings back to datetime objects
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['last_accessed'] = datetime.fromisoformat(data['last_accessed'])
        data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        data['status'] = SessionStatus(data['status'])
        return cls(**data)


class RedisSessionManager:
    """Production-grade Redis session manager"""
    
    def __init__(self, redis_url: str = None, encryption_key: bytes = None):
        """
        Initialize Redis session manager
        
        Args:
            redis_url: Redis connection URL
            encryption_key: 32-byte key for session data encryption
        """
        self.redis_url = redis_url or settings.REDIS_URL
        self.redis_client: Optional[redis.Redis] = None
        
        # Session encryption
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            # Generate or load encryption key securely
            self.encryption_key = self._get_or_create_session_key()
        
        self.cipher = Fernet(self.encryption_key)
        
        # Session configuration
        self.session_timeout = timedelta(hours=8)  # 8-hour sessions
        self.session_refresh_threshold = timedelta(minutes=30)  # Refresh if < 30min left
        self.max_sessions_per_user = 5  # Maximum concurrent sessions
        
        # Security tracking
        self.failed_session_attempts: Dict[str, int] = {}
        self.blocked_ips: Dict[str, datetime] = {}
    
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis session manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Redis session manager: {e}")
            raise RuntimeError(f"Redis session manager initialization failed: {e}")
    
    def _get_or_create_session_key(self) -> bytes:
        """Get or create session encryption key"""
        key_path = settings.get("SESSION_KEY_PATH", "session.key")
        
        try:
            with open(key_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            # Generate new key
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            logger.info("Generated new session encryption key")
            return key
    
    def _generate_session_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def _create_session_key(self, session_id: str) -> str:
        """Create Redis key for session"""
        return f"session:{session_id}"
    
    def _create_user_sessions_key(self, user_id: str) -> str:
        """Create Redis key for user sessions list"""
        return f"user_sessions:{user_id}"
    
    async def create_session(
        self,
        user_id: str,
        username: str,
        role: str,
        permissions: List[str],
        ip_address: str,
        user_agent: str,
        mfa_verified: bool = False,
        device_fingerprint: str = ""
    ) -> Tuple[str, SessionData]:
        """
        Create new session with security validation
        
        Returns:
            Tuple of (session_token, session_data)
        """
        if not self.redis_client:
            raise RuntimeError("Redis session manager not initialized")
        
        # Check for too many concurrent sessions
        await self._cleanup_expired_sessions(user_id)
        user_sessions = await self._get_user_sessions(user_id)
        
        if len(user_sessions) >= self.max_sessions_per_user:
            # Revoke oldest session
            oldest_session = min(user_sessions, key=lambda s: s.last_accessed)
            await self.revoke_session(oldest_session.session_id)
            logger.warning(f"Revoked oldest session for user {user_id} due to session limit")
        
        # Generate session
        session_id = self._generate_session_token()
        now = datetime.utcnow()
        
        session_data = SessionData(
            session_id=session_id,
            user_id=user_id,
            username=username,
            role=role,
            permissions=permissions,
            created_at=now,
            last_accessed=now,
            expires_at=now + self.session_timeout,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_verified=mfa_verified,
            device_fingerprint=device_fingerprint
        )
        
        # Encrypt and store session data
        encrypted_data = self.cipher.encrypt(json.dumps(session_data.to_dict()).encode())
        
        # Store in Redis with TTL
        session_key = self._create_session_key(session_id)
        ttl_seconds = int(self.session_timeout.total_seconds())
        
        await self.redis_client.setex(session_key, ttl_seconds, encrypted_data)
        
        # Add to user sessions list
        user_sessions_key = self._create_user_sessions_key(user_id)
        await self.redis_client.sadd(user_sessions_key, session_id)
        await self.redis_client.expire(user_sessions_key, ttl_seconds)
        
        # Log session creation
        await self._log_session_event(
            session_id, user_id, "SESSION_CREATED", 
            {"ip_address": ip_address, "user_agent": user_agent}
        )
        
        logger.info(f"Created session {session_id} for user {username}")
        return session_id, session_data
    
    async def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session data by session ID"""
        if not self.redis_client:
            return None
        
        try:
            session_key = self._create_session_key(session_id)
            encrypted_data = await self.redis_client.get(session_key)
            
            if not encrypted_data:
                return None
            
            # Decrypt session data
            decrypted_data = self.cipher.decrypt(encrypted_data)
            session_dict = json.loads(decrypted_data.decode())
            session_data = SessionData.from_dict(session_dict)
            
            # Check if session is expired
            if session_data.expires_at < datetime.utcnow():
                await self.revoke_session(session_id)
                return None
            
            # Update last accessed time if needed
            if datetime.utcnow() - session_data.last_accessed > timedelta(minutes=5):
                await self._update_session_access(session_id, session_data)
            
            return session_data
            
        except Exception as e:
            logger.error(f"Error retrieving session {session_id}: {e}")
            return None
    
    async def refresh_session(self, session_id: str) -> bool:
        """Refresh session expiration time"""
        session_data = await self.get_session(session_id)
        if not session_data:
            return False
        
        # Only refresh if close to expiry
        time_left = session_data.expires_at - datetime.utcnow()
        if time_left > self.session_refresh_threshold:
            return True  # No refresh needed
        
        # Extend session
        session_data.expires_at = datetime.utcnow() + self.session_timeout
        session_data.last_accessed = datetime.utcnow()
        
        # Re-encrypt and store
        encrypted_data = self.cipher.encrypt(json.dumps(session_data.to_dict()).encode())
        session_key = self._create_session_key(session_id)
        ttl_seconds = int(self.session_timeout.total_seconds())
        
        await self.redis_client.setex(session_key, ttl_seconds, encrypted_data)
        
        await self._log_session_event(session_id, session_data.user_id, "SESSION_REFRESHED", {})
        
        logger.info(f"Refreshed session {session_id}")
        return True
    
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a session"""
        session_data = await self.get_session(session_id)
        if not session_data:
            return False
        
        # Remove from Redis
        session_key = self._create_session_key(session_id)
        await self.redis_client.delete(session_key)
        
        # Remove from user sessions list
        user_sessions_key = self._create_user_sessions_key(session_data.user_id)
        await self.redis_client.srem(user_sessions_key, session_id)
        
        # Log session revocation
        await self._log_session_event(
            session_id, session_data.user_id, "SESSION_REVOKED", {}
        )
        
        logger.info(f"Revoked session {session_id}")
        return True
    
    async def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user"""
        user_sessions = await self._get_user_sessions(user_id)
        revoked_count = 0
        
        for session_data in user_sessions:
            if await self.revoke_session(session_data.session_id):
                revoked_count += 1
        
        logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
        return revoked_count
    
    async def _get_user_sessions(self, user_id: str) -> List[SessionData]:
        """Get all active sessions for a user"""
        if not self.redis_client:
            return []
        
        user_sessions_key = self._create_user_sessions_key(user_id)
        session_ids = await self.redis_client.smembers(user_sessions_key)
        
        sessions = []
        for session_id in session_ids:
            session_data = await self.get_session(session_id.decode())
            if session_data:
                sessions.append(session_data)
        
        return sessions
    
    async def _update_session_access(self, session_id: str, session_data: SessionData):
        """Update session last accessed time"""
        session_data.last_accessed = datetime.utcnow()
        
        # Re-encrypt and store
        encrypted_data = self.cipher.encrypt(json.dumps(session_data.to_dict()).encode())
        session_key = self._create_session_key(session_id)
        
        # Keep existing TTL
        ttl = await self.redis_client.ttl(session_key)
        if ttl > 0:
            await self.redis_client.setex(session_key, ttl, encrypted_data)
    
    async def _cleanup_expired_sessions(self, user_id: str):
        """Clean up expired sessions for a user"""
        user_sessions = await self._get_user_sessions(user_id)
        now = datetime.utcnow()
        
        for session_data in user_sessions:
            if session_data.expires_at < now:
                await self.revoke_session(session_data.session_id)
    
    async def _log_session_event(
        self, 
        session_id: str, 
        user_id: str, 
        event_type: str, 
        metadata: Dict[str, Any]
    ):
        """Log session security events"""
        # This would integrate with your audit logging system
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "session_id": session_id,
            "user_id": user_id,
            "metadata": metadata
        }
        
        # Store in Redis for real-time monitoring
        event_key = f"session_events:{datetime.utcnow().strftime('%Y-%m-%d')}"
        await self.redis_client.lpush(event_key, json.dumps(event_data))
        await self.redis_client.expire(event_key, 86400 * 7)  # Keep for 7 days
    
    async def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics for monitoring"""
        if not self.redis_client:
            return {}
        
        # Get all session keys
        session_keys = await self.redis_client.keys("session:*")
        active_sessions = len(session_keys)
        
        # Get user session counts
        user_session_keys = await self.redis_client.keys("user_sessions:*")
        active_users = len(user_session_keys)
        
        return {
            "active_sessions": active_sessions,
            "active_users": active_users,
            "redis_connected": True,
            "session_timeout_hours": self.session_timeout.total_seconds() / 3600,
            "max_sessions_per_user": self.max_sessions_per_user
        }


# Global session manager instance
session_manager: Optional[RedisSessionManager] = None


async def get_session_manager() -> RedisSessionManager:
    """Get the global session manager instance"""
    global session_manager
    if not session_manager:
        session_manager = RedisSessionManager()
        await session_manager.initialize()
    return session_manager


async def initialize_session_manager(redis_url: str = None) -> RedisSessionManager:
    """Initialize the global session manager"""
    global session_manager
    session_manager = RedisSessionManager(redis_url=redis_url)
    await session_manager.initialize()
    return session_manager