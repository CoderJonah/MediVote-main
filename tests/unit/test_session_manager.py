#!/usr/bin/env python3
"""
Unit Tests for Redis Session Manager
Tests all session management functionality including creation, validation, expiration, and Redis integration
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from freezegun import freeze_time

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from core.session_manager import (
    RedisSessionManager, SessionData, SessionStatus,
    get_session_manager, initialize_session_manager
)
from core.error_handler import AuthenticationError


class TestSessionData:
    """Test SessionData model"""
    
    def test_session_data_creation(self):
        """Test creating SessionData instance"""
        now = datetime.utcnow()
        session_data = SessionData(
            session_id="test_session_123",
            user_id="user_123",
            username="testuser",
            role="voter",
            permissions=["vote", "verify"],
            created_at=now,
            last_accessed=now,
            expires_at=now + timedelta(hours=8),
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            mfa_verified=True,
            device_fingerprint="fingerprint_123"
        )
        
        assert session_data.session_id == "test_session_123"
        assert session_data.user_id == "user_123"
        assert session_data.role == "voter"
        assert session_data.permissions == ["vote", "verify"]
        assert session_data.mfa_verified is True
        assert session_data.status == SessionStatus.ACTIVE
    
    def test_session_data_to_dict(self):
        """Test converting SessionData to dictionary"""
        now = datetime.utcnow()
        session_data = SessionData(
            session_id="test_session_123",
            user_id="user_123",
            username="testuser",
            role="voter",
            permissions=["vote"],
            created_at=now,
            last_accessed=now,
            expires_at=now + timedelta(hours=8),
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            mfa_verified=False,
            device_fingerprint="fingerprint_123"
        )
        
        data_dict = session_data.to_dict()
        
        assert data_dict["session_id"] == "test_session_123"
        assert data_dict["created_at"] == now.isoformat()
        assert data_dict["expires_at"] == (now + timedelta(hours=8)).isoformat()
        assert data_dict["status"] == "active"
    
    def test_session_data_from_dict(self):
        """Test creating SessionData from dictionary"""
        now = datetime.utcnow()
        data_dict = {
            "session_id": "test_session_123",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": now.isoformat(),
            "last_accessed": now.isoformat(),
            "expires_at": (now + timedelta(hours=8)).isoformat(),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": False,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        session_data = SessionData.from_dict(data_dict)
        
        assert session_data.session_id == "test_session_123"
        assert session_data.created_at == now
        assert session_data.expires_at == now + timedelta(hours=8)
        assert session_data.status == SessionStatus.ACTIVE


class TestRedisSessionManager:
    """Test RedisSessionManager functionality"""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client"""
        redis_mock = AsyncMock()
        redis_mock.ping = AsyncMock()
        redis_mock.setex = AsyncMock()
        redis_mock.get = AsyncMock()
        redis_mock.delete = AsyncMock()
        redis_mock.sadd = AsyncMock()
        redis_mock.srem = AsyncMock()
        redis_mock.smembers = AsyncMock()
        redis_mock.expire = AsyncMock()
        redis_mock.ttl = AsyncMock()
        redis_mock.keys = AsyncMock()
        redis_mock.lpush = AsyncMock()
        return redis_mock
    
    @pytest.fixture
    def session_manager(self, mock_redis):
        """Create session manager with mocked Redis"""
        with patch('core.session_manager.redis.from_url', return_value=mock_redis):
            manager = RedisSessionManager(redis_url="redis://localhost:6379")
            manager.redis_client = mock_redis
            return manager
    
    @pytest.mark.asyncio
    async def test_initialize_success(self, mock_redis):
        """Test successful Redis initialization"""
        with patch('core.session_manager.redis.from_url', return_value=mock_redis):
            manager = RedisSessionManager()
            await manager.initialize()
            
            mock_redis.ping.assert_called_once()
            assert manager.redis_client == mock_redis
    
    @pytest.mark.asyncio
    async def test_initialize_failure(self):
        """Test Redis initialization failure"""
        mock_redis = AsyncMock()
        mock_redis.ping.side_effect = Exception("Connection failed")
        
        with patch('core.session_manager.redis.from_url', return_value=mock_redis):
            manager = RedisSessionManager()
            
            with pytest.raises(RuntimeError, match="Redis session manager initialization failed"):
                await manager.initialize()
    
    @pytest.mark.asyncio
    async def test_create_session_success(self, session_manager, mock_redis):
        """Test successful session creation"""
        mock_redis.smembers.return_value = set()  # No existing sessions
        
        session_id, session_data = await session_manager.create_session(
            user_id="user_123",
            username="testuser",
            role="voter",
            permissions=["vote", "verify"],
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            mfa_verified=True,
            device_fingerprint="fingerprint_123"
        )
        
        assert session_id is not None
        assert len(session_id) > 20  # Secure token length
        assert session_data.user_id == "user_123"
        assert session_data.username == "testuser"
        assert session_data.role == "voter"
        assert session_data.permissions == ["vote", "verify"]
        assert session_data.mfa_verified is True
        
        # Verify Redis calls
        mock_redis.setex.assert_called_once()
        mock_redis.sadd.assert_called_once()
        mock_redis.expire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_session_max_sessions_exceeded(self, session_manager, mock_redis):
        """Test session creation when max sessions exceeded"""
        # Mock existing sessions
        existing_sessions = [f"session_{i}" for i in range(5)]
        mock_redis.smembers.return_value = set(existing_sessions)
        
        # Mock session data for cleanup
        old_session_data = {
            "session_id": "old_session",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "last_accessed": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=6)).isoformat(),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(old_session_data).encode())
        mock_redis.get.return_value = encrypted_data
        
        session_id, session_data = await session_manager.create_session(
            user_id="user_123",
            username="testuser",
            role="voter",
            permissions=["vote"],
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        # Should create new session and revoke oldest
        assert session_id is not None
        mock_redis.delete.assert_called()  # Oldest session deleted
    
    @pytest.mark.asyncio
    async def test_get_session_success(self, session_manager, mock_redis):
        """Test successful session retrieval"""
        now = datetime.utcnow()
        session_data_dict = {
            "session_id": "test_session_123",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": now.isoformat(),
            "last_accessed": now.isoformat(),
            "expires_at": (now + timedelta(hours=8)).isoformat(),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(session_data_dict).encode())
        mock_redis.get.return_value = encrypted_data
        
        session_data = await session_manager.get_session("test_session_123")
        
        assert session_data is not None
        assert session_data.session_id == "test_session_123"
        assert session_data.user_id == "user_123"
        assert session_data.mfa_verified is True
        
        mock_redis.get.assert_called_with("session:test_session_123")
    
    @pytest.mark.asyncio
    async def test_get_session_not_found(self, session_manager, mock_redis):
        """Test session retrieval when session doesn't exist"""
        mock_redis.get.return_value = None
        
        session_data = await session_manager.get_session("nonexistent_session")
        
        assert session_data is None
    
    @pytest.mark.asyncio
    async def test_get_session_expired(self, session_manager, mock_redis):
        """Test session retrieval when session is expired"""
        now = datetime.utcnow()
        expired_session_data = {
            "session_id": "expired_session",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": (now - timedelta(hours=10)).isoformat(),
            "last_accessed": (now - timedelta(hours=1)).isoformat(),
            "expires_at": (now - timedelta(minutes=1)).isoformat(),  # Expired
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(expired_session_data).encode())
        mock_redis.get.return_value = encrypted_data
        
        session_data = await session_manager.get_session("expired_session")
        
        assert session_data is None
        # Should have called revoke_session
        mock_redis.delete.assert_called()
    
    @pytest.mark.asyncio
    async def test_refresh_session_success(self, session_manager, mock_redis):
        """Test successful session refresh"""
        now = datetime.utcnow()
        # Session close to expiry (within refresh threshold)
        session_data_dict = {
            "session_id": "test_session_123",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": (now - timedelta(hours=7)).isoformat(),
            "last_accessed": now.isoformat(),
            "expires_at": (now + timedelta(minutes=15)).isoformat(),  # Close to expiry
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(session_data_dict).encode())
        mock_redis.get.return_value = encrypted_data
        
        result = await session_manager.refresh_session("test_session_123")
        
        assert result is True
        mock_redis.setex.assert_called()  # Session should be updated
    
    @pytest.mark.asyncio
    async def test_refresh_session_not_needed(self, session_manager, mock_redis):
        """Test session refresh when not needed"""
        now = datetime.utcnow()
        # Session with plenty of time left
        session_data_dict = {
            "session_id": "test_session_123",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": now.isoformat(),
            "last_accessed": now.isoformat(),
            "expires_at": (now + timedelta(hours=6)).isoformat(),  # Plenty of time
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(session_data_dict).encode())
        mock_redis.get.return_value = encrypted_data
        
        result = await session_manager.refresh_session("test_session_123")
        
        assert result is True
        # Should not update Redis since refresh not needed
        mock_redis.setex.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_revoke_session_success(self, session_manager, mock_redis):
        """Test successful session revocation"""
        now = datetime.utcnow()
        session_data_dict = {
            "session_id": "test_session_123",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": now.isoformat(),
            "last_accessed": now.isoformat(),
            "expires_at": (now + timedelta(hours=8)).isoformat(),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(session_data_dict).encode())
        mock_redis.get.return_value = encrypted_data
        
        result = await session_manager.revoke_session("test_session_123")
        
        assert result is True
        mock_redis.delete.assert_called_with("session:test_session_123")
        mock_redis.srem.assert_called_with("user_sessions:user_123", "test_session_123")
    
    @pytest.mark.asyncio
    async def test_revoke_session_not_found(self, session_manager, mock_redis):
        """Test revoking non-existent session"""
        mock_redis.get.return_value = None
        
        result = await session_manager.revoke_session("nonexistent_session")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions(self, session_manager, mock_redis):
        """Test revoking all sessions for a user"""
        # Mock user sessions
        mock_redis.smembers.return_value = {b"session_1", b"session_2", b"session_3"}
        
        # Mock session data for each session
        now = datetime.utcnow()
        session_data_dict = {
            "session_id": "session_1",
            "user_id": "user_123",
            "username": "testuser",
            "role": "voter",
            "permissions": ["vote"],
            "created_at": now.isoformat(),
            "last_accessed": now.isoformat(),
            "expires_at": (now + timedelta(hours=8)).isoformat(),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "mfa_verified": True,
            "device_fingerprint": "fingerprint_123",
            "status": "active"
        }
        
        encrypted_data = session_manager.cipher.encrypt(json.dumps(session_data_dict).encode())
        mock_redis.get.return_value = encrypted_data
        
        revoked_count = await session_manager.revoke_all_user_sessions("user_123")
        
        assert revoked_count == 3
        assert mock_redis.delete.call_count == 3
    
    @pytest.mark.asyncio
    async def test_get_session_stats(self, session_manager, mock_redis):
        """Test getting session statistics"""
        mock_redis.keys.side_effect = [
            ["session:1", "session:2", "session:3"],  # Session keys
            ["user_sessions:user1", "user_sessions:user2"]  # User session keys
        ]
        
        stats = await session_manager.get_session_stats()
        
        assert stats["active_sessions"] == 3
        assert stats["active_users"] == 2
        assert stats["redis_connected"] is True
        assert stats["session_timeout_hours"] == 8.0
        assert stats["max_sessions_per_user"] == 5
    
    def test_session_key_generation(self, session_manager):
        """Test Redis key generation methods"""
        session_key = session_manager._create_session_key("test_session_123")
        assert session_key == "session:test_session_123"
        
        user_sessions_key = session_manager._create_user_sessions_key("user_123")
        assert user_sessions_key == "user_sessions:user_123"
    
    def test_session_token_generation(self, session_manager):
        """Test secure session token generation"""
        token1 = session_manager._generate_session_token()
        token2 = session_manager._generate_session_token()
        
        assert len(token1) > 20  # Should be substantial length
        assert len(token2) > 20
        assert token1 != token2  # Should be unique
        assert all(c.isalnum() or c in '_-' for c in token1)  # URL-safe characters


class TestGlobalSessionManager:
    """Test global session manager functions"""
    
    @pytest.mark.asyncio
    async def test_get_session_manager_singleton(self):
        """Test that get_session_manager returns singleton"""
        with patch('core.session_manager.RedisSessionManager') as mock_manager_class:
            mock_instance = AsyncMock()
            mock_manager_class.return_value = mock_instance
            
            # Clear global instance
            import core.session_manager as sm
            sm.session_manager = None
            
            # First call should create instance
            manager1 = await get_session_manager()
            assert manager1 == mock_instance
            mock_instance.initialize.assert_called_once()
            
            # Second call should return same instance
            manager2 = await get_session_manager()
            assert manager2 == mock_instance
            assert manager1 is manager2
    
    @pytest.mark.asyncio
    async def test_initialize_session_manager(self):
        """Test session manager initialization function"""
        with patch('core.session_manager.RedisSessionManager') as mock_manager_class:
            mock_instance = AsyncMock()
            mock_manager_class.return_value = mock_instance
            
            manager = await initialize_session_manager("redis://custom:6379")
            
            assert manager == mock_instance
            mock_manager_class.assert_called_once_with(redis_url="redis://custom:6379")
            mock_instance.initialize.assert_called_once()


# Integration-style tests (would require real Redis in full integration testing)
class TestSessionManagerIntegration:
    """Integration tests for session manager (mocked Redis)"""
    
    @pytest.mark.asyncio
    async def test_full_session_lifecycle(self):
        """Test complete session lifecycle: create, get, refresh, revoke"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_redis.get = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.sadd = AsyncMock()
        mock_redis.srem = AsyncMock()
        mock_redis.smembers = AsyncMock(return_value=set())
        mock_redis.expire = AsyncMock()
        mock_redis.ttl = AsyncMock(return_value=3600)
        mock_redis.lpush = AsyncMock()
        
        with patch('core.session_manager.redis.from_url', return_value=mock_redis):
            manager = RedisSessionManager()
            await manager.initialize()
            
            # Create session
            session_id, session_data = await manager.create_session(
                user_id="user_123",
                username="testuser",
                role="admin",
                permissions=["read", "write"],
                ip_address="192.168.1.1",
                user_agent="Test Agent",
                mfa_verified=True
            )
            
            # Mock the encrypted session data for get_session
            encrypted_data = manager.cipher.encrypt(json.dumps(session_data.to_dict()).encode())
            mock_redis.get.return_value = encrypted_data
            
            # Get session
            retrieved_session = await manager.get_session(session_id)
            assert retrieved_session is not None
            assert retrieved_session.user_id == "user_123"
            assert retrieved_session.role == "admin"
            
            # Refresh session
            refresh_result = await manager.refresh_session(session_id)
            assert refresh_result is True
            
            # Revoke session
            revoke_result = await manager.revoke_session(session_id)
            assert revoke_result is True
            
            # Try to get revoked session
            mock_redis.get.return_value = None
            revoked_session = await manager.get_session(session_id)
            assert revoked_session is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])