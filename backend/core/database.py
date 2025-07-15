"""
Database management for MediVote
Enhanced with production authentication and security features
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import uuid

from sqlalchemy import (
    create_engine, Column, String, DateTime, Boolean, 
    Integer, Text, JSON, BigInteger, MetaData
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from loguru import logger

from .config import get_settings
from .auth_models import AdminUser, AdminSession, AuditLog, APIKey, Base as AuthBase

settings = get_settings()

# Create declarative base
Base = declarative_base()

# Database models
class User(Base):
    """User model for DID-based authentication"""
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    did = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    status = Column(String(50), default='active')

class Election(Base):
    """Election model"""
    __tablename__ = "elections"
    
    id = Column(String, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(String(50), default='pending')  # pending, active, completed
    
    # Blockchain integration
    blockchain_address = Column(String(255))
    transaction_hash = Column(String(255))
    
    # Cryptographic setup
    homomorphic_public_key = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(255))
    updated_at = Column(DateTime, default=datetime.utcnow)

class Vote(Base):
    """Vote model for audit trail"""
    __tablename__ = "votes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    election_id = Column(String(255), nullable=False)
    voter_did = Column(String(255), nullable=False)
    
    # Encrypted vote data
    encrypted_ballot = Column(Text, nullable=False)
    ballot_signature = Column(Text, nullable=False)
    
    # Blockchain reference
    transaction_hash = Column(String(255))
    block_number = Column(BigInteger)
    
    # Verification
    verification_receipt = Column(String(255), unique=True)
    
    # Metadata
    cast_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    device_fingerprint_hash = Column(String(255))

class Database:
    """Enhanced database service with security features"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = MetaData()
    
    async def initialize(self):
        """Initialize database with all tables"""
        try:
            # Create engine
            self.engine = create_engine(
                settings.DATABASE_URL,
                echo=settings.DATABASE_ECHO,
                pool_pre_ping=True,
                pool_recycle=300
            )
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            # Create all tables
            Base.metadata.create_all(bind=self.engine)
            AuthBase.metadata.create_all(bind=self.engine)
            
            # Initialize default admin user if not exists
            await self._create_default_admin()
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    async def _create_default_admin(self):
        """Create default admin user for initial access"""
        db = self.get_session()
        try:
            # Check if any admin users exist
            existing_admin = db.query(AdminUser).first()
            
            if not existing_admin:
                from .auth_models import SecurityUtils, UserRole
                
                # Create default admin
                password = "TempAdmin123!@#"  # Should be changed immediately
                password_hash, salt = SecurityUtils.hash_password(password)
                
                default_admin = AdminUser(
                    id=str(uuid.uuid4()),
                    username="admin",
                    email="admin@medivote.local",
                    password_hash=password_hash,
                    salt=salt,
                    role=UserRole.SUPER_ADMIN.value,
                    permissions=[],
                    is_active=True,
                    is_verified=True,
                    created_by="system",
                    created_at=datetime.utcnow()
                )
                
                db.add(default_admin)
                db.commit()
                
                logger.warning(
                    "Default admin user created: username='admin', password='TempAdmin123!@#' "
                    "*** CHANGE THIS PASSWORD IMMEDIATELY ***"
                )
            
        except Exception as e:
            logger.error(f"Failed to create default admin: {e}")
            db.rollback()
        finally:
            db.close()
    
    def get_session(self) -> Session:
        """Get database session"""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        return self.SessionLocal()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check database health"""
        try:
            db = self.get_session()
            
            # Simple query to test connection
            result = db.execute("SELECT 1").fetchone()
            
            # Get table counts
            user_count = db.query(User).count()
            admin_count = db.query(AdminUser).count()
            session_count = db.query(AdminSession).filter(
                AdminSession.is_active == True
            ).count()
            
            db.close()
            
            return {
                "status": "healthy",
                "connection": "active",
                "users": user_count,
                "admins": admin_count,
                "active_sessions": session_count,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        try:
            db = self.get_session()
            
            # Delete expired sessions
            expired_count = db.query(AdminSession).filter(
                AdminSession.expires_at < datetime.utcnow()
            ).delete()
            
            db.commit()
            db.close()
            
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired sessions")
                
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
    
    async def get_security_metrics(self) -> Dict[str, Any]:
        """Get security-related metrics"""
        try:
            db = self.get_session()
            
            # Count various security events
            recent_logins = db.query(AuditLog).filter(
                AuditLog.event_type == "login_success",
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).count()
            
            failed_logins = db.query(AuditLog).filter(
                AuditLog.event_type == "login_failed",
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).count()
            
            high_risk_events = db.query(AuditLog).filter(
                AuditLog.risk_score >= 70,
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).count()
            
            active_sessions = db.query(AdminSession).filter(
                AdminSession.is_active == True,
                AdminSession.expires_at > datetime.utcnow()
            ).count()
            
            db.close()
            
            return {
                "recent_logins": recent_logins,
                "failed_logins": failed_logins,
                "high_risk_events": high_risk_events,
                "active_sessions": active_sessions,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Security metrics failed: {e}")
            return {}
    
    async def close(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connections closed")

# Dependency for getting database session
def get_db() -> Session:
    """FastAPI dependency for database session"""
    from .database import Database
    
    # This will be replaced with proper dependency injection
    db_instance = Database()
    if not db_instance.SessionLocal:
        # Initialize if not already done
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're in an async context, we need to handle this differently
            pass
        else:
            loop.run_until_complete(db_instance.initialize())
    
    db = db_instance.get_session()
    try:
        yield db
    finally:
        db.close() 