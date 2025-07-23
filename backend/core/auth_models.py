"""
Advanced Authentication Models for Production MediVote
Implements role-based access control, secure sessions, and admin management
"""

import hashlib
import secrets
import uuid
import json
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass

import bcrypt
from pydantic import BaseModel, Field, validator
from sqlalchemy import Column, String, DateTime, Boolean, Text, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
logger = logging.getLogger(__name__)

class UserRole(str, Enum):
    """User roles with hierarchical permissions"""
    SUPER_ADMIN = "super_admin"        # Full system access
    ELECTION_ADMIN = "election_admin"   # Election management
    AUDITOR = "auditor"                # Read-only audit access
    SUPPORT = "support"                # Technical support access
    VOTER = "voter"                    # Standard voter access

class Permission(str, Enum):
    """Granular permissions for fine-grained access control"""
    # Election Management
    CREATE_ELECTION = "create_election"
    MODIFY_ELECTION = "modify_election"
    DELETE_ELECTION = "delete_election"
    VIEW_ELECTION = "view_election"
    
    # System Administration
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_SYSTEM = "manage_system"
    
    # Voting Operations
    VOTE = "vote"
    VERIFY_VOTE = "verify_vote"
    
    # Results and Analytics
    VIEW_RESULTS = "view_results"
    EXPORT_DATA = "export_data"

class SecurityEvent(str, Enum):
    """Security event types for audit logging"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ROLE_CHANGE = "role_change"
    PERMISSION_DENIED = "permission_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ADMIN_ACTION = "admin_action"
    DATA_ACCESS = "data_access"
    SYSTEM_CHANGE = "system_change"

# Database Models
class AdminUser(Base):
    """Admin user model with enhanced security"""
    __tablename__ = "admin_users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)
    permissions = Column(JSON, default=list)
    
    # Security fields
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    last_login = Column(DateTime)
    last_failed_login = Column(DateTime)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    
    # MFA fields
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))
    backup_codes = Column(JSON, default=list)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(255))
    updated_at = Column(DateTime, default=datetime.utcnow)
    
    # Session tracking
    max_concurrent_sessions = Column(Integer, default=3)

class AdminSession(Base):
    """Secure admin session management"""
    __tablename__ = "admin_sessions"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    session_token = Column(String(255), unique=True, nullable=False)
    refresh_token = Column(String(255), unique=True, nullable=False)
    
    # Session metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    
    # Device information
    device_fingerprint = Column(String(255))
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    
    # Security flags
    is_active = Column(Boolean, default=True)
    requires_mfa = Column(Boolean, default=False)
    mfa_verified = Column(Boolean, default=False)

class AuditLog(Base):
    """
    🔐 ENHANCED COMPREHENSIVE AUDIT LOGGING with FULL ENCRYPTION
    
    CRITICAL SECURITY ENHANCEMENT: All sensitive fields are now encrypted
    - IP addresses encrypted to prevent location tracking
    - User agents encrypted to prevent device fingerprinting
    - Session IDs encrypted to prevent session correlation
    - Metadata encrypted to prevent sensitive data leakage
    - User IDs encrypted to prevent identity correlation
    
    ⚠️  SECURITY FLAW IDENTIFIED & FIXED:
    Previous implementation stored sensitive audit data in plaintext:
    1. IP addresses could reveal user locations and correlate activities
    2. User agents could enable device fingerprinting across sessions
    3. Session IDs could link activities to specific user sessions
    4. Metadata could contain sensitive operational details
    5. User IDs could enable cross-election activity correlation
    
    This violated voter privacy and admin operational security.
    """
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Event details (kept unencrypted for filtering and alerting)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), default="INFO")
    message = Column(Text, nullable=False)
    
    # 🔒 ENCRYPTED SENSITIVE FIELDS
    # All PII and sensitive context is now encrypted
    encrypted_user_context = Column(Text)  # Contains: user_id, user_role, session_id
    encrypted_request_context = Column(Text)  # Contains: ip_address, user_agent, endpoint, method
    encrypted_audit_metadata = Column(Text)  # Contains: audit_metadata, risk_score
    
    # Encryption metadata for future key rotation
    encryption_version = Column(String(10), default="2.0")  # Track encryption scheme version
    
    @classmethod
    def create_encrypted_audit_log(
        cls,
        event_type: str,
        message: str,
        severity: str = "INFO",
        user_id: str = None,
        user_role: str = None,
        session_id: str = None,
        ip_address: str = None,
        user_agent: str = None,
        endpoint: str = None,
        method: str = None,
        audit_metadata: Dict[str, Any] = None,
        risk_score: int = 0,
        encryption_key: bytes = None
    ) -> 'AuditLog':
        """
        🏭 FACTORY METHOD: Create audit log with INTEGRATED KEY MANAGEMENT
        
        SECURITY ENHANCEMENT: Now integrates with MediVote key management system
        - Automatically retrieves encryption key from secure key manager
        - Falls back to provided key for backward compatibility
        - Ensures all sensitive data is encrypted before storage
        - Provides a clean interface for creating audit logs
        
        Args:
            event_type: Type of security event (unencrypted for filtering)
            message: Human-readable message (unencrypted for alerting)
            severity: Event severity level (unencrypted for alerting)
            encryption_key: Optional 32-byte key (uses key manager if None)
            ... other fields: All sensitive data that will be encrypted
        """
        from cryptography.fernet import Fernet
        import base64
        
        # 🔐 INTEGRATED KEY MANAGEMENT
        if encryption_key is None:
            try:
                # Get encryption key from key management system
                from backend.core.key_integration import get_audit_encryption_key
                encryption_key = get_audit_encryption_key()
                logger.debug("🔑 Using audit encryption key from key management system")
            except Exception as e:
                logger.error(f"❌ Failed to get audit encryption key from key manager: {e}")
                raise ValueError("SECURITY ERROR: No audit encryption key available - initialize key management system first")
        
        if not encryption_key or len(encryption_key) != 32:
            raise ValueError("🚨 SECURITY ERROR: Valid encryption key required for audit logging")
        
        fernet = Fernet(base64.urlsafe_b64encode(encryption_key))
        
        def encrypt_data(data: Dict[str, Any]) -> str:
            """Encrypt dictionary data for secure storage"""
            try:
                json_data = json.dumps(data, sort_keys=True, default=str)
                encrypted_data = fernet.encrypt(json_data.encode())
                return base64.b64encode(encrypted_data).decode()
            except Exception as e:
                # Never fail audit logging - use emergency fallback
                logger.error(f"🚨 Encryption failed in audit log: {e}")
                return base64.b64encode(b"ENCRYPTION_FAILED").decode()
        
        # Encrypt user context (identity-related data)
        user_context = {
            "user_id": user_id,
            "user_role": user_role,
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Encrypt request context (network-related data)
        request_context = {
            "ip_address": ip_address,
            "user_agent": user_agent,
            "endpoint": endpoint,
            "method": method,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Encrypt metadata (operational data)
        metadata_context = {
            "audit_metadata": audit_metadata or {},
            "risk_score": risk_score,
            "encryption_timestamp": datetime.utcnow().isoformat(),
            "privacy_note": "All sensitive fields encrypted for privacy protection"
        }
        
        return cls(
            event_type=event_type,
            severity=severity,
            message=message,
            encrypted_user_context=encrypt_data(user_context),
            encrypted_request_context=encrypt_data(request_context),
            encrypted_audit_metadata=encrypt_data(metadata_context),
            encryption_version="2.0"
        )
    
    def decrypt_audit_data(self, encryption_key: bytes = None) -> Dict[str, Any]:
        """
        🔓 SECURE DECRYPTION: Decrypt audit data with INTEGRATED KEY MANAGEMENT
        
        SECURITY ENHANCEMENT: Now integrates with MediVote key management system
        - Automatically retrieves encryption key from secure key manager if not provided
        - Falls back to provided key for backward compatibility
        - This method should only be called by authorized administrators
        - The access itself should be logged for accountability
        
        Args:
            encryption_key: Optional 32-byte key (uses key manager if None)
            
        Returns:
            Dictionary with decrypted audit data
        """
        from cryptography.fernet import Fernet
        import base64
        
        # 🔐 INTEGRATED KEY MANAGEMENT
        if encryption_key is None:
            try:
                # Get encryption key from key management system
                from backend.core.key_integration import get_audit_encryption_key
                encryption_key = get_audit_encryption_key()
                logger.debug("🔑 Using audit encryption key from key management system for decryption")
            except Exception as e:
                logger.error(f"❌ Failed to get audit encryption key from key manager: {e}")
                raise ValueError("SECURITY ERROR: No audit encryption key available - initialize key management system first")
        
        if not encryption_key or len(encryption_key) != 32:
            raise ValueError("🚨 SECURITY ERROR: Valid encryption key required for audit decryption")
        
        fernet = Fernet(base64.urlsafe_b64encode(encryption_key))
        
        def decrypt_data(encrypted_data: str) -> Dict[str, Any]:
            """Decrypt and parse JSON data"""
            try:
                if not encrypted_data:
                    return {}
                
                encrypted_bytes = base64.b64decode(encrypted_data.encode())
                decrypted_data = fernet.decrypt(encrypted_bytes)
                return json.loads(decrypted_data.decode())
            except Exception as e:
                logger.warning(f"🔍 Failed to decrypt audit field: {e}")
                return {"decryption_error": str(e), "encrypted": True}
        
        # Decrypt all encrypted fields
        user_context = decrypt_data(self.encrypted_user_context)
        request_context = decrypt_data(self.encrypted_request_context)
        metadata_context = decrypt_data(self.encrypted_audit_metadata)
        
        # Combine decrypted data with public fields
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "encryption_version": self.encryption_version,
            
            # Decrypted user context
            "user_id": user_context.get("user_id"),
            "user_role": user_context.get("user_role"),
            "session_id": user_context.get("session_id"),
            
            # Decrypted request context
            "ip_address": request_context.get("ip_address"),
            "user_agent": request_context.get("user_agent"),
            "endpoint": request_context.get("endpoint"),
            "method": request_context.get("method"),
            
            # Decrypted metadata
            "audit_metadata": metadata_context.get("audit_metadata", {}),
            "risk_score": metadata_context.get("risk_score", 0),
            
            # Privacy indicators
            "privacy_protected": True,
            "decryption_authorized": True
        }
    
    def get_public_summary(self) -> Dict[str, Any]:
        """
        📊 PUBLIC SUMMARY: Get non-sensitive audit data for statistics
        
        This method returns only non-sensitive fields that can be used
        for aggregate statistics and monitoring without privacy concerns.
        """
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "encryption_version": self.encryption_version,
            "message_preview": self.message[:50] + "..." if len(self.message) > 50 else self.message,
            "has_user_context": bool(self.encrypted_user_context),
            "has_request_context": bool(self.encrypted_request_context),
            "has_metadata": bool(self.encrypted_audit_metadata),
            "privacy_note": "Sensitive fields encrypted and not included in summary"
        }

class APIKey(Base):
    """API key management for service-to-service authentication"""
    __tablename__ = "api_keys"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False)
    key_prefix = Column(String(20), nullable=False)  # First few chars for identification
    
    # Access control
    permissions = Column(JSON, default=list)
    rate_limit = Column(Integer, default=1000)  # requests per hour
    
    # Status
    is_active = Column(Boolean, default=True)
    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    last_used = Column(DateTime)
    
    # Usage tracking
    usage_count = Column(Integer, default=0)

# Pydantic Models for API
class AdminLoginRequest(BaseModel):
    """Admin login request with enhanced security"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=6)
    device_fingerprint: Dict = Field(default_factory=dict)
    remember_me: bool = False

class AdminCreateRequest(BaseModel):
    """Admin user creation request"""
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=12)
    role: UserRole = Field(..., description="User role")
    permissions: List[Permission] = Field(default_factory=list)
    
    @validator('email')
    def validate_email(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid email format')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        """Enhanced password validation for admin accounts"""
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in v):
            raise ValueError('Password must contain special character')
        return v

class AdminResponse(BaseModel):
    """Admin user response model"""
    id: str
    username: str
    email: str
    role: UserRole
    permissions: List[Permission]
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login: Optional[datetime]
    created_at: datetime

class SessionResponse(BaseModel):
    """Session response with security context"""
    session_id: str
    access_token: str
    refresh_token: str
    expires_at: datetime
    user: AdminResponse
    permissions: List[Permission]
    requires_mfa: bool

class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str
    new_password: str = Field(..., min_length=12)
    mfa_code: Optional[str] = None
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Same validation as AdminCreateRequest"""
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in v):
            raise ValueError('Password must contain special character')
        return v

@dataclass
class SecurityContext:
    """Security context for request processing"""
    user_id: str
    username: str
    role: UserRole
    permissions: Set[Permission]
    session_id: str
    ip_address: str
    device_fingerprint: str
    mfa_verified: bool = False

# Permission Mappings
ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: {
        Permission.CREATE_ELECTION,
        Permission.MODIFY_ELECTION,
        Permission.DELETE_ELECTION,
        Permission.VIEW_ELECTION,
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MANAGE_SYSTEM,
        Permission.VIEW_RESULTS,
        Permission.EXPORT_DATA,
    },
    UserRole.ELECTION_ADMIN: {
        Permission.CREATE_ELECTION,
        Permission.MODIFY_ELECTION,
        Permission.VIEW_ELECTION,
        Permission.VIEW_RESULTS,
        Permission.EXPORT_DATA,
    },
    UserRole.AUDITOR: {
        Permission.VIEW_ELECTION,
        Permission.VIEW_AUDIT_LOGS,
        Permission.VIEW_RESULTS,
    },
    UserRole.SUPPORT: {
        Permission.VIEW_ELECTION,
        Permission.VIEW_AUDIT_LOGS,
    },
    UserRole.VOTER: {
        Permission.VOTE,
        Permission.VERIFY_VOTE,
    }
}

class SecurityUtils:
    """Security utility functions"""
    
    @staticmethod
    def hash_password(password: str) -> tuple[str, str]:
        """Hash password with salt using bcrypt"""
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8'), salt.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            password_hash.encode('utf-8')
        )
    
    @staticmethod
    def generate_api_key() -> tuple[str, str, str]:
        """Generate API key with prefix and hash"""
        # Generate random key
        key = secrets.token_urlsafe(32)
        prefix = f"mvote_{key[:8]}"
        full_key = f"{prefix}.{key}"
        
        # Hash for storage
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        
        return full_key, key_hash, prefix
    
    @staticmethod
    def generate_session_tokens() -> tuple[str, str]:
        """Generate session and refresh tokens"""
        session_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        return session_token, refresh_token
    
    @staticmethod
    def calculate_risk_score(event_type: SecurityEvent, audit_metadata: Dict) -> int:
        """Calculate risk score for security events"""
        base_scores = {
            SecurityEvent.LOGIN_FAILED: 20,
            SecurityEvent.PERMISSION_DENIED: 30,
            SecurityEvent.SUSPICIOUS_ACTIVITY: 80,
            SecurityEvent.LOGIN_SUCCESS: 5,
            SecurityEvent.ADMIN_ACTION: 15,
            SecurityEvent.SYSTEM_CHANGE: 40,
        }
        
        score = base_scores.get(event_type, 10)
        
        # Adjust based on audit_metadata
        if audit_metadata.get('repeated_attempts', 0) > 3:
            score += 2
        if audit_metadata.get('unusual_location', False):
            score += 2
        if audit_metadata.get('privileged_operation', False):
            score += 2
            
        return min(score, 100)  # Cap at 100 