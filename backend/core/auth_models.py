"""
Advanced Authentication Models for Production MediVote
Implements role-based access control, secure sessions, and admin management
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

import bcrypt
from pydantic import BaseModel, Field, validator
from sqlalchemy import Column, String, DateTime, Boolean, Text, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

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
    """Comprehensive audit logging"""
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Event details
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), default="INFO")
    message = Column(Text, nullable=False)
    
    # User context
    user_id = Column(String(255))
    user_role = Column(String(50))
    session_id = Column(String(255))
    
    # Request context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    endpoint = Column(String(255))
    method = Column(String(10))
    
    # Additional data
    metadata = Column(JSON, default=dict)
    risk_score = Column(Integer, default=0)

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
    def calculate_risk_score(event_type: SecurityEvent, metadata: Dict) -> int:
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
        
        # Adjust based on metadata
        if metadata.get('repeated_attempts', 0) > 3:
            score += 30
        if metadata.get('unusual_location', False):
            score += 20
        if metadata.get('privileged_operation', False):
            score += 25
            
        return min(score, 100)  # Cap at 100 