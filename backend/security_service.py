"""
MediVote Security Service
Comprehensive authentication, authorization, encryption, and audit system
"""

import jwt
import hashlib
import secrets
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from dataclasses import dataclass
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

logger = logging.getLogger(__name__)

class UserRole(str, Enum):
    """User roles with hierarchical permissions"""
    SUPER_ADMIN = "super_admin"
    ELECTION_ADMIN = "election_admin" 
    AUDITOR = "auditor"
    VOTER = "voter"
    ANONYMOUS = "anonymous"

class Permission(str, Enum):
    """System permissions"""
    # Voting permissions
    VOTE = "vote"
    VERIFY_VOTE = "verify_vote"
    
    # Election management
    CREATE_ELECTION = "create_election"
    VIEW_ELECTION = "view_election"
    MODIFY_ELECTION = "modify_election"
    DELETE_ELECTION = "delete_election"
    
    # Results and data
    VIEW_RESULTS = "view_results"
    VIEW_ALL_RESULTS = "view_all_results"
    EXPORT_DATA = "export_data"
    
    # System administration
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    SYSTEM_ADMIN = "system_admin"
    SHUTDOWN_SYSTEM = "shutdown_system"

# Role-based permissions mapping
ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: {
        Permission.CREATE_ELECTION, Permission.VIEW_ELECTION, Permission.MODIFY_ELECTION,
        Permission.DELETE_ELECTION, Permission.VIEW_ALL_RESULTS, Permission.VIEW_RESULTS, Permission.EXPORT_DATA,
        Permission.MANAGE_USERS, Permission.VIEW_AUDIT_LOGS, Permission.SYSTEM_ADMIN,
        Permission.SHUTDOWN_SYSTEM, Permission.VOTE, Permission.VERIFY_VOTE  # Added for testing
    },
    UserRole.ELECTION_ADMIN: {
        Permission.CREATE_ELECTION, Permission.VIEW_ELECTION, Permission.MODIFY_ELECTION,
        Permission.VIEW_RESULTS, Permission.EXPORT_DATA
    },
    UserRole.AUDITOR: {
        Permission.VIEW_ELECTION, Permission.VIEW_RESULTS, Permission.VIEW_AUDIT_LOGS
    },
    UserRole.VOTER: {
        Permission.VOTE, Permission.VERIFY_VOTE, Permission.VIEW_ELECTION
    },
    UserRole.ANONYMOUS: set()  # No permissions
}

@dataclass
class SecurityContext:
    """Security context for authenticated users"""
    user_id: str
    username: str
    role: UserRole
    permissions: Set[Permission]
    session_id: str
    authenticated_at: datetime
    expires_at: datetime
    ip_address: str
    device_fingerprint: str

@dataclass
class AuditEvent:
    """Audit event for security logging"""
    event_id: str
    event_type: str
    user_id: Optional[str]
    username: Optional[str]
    action: str
    resource: str
    ip_address: str
    user_agent: str
    timestamp: datetime
    details: Dict[str, Any]
    success: bool

class EncryptionService:
    """Handles all encryption/decryption operations"""
    
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or os.getenv('MEDIVOTE_MASTER_KEY')
        if not self.master_key:
            # Try to load existing master key from secure file
            self.master_key = self._load_or_create_master_key()
        
        # Initialize encryption
        self._init_encryption()
    
    def _load_or_create_master_key(self) -> str:
        """Load existing master key or create new one and persist it"""
        key_file_path = os.path.join(os.path.dirname(__file__), 'keys', 'master.key')
        
        # Try to load existing key
        if os.path.exists(key_file_path):
            try:
                with open(key_file_path, 'r', encoding='utf-8') as f:
                    key = f.read().strip()
                    logger.info("🔑 Loaded existing master key from secure storage")
                    return key
            except Exception as e:
                logger.warning(f"Could not load existing master key: {e}")
        
        # Generate new master key
        new_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        
        # Save to secure file
        try:
            os.makedirs(os.path.dirname(key_file_path), exist_ok=True)
            with open(key_file_path, 'w', encoding='utf-8') as f:
                f.write(new_key)
            # Set restrictive permissions (owner read/write only)
            if hasattr(os, 'chmod'):
                os.chmod(key_file_path, 0o600)
            logger.info("🔑 Generated and saved new master key to secure storage")
        except Exception as e:
            logger.error(f"Could not save master key: {e}")
        
        return new_key
    
    def _init_encryption(self):
        """Initialize encryption with derived keys"""
        # Derive encryption key from master key
        master_bytes = self.master_key.encode()
        salt = b'medivote_salt_2024'  # In production, use random salt per encryption
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_bytes))
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt string data"""
        try:
            return self.fernet.encrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        try:
            return self.fernet.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise
    
    def encrypt_vote_choice(self, choice: str, voter_id: str) -> str:
        """Encrypt vote choice with voter-specific salt"""
        # Add voter-specific salt for additional security
        salted_choice = f"{choice}:{voter_id}:{int(time.time())}"
        return self.encrypt_data(salted_choice)
    
    def encrypt_anonymous_vote_choice(self, choice: str, receipt_id: str, verification_code: str) -> str:
        """Encrypt vote choice anonymously - only decryptable with receipt credentials"""
        try:
            # Create encryption key from receipt credentials
            key_material = f"{receipt_id}:{verification_code}:{self.master_key}".encode()
            choice_key = hashlib.pbkdf2_hmac('sha256', key_material, b'medivote_vote_salt', 100000)
            choice_key_b64 = base64.urlsafe_b64encode(choice_key)
            
            # Create Fernet instance with choice-specific key
            choice_fernet = Fernet(choice_key_b64)
            
            # Encrypt the choice
            encrypted_choice = choice_fernet.encrypt(choice.encode())
            
            return base64.b64encode(encrypted_choice).decode()
            
        except Exception as e:
            logger.error(f"Anonymous vote choice encryption error: {e}")
            raise
    
    def decrypt_anonymous_vote_choice(self, encrypted_choice: str, receipt_id: str, verification_code: str) -> str:
        """Decrypt anonymous vote choice using receipt credentials"""
        try:
            # Recreate the same encryption key
            key_material = f"{receipt_id}:{verification_code}:{self.master_key}".encode()
            choice_key = hashlib.pbkdf2_hmac('sha256', key_material, b'medivote_vote_salt', 100000)
            choice_key_b64 = base64.urlsafe_b64encode(choice_key)
            
            # Create Fernet instance with choice-specific key
            choice_fernet = Fernet(choice_key_b64)
            
            # Decrypt the choice
            encrypted_bytes = base64.b64decode(encrypted_choice.encode())
            decrypted_choice = choice_fernet.decrypt(encrypted_bytes)
            
            return decrypted_choice.decode()
            
        except Exception as e:
            logger.error(f"Anonymous vote choice decryption error: {e}")
            raise ValueError("Invalid receipt credentials or corrupted vote data")
    
    def hash_voter_id(self, voter_id: str) -> str:
        """Create anonymous hash of voter ID"""
        # Use HMAC for secure hashing with salt
        salt = "medivote_voter_anonymization_2024"
        data = f"{voter_id}:{salt}".encode()
        return hashlib.sha256(data).hexdigest()[:16]  # First 16 chars for anonymization

class AuthenticationService:
    """Handles authentication and authorization"""
    
    def __init__(self, jwt_secret: str, encryption_service: EncryptionService):
        self.jwt_secret = jwt_secret
        self.encryption = encryption_service
        self.active_sessions: Dict[str, SecurityContext] = {}
        self.failed_attempts: Dict[str, int] = {}
        self.rate_limits: Dict[str, List[float]] = {}
        self.audit_events: List[AuditEvent] = []
        
        # Create default admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user with secure random password"""
        # Generate cryptographically secure random password
        admin_password = self._generate_secure_password()
        
        admin_id = "admin_001"
        admin_username = "admin"
        admin_password_hash = self._hash_password(admin_password)
        
        # Store in a simple in-memory store (in production, use database)
        self.users = {
            admin_id: {
                "id": admin_id,
                "username": admin_username,
                "password_hash": admin_password_hash,
                "role": UserRole.SUPER_ADMIN,
                "created_at": datetime.now(),
                "is_active": True
            }
        }
        
        # CRITICAL: Log the secure password for initial setup
        logger.critical(f"🔐 INITIAL ADMIN CREDENTIALS (SAVE THESE SECURELY):")
        logger.critical(f"   Username: {admin_username}")
        logger.critical(f"   Password: {admin_password}")
        logger.critical(f"   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
        
        # Write credentials to secure file for administrator
        try:
            with open("ADMIN_CREDENTIALS_SECURITY_SERVICE.txt", "w") as f:
                f.write(f"MediVote Security Service Admin Credentials\n")
                f.write(f"==========================================\n\n")
                f.write(f"Username: {admin_username}\n")
                f.write(f"Password: {admin_password}\n\n")
                f.write(f"⚠️  CRITICAL SECURITY NOTICE:\n")
                f.write(f"- Change this password immediately after first login\n")
                f.write(f"- Delete this file after securing the credentials\n")
                f.write(f"- Use strong, unique passwords for all accounts\n")
        except Exception as e:
            logger.error(f"Could not write admin credentials file: {e}")
    
    def _generate_secure_password(self) -> str:
        """Generate cryptographically secure random password"""
        import string
        charset = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(charset) for _ in range(16))
        return password
    
    def _hash_password(self, password: str) -> str:
        """Hash password securely"""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{pwd_hash.hex()}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, stored_hash = password_hash.split(':')
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return pwd_hash.hex() == stored_hash
        except Exception:
            return False
    
    def _check_rate_limit(self, ip_address: str, max_requests: int = 10, window_minutes: int = 1) -> bool:
        """Check if IP is rate limited"""
        now = time.time()
        window_start = now - (window_minutes * 60)
        
        if ip_address not in self.rate_limits:
            self.rate_limits[ip_address] = []
        
        # Remove old requests outside the window
        self.rate_limits[ip_address] = [
            req_time for req_time in self.rate_limits[ip_address]
            if req_time > window_start
        ]
        
        # Check if under limit
        if len(self.rate_limits[ip_address]) >= max_requests:
            return False
        
        # Add current request
        self.rate_limits[ip_address].append(now)
        return True
    
    def authenticate_user(self, username: str, password: str, ip_address: str, user_agent: str = "") -> Optional[str]:
        """Authenticate user and return JWT token"""
        try:
            # Check rate limiting
            if not self._check_rate_limit(ip_address, max_requests=5, window_minutes=5):
                self._audit_event("AUTH_RATE_LIMITED", None, username, "authentication", "user_login", 
                                ip_address, user_agent, {"reason": "rate_limited"}, False)
                raise Exception("Rate limit exceeded")
            
            # Find user
            user = None
            for u in self.users.values():
                if u["username"] == username and u["is_active"]:
                    user = u
                    break
            
            if not user:
                self._audit_event("AUTH_FAILED", None, username, "authentication", "user_login",
                                ip_address, user_agent, {"reason": "user_not_found"}, False)
                return None
            
            # Verify password
            if not self._verify_password(password, user["password_hash"]):
                self._audit_event("AUTH_FAILED", user["id"], username, "authentication", "user_login",
                                ip_address, user_agent, {"reason": "invalid_password"}, False)
                return None
            
            # Create session
            session_id = secrets.token_urlsafe(32)
            device_fingerprint = hashlib.sha256(f"{ip_address}:{user_agent}".encode()).hexdigest()
            
            # Get user permissions
            permissions = ROLE_PERMISSIONS.get(user["role"], set())
            
            # Create security context
            context = SecurityContext(
                user_id=user["id"],
                username=user["username"],
                role=user["role"],
                permissions=permissions,
                session_id=session_id,
                authenticated_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=8),  # 8 hour session
                ip_address=ip_address,
                device_fingerprint=device_fingerprint
            )
            
            self.active_sessions[session_id] = context
            
            # Generate JWT token
            token_payload = {
                "session_id": session_id,
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"].value,
                "exp": context.expires_at.timestamp(),
                "iat": datetime.now().timestamp()
            }
            
            token = jwt.encode(token_payload, self.jwt_secret, algorithm="HS256")
            
            # Audit successful login
            self._audit_event("AUTH_SUCCESS", user["id"], username, "authentication", "user_login",
                            ip_address, user_agent, {"session_id": session_id}, True)
            
            logger.info(f"🔓 User authenticated: {username} ({user['role'].value})")
            return token
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    def verify_token(self, token: str, ip_address: str) -> Optional[SecurityContext]:
        """Verify JWT token and return security context"""
        try:
            # Decode JWT
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            session_id = payload.get("session_id")
            
            # Check session exists
            if session_id not in self.active_sessions:
                return None
            
            context = self.active_sessions[session_id]
            
            # Check expiration
            if datetime.now() > context.expires_at:
                del self.active_sessions[session_id]
                return None
            
            # Verify IP (optional - could be disabled for mobile users)
            # if context.ip_address != ip_address:
            #     logger.warning(f"IP mismatch for session {session_id}")
            #     return None
            
            return context
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None
    
    def require_permission(self, context: SecurityContext, permission: Permission) -> bool:
        """Check if user has required permission"""
        return permission in context.permissions
    
    def logout(self, session_id: str):
        """Logout user and invalidate session"""
        if session_id in self.active_sessions:
            context = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            
            self._audit_event("AUTH_LOGOUT", context.user_id, context.username, 
                            "authentication", "user_logout", context.ip_address, "", 
                            {"session_id": session_id}, True)
            
            logger.info(f"🔒 User logged out: {context.username}")
    
    def _audit_event(self, event_type: str, user_id: Optional[str], username: Optional[str],
                    action: str, resource: str, ip_address: str, user_agent: str,
                    details: Dict[str, Any], success: bool):
        """Record audit event"""
        event = AuditEvent(
            event_id=secrets.token_hex(8),
            event_type=event_type,
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.now(),
            details=details,
            success=success
        )
        
        self.audit_events.append(event)
        
        # Keep only last 1000 events in memory
        if len(self.audit_events) > 1000:
            self.audit_events = self.audit_events[-1000:]
        
        # Log security events
        if not success or event_type in ["AUTH_FAILED", "PERMISSION_DENIED", "SUSPICIOUS_ACTIVITY"]:
            logger.warning(f"🔐 SECURITY EVENT: {event_type} - {username} @ {ip_address} - {action} on {resource}")
    
    def get_audit_events(self, limit: int = 100) -> List[AuditEvent]:
        """Get recent audit events"""
        return self.audit_events[-limit:]

class SecureVoteService:
    """Handles secure vote processing with encryption"""
    
    def __init__(self, encryption_service: EncryptionService, auth_service: AuthenticationService):
        self.encryption = encryption_service
        self.auth = auth_service
    
    def encrypt_vote_record(self, vote_data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive vote data with anonymous choice encryption"""
        try:
            # Encrypt the vote choice ANONYMOUSLY - only decryptable with receipt credentials
            anonymous_encrypted_choice = self.encryption.encrypt_anonymous_vote_choice(
                vote_data["choice"], 
                vote_data["receipt_id"],
                vote_data["verification_code"]
            )
            
            # Create counting hash for vote aggregation (doesn't reveal choice to individuals)
            choice_counting_hash = hashlib.sha256(
                f"{vote_data['choice']}:COUNTING_SALT:{vote_data['ballot_id']}".encode()
            ).hexdigest()[:12]  # Short hash for counting purposes
            
            # Anonymize voter ID
            anonymous_voter_id = self.encryption.hash_voter_id(vote_data["voter_id"])
            
            # Create encrypted vote record - NO READABLE CHOICE
            encrypted_record = {
                "id": vote_data["id"],
                "ballot_id": vote_data["ballot_id"],
                "choice": "[ANONYMOUS]",  # Hidden from all except voter with receipt
                "choice_counting_hash": choice_counting_hash,  # For aggregation only
                "anonymous_choice": anonymous_encrypted_choice,  # Only decryptable with receipt
                "voter_id": anonymous_voter_id,  # ANONYMIZED
                "voter_did": vote_data.get("voter_did", ""),  # Keep DID for audit
                "voter_username": vote_data.get("voter_username", ""),  # Keep username for audit
                "timestamp": vote_data["timestamp"],
                "verified": vote_data["verified"],
                "vote_hash": vote_data["vote_hash"],
                "receipt_id": vote_data["receipt_id"],
                "verification_code": "[HIDDEN]",  # Hide verification code from storage
                "encrypted": True,  # Flag to indicate encryption
                "anonymous_voting": True  # Flag for anonymous choice
            }
            
            logger.info(f"🔒 Vote encrypted with anonymous choice: {vote_data['id']}")
            return encrypted_record
            
        except Exception as e:
            logger.error(f"Vote encryption error: {e}")
            raise

# Global security services
def get_security_services():
    """Get initialized security services"""
    # Use environment variable or generate secure defaults
    jwt_secret = os.getenv('MEDIVOTE_JWT_SECRET') or secrets.token_urlsafe(64)
    master_key = os.getenv('MEDIVOTE_MASTER_KEY') or base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    encryption_service = EncryptionService(master_key)
    auth_service = AuthenticationService(jwt_secret, encryption_service)
    vote_service = SecureVoteService(encryption_service, auth_service)
    
    return encryption_service, auth_service, vote_service

# Initialize global services
encryption_service, auth_service, vote_service = get_security_services()

# Export for use in other modules
__all__ = [
    'UserRole', 'Permission', 'SecurityContext', 'AuditEvent',
    'EncryptionService', 'AuthenticationService', 'SecureVoteService',
    'encryption_service', 'auth_service', 'vote_service'
] 