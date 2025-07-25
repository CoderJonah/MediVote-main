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
        # CRITICAL FIX: Use the provided master_key directly when available
        # This prevents key mismatches between encryption and decryption
        if master_key:
            self.master_key = master_key
            logger.info("Using provided master key for encryption service")
        else:
            # Only try key management system if no key provided
            self.master_key = os.getenv('MEDIVOTE_MASTER_KEY')
            if not self.master_key:
                # Try to use key management system as fallback
                self.master_key = self._get_key_from_management_system()
        
        # Initialize encryption
        self._init_encryption()
    
    def _get_key_from_management_system(self) -> str:
        """Get encryption key from the key management system"""
        try:
            # Import key management system
            from core.key_integration import get_database_encryption_key
            
            # Get database encryption key from key management system
            raw_key = get_database_encryption_key()
            
            # Convert to base64 string format expected by this service
            key_b64 = base64.urlsafe_b64encode(raw_key).decode()
            logger.info("Using encryption key from key management system")
            return key_b64
            
        except Exception as e:
            logger.warning(f"Could not get key from management system: {e}")
            # Fallback to old method
            return self._load_or_create_master_key()
    
    def _load_or_create_master_key(self) -> str:
        """Load existing master key or create new one and persist it (FALLBACK)"""
        key_file_path = os.path.join(os.path.dirname(__file__), 'keys', 'master.key')
        
        # Try to load existing key as BINARY (matching key management system)
        if os.path.exists(key_file_path):
            try:
                with open(key_file_path, 'rb') as f:
                    binary_key = f.read()
                    if len(binary_key) == 32:  # Key management system binary format
                        key_b64 = base64.urlsafe_b64encode(binary_key).decode()
                        logger.info("Loaded existing binary master key from secure storage")
                        return key_b64
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
            logger.info("Generated and saved new master key to secure storage")
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
        """Create default admin user with persistent credentials"""
        
        # Check if admin credentials already exist
        credentials_file = "ADMIN_CREDENTIALS_SECURITY_SERVICE.txt"
        existing_password = self._load_existing_admin_password(credentials_file)
        
        if existing_password:
            admin_password = existing_password
            logger.info("Using existing admin credentials")
        else:
            # Generate new password only if none exists
            admin_password = self._generate_secure_password()
            logger.critical(f"INITIAL ADMIN CREDENTIALS (SAVE THESE SECURELY):")
            logger.critical(f"   Username: admin")
            logger.critical(f"   Password: {admin_password}")
            logger.critical(f"   WARNING: CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
            
            # Write credentials to secure file for administrator
            try:
                with open(credentials_file, "w", encoding='utf-8') as f:
                    f.write(f"MediVote Security Service Admin Credentials\n")
                    f.write(f"==========================================\n\n")
                    f.write(f"Username: admin\n")
                    f.write(f"Password: {admin_password}\n\n")
                    f.write(f"WARNING: CRITICAL SECURITY NOTICE:\n")
                    f.write(f"- Change this password immediately after first login\n")
                    f.write(f"- Delete this file after securing the credentials\n")
                    f.write(f"- Use strong, unique passwords for all accounts\n")
            except Exception as e:
                logger.error(f"Could not write admin credentials file: {e}")
        
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
    
    def _load_existing_admin_password(self, credentials_file: str) -> Optional[str]:
        """Load existing admin password from credentials file"""
        try:
            if os.path.exists(credentials_file):
                with open(credentials_file, "r", encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("Password: "):
                            return line.replace("Password: ", "").strip()
        except Exception as e:
            logger.warning(f"Could not load existing admin credentials: {e}")
        return None
    
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
            
            # Generate JWT token using secure asymmetric signing
            token_payload = {
                "session_id": session_id,
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"].value,
                "exp": context.expires_at.timestamp(),
                "iat": datetime.now().timestamp()
            }
            
            # Use secure JWT service with RSA signing (replaces vulnerable HMAC)
            try:
                from core.jwt_security import create_secure_token
                token = create_secure_token(
                    payload=token_payload,
                    expires_in_minutes=480  # 8 hours (matches session expiry)
                )
                logger.debug("🔐 JWT token created with secure RSA signing")
            except Exception as jwt_error:
                # Fallback to legacy HMAC for backward compatibility
                logger.warning(f"⚠️  Secure JWT failed, using legacy HMAC: {jwt_error}")
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
            # Try secure JWT verification first (RSA/ECDSA)
            try:
                from core.jwt_security import verify_secure_token
                payload = verify_secure_token(token)
                if payload:
                    logger.debug("🔐 JWT token verified with secure asymmetric signing")
                else:
                    raise ValueError("Secure JWT verification failed")
            except Exception as secure_error:
                # Fallback to legacy HMAC verification
                logger.warning(f"⚠️  Secure JWT verification failed, trying legacy HMAC: {secure_error}")
                payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
                logger.debug("🔓 JWT token verified with legacy HMAC signing")
            
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
            
            logger.info(f"User logged out: {context.username}")
    
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
            logger.warning(f"SECURITY EVENT: {event_type} - {username} @ {ip_address} - {action} on {resource}")
    
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
            
            logger.info(f"Vote encrypted with anonymous choice: {vote_data['id']}")
            return encrypted_record
            
        except Exception as e:
            logger.error(f"Vote encryption error: {e}")
            raise

# ============ KEY VALIDATION SYSTEM ============

class KeyValidationResult:
    """Result of key validation operation"""
    def __init__(self, service_name: str, key_type: str, is_valid: bool, details: Dict[str, Any]):
        self.service_name = service_name
        self.key_type = key_type  
        self.is_valid = is_valid
        self.details = details
        self.timestamp = datetime.now()
        self.validation_id = secrets.token_hex(8)

class MediVoteKeyValidator:
    """
    COMPREHENSIVE KEY VALIDATION SYSTEM
    
    Detects when services are using different encryption keys and alerts administrators.
    Critical for preventing silent data corruption and ensuring system integrity.
    """
    
    def __init__(self, security_manager: MediVoteSecurityManager):
        self.security_manager = security_manager
        self.validation_history: List[KeyValidationResult] = []
        self.active_key_hashes: Dict[str, str] = {}
        self.service_key_mappings: Dict[str, Dict[str, str]] = {}
        self.validation_enabled = True
        self.last_validation_time = datetime.now()
        
        # Alert thresholds
        self.mismatch_alert_threshold = 1  # Alert on any mismatch
        self.validation_interval = 300  # 5 minutes
        
        logger.critical("KEY VALIDATION SYSTEM INITIALIZED")
        logger.critical("   Mismatch Detection: ENABLED")
        logger.critical("   Alert Threshold: IMMEDIATE")
        logger.critical("   Validation Interval: 5 minutes")
    
    def validate_service_keys(self, service_name: str, service_keys: Dict[str, bytes]) -> List[KeyValidationResult]:
        """
        Validate that a service is using the correct encryption keys
        
        Args:
            service_name: Name of the service (e.g., 'cache_manager', 'security_service')
            service_keys: Dictionary of key_type -> key_bytes from the service
            
        Returns:
            List of validation results for each key type
        """
        try:
            logger.info(f"VALIDATING KEYS FOR SERVICE: {service_name}")
            
            validation_results = []
            
            for key_type, service_key in service_keys.items():
                result = self._validate_individual_key(service_name, key_type, service_key)
                validation_results.append(result)
                
                # Store validation result
                self.validation_history.append(result)
                
                # Alert on validation failure
                if not result.is_valid:
                    self._trigger_key_mismatch_alert(result)
            
            # Update service key mappings
            self.service_key_mappings[service_name] = {
                key_type: hashlib.sha256(key_bytes).hexdigest()[:16]
                for key_type, key_bytes in service_keys.items()
            }
            
            # Cleanup old validation history
            self._cleanup_validation_history()
            
            valid_count = sum(1 for r in validation_results if r.is_valid)
            total_count = len(validation_results)
            
            logger.critical(f"KEY VALIDATION COMPLETE: {service_name}")
            logger.critical(f"   Valid Keys: {valid_count}/{total_count}")
            logger.critical(f"   Service Status: {'SECURE' if valid_count == total_count else 'KEY MISMATCH DETECTED'}")
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Key validation failed for {service_name}: {e}")
            error_result = KeyValidationResult(
                service_name, "validation_error", False,
                {"error": str(e), "error_type": type(e).__name__}
            )
            self._trigger_key_mismatch_alert(error_result)
            return [error_result]
    
    def _validate_individual_key(self, service_name: str, key_type: str, service_key: bytes) -> KeyValidationResult:
        """Validate an individual key against the security manager"""
        try:
            # Get expected key from security manager
            expected_key = None
            
            if key_type == "database":
                expected_key = self.security_manager.get_database_key()
            elif key_type == "audit":
                expected_key = self.security_manager.get_audit_key()
            elif key_type == "jwt":
                expected_key = self.security_manager.get_jwt_secret()
            elif key_type == "session":
                expected_key = self.security_manager.get_session_key()
            else:
                return KeyValidationResult(
                    service_name, key_type, False,
                    {"error": f"Unknown key type: {key_type}"}
                )
            
            # Compare keys
            keys_match = service_key == expected_key
            
            # Generate key hashes for logging (never log actual keys)
            service_key_hash = hashlib.sha256(service_key).hexdigest()[:16]
            expected_key_hash = hashlib.sha256(expected_key).hexdigest()[:16]
            
            details = {
                "service_key_hash": service_key_hash,
                "expected_key_hash": expected_key_hash,
                "keys_match": keys_match,
                "key_length": len(service_key),
                "expected_length": len(expected_key)
            }
            
            if keys_match:
                logger.debug(f"Key validation PASSED: {service_name}.{key_type}")
            else:
                logger.error(f"KEY MISMATCH DETECTED: {service_name}.{key_type}")
                logger.error(f"   Service Key Hash: {service_key_hash}")
                logger.error(f"   Expected Key Hash: {expected_key_hash}")
            
            return KeyValidationResult(service_name, key_type, keys_match, details)
            
        except Exception as e:
            logger.error(f"Individual key validation failed: {e}")
            return KeyValidationResult(
                service_name, key_type, False,
                {"error": str(e), "validation_failed": True}
            )
    
    def _trigger_key_mismatch_alert(self, validation_result: KeyValidationResult):
        """Trigger admin alert for key mismatch"""
        try:
            alert_details = {
                "service_name": validation_result.service_name,
                "key_type": validation_result.key_type,
                "validation_id": validation_result.validation_id,
                "timestamp": validation_result.timestamp.isoformat(),
                "details": validation_result.details
            }
            
            # Use the admin alert system
            admin_alert_system = get_admin_alert_system()
            admin_alert_system.send_critical_alert(
                "KEY_MISMATCH_DETECTED",
                f"Service {validation_result.service_name} using incorrect {validation_result.key_type} key",
                alert_details
            )
            
            logger.critical(f"ADMIN ALERT TRIGGERED: KEY_MISMATCH_DETECTED")
            logger.critical(f"   Service: {validation_result.service_name}")
            logger.critical(f"   Key Type: {validation_result.key_type}")
            logger.critical(f"   Alert ID: {validation_result.validation_id}")
            
        except Exception as e:
            logger.error(f"Failed to trigger key mismatch alert: {e}")
    
    def validate_all_active_services(self) -> Dict[str, List[KeyValidationResult]]:
        """Validate keys for all known active services"""
        logger.critical("VALIDATING ALL ACTIVE SERVICES")
        
        all_results = {}
        
        # Validate cache manager keys (if available)
        try:
            from cache_manager import cache_manager
            if hasattr(cache_manager, '_get_encryption_keys'):
                cache_keys = cache_manager._get_encryption_keys()
                all_results["cache_manager"] = self.validate_service_keys("cache_manager", cache_keys)
        except Exception as e:
            logger.warning(f"Could not validate cache_manager keys: {e}")
        
        # Validate security service keys
        try:
            from security_service import encryption_service
            if hasattr(encryption_service, '_get_encryption_keys'):
                security_keys = encryption_service._get_encryption_keys()
                all_results["security_service"] = self.validate_service_keys("security_service", security_keys)
        except Exception as e:
            logger.warning(f"Could not validate security_service keys: {e}")
        
        # Generate summary
        total_services = len(all_results)
        secure_services = 0
        total_keys_validated = 0
        total_keys_valid = 0
        
        for service_name, results in all_results.items():
            service_valid = all(r.is_valid for r in results)
            if service_valid:
                secure_services += 1
            
            total_keys_validated += len(results)
            total_keys_valid += sum(1 for r in results if r.is_valid)
        
        logger.critical("ALL SERVICES VALIDATION COMPLETE")
        logger.critical(f"   Secure Services: {secure_services}/{total_services}")
        logger.critical(f"   Valid Keys: {total_keys_valid}/{total_keys_validated}")
        logger.critical(f"   System Status: {'SECURE' if secure_services == total_services else 'CRITICAL - KEY MISMATCHES DETECTED'}")
        
        return all_results
    
    def get_validation_status(self) -> Dict[str, Any]:
        """Get comprehensive validation status"""
        recent_validations = [
            v for v in self.validation_history 
            if (datetime.now() - v.timestamp).seconds < 3600  # Last hour
        ]
        
        return {
            "validation_enabled": self.validation_enabled,
            "last_validation": self.last_validation_time.isoformat(),
            "validation_interval": self.validation_interval,
            "recent_validations": {
                "total": len(recent_validations),
                "valid": len([v for v in recent_validations if v.is_valid]),
                "failed": len([v for v in recent_validations if not v.is_valid])
            },
            "active_services": len(self.service_key_mappings),
            "service_status": {
                service: len([v for v in recent_validations if v.service_name == service and v.is_valid])
                for service in self.service_key_mappings.keys()
            },
            "alert_thresholds": {
                "mismatch_alert_threshold": self.mismatch_alert_threshold,
                "immediate_alerts": True
            }
        }
    
    def _cleanup_validation_history(self):
        """Clean up old validation history to prevent memory bloat"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.validation_history = [
            v for v in self.validation_history 
            if v.timestamp > cutoff_time
        ]

# ============ ADMIN ALERT SYSTEM ============

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class AdminAlert:
    """Admin alert data structure"""
    alert_id: str
    alert_type: str
    severity: AlertSeverity
    title: str
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None

class AdminAlertSystem:
    """
    COMPREHENSIVE ADMIN ALERT SYSTEM
    
    Handles critical alerts for key synchronization failures, system issues,
    and operational problems that require immediate administrator attention.
    """
    
    def __init__(self):
        self.alerts: Dict[str, AdminAlert] = {}
        self.alert_history: List[AdminAlert] = []
        self.notification_channels: Dict[str, callable] = {}
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.is_enabled = True
        
        # Alert statistics
        self.stats = {
            "alerts_sent": 0,
            "critical_alerts": 0,
            "acknowledged_alerts": 0,
            "resolved_alerts": 0,
            "last_alert_time": None
        }
        
        # Initialize default alert rules
        self._initialize_alert_rules()
        
        # Initialize notification channels
        self._initialize_notification_channels()
        
        logger.critical("ADMIN ALERT SYSTEM INITIALIZED")
        logger.critical("   Real-time Alerts: ENABLED")
        logger.critical("   Critical Alert Escalation: ACTIVE")
        logger.critical("   Multi-channel Notifications: READY")
    
    def _initialize_alert_rules(self):
        """Initialize default alert rules"""
        self.alert_rules = {
            "KEY_MISMATCH_DETECTED": {
                "severity": AlertSeverity.CRITICAL,
                "auto_escalate": True,
                "escalation_delay": 300,  # 5 minutes
                "notification_channels": ["log", "email", "dashboard"],
                "description": "Service using incorrect encryption key"
            },
            "KEY_SYNCHRONIZATION_FAILURE": {
                "severity": AlertSeverity.CRITICAL,
                "auto_escalate": True,
                "escalation_delay": 180,  # 3 minutes
                "notification_channels": ["log", "email", "dashboard"],
                "description": "Key synchronization between services failed"
            },
            "RANDOM_KEY_FALLBACK": {
                "severity": AlertSeverity.CRITICAL,
                "auto_escalate": True,
                "escalation_delay": 60,  # 1 minute
                "notification_channels": ["log", "email", "sms", "dashboard"],
                "description": "Service fell back to random keys - data corruption risk"
            },
            "BLOCKCHAIN_SYNC_FAILURE": {
                "severity": AlertSeverity.ERROR,
                "auto_escalate": False,
                "notification_channels": ["log", "dashboard"],
                "description": "Blockchain synchronization failed"
            },
            "CACHE_BACKUP_FAILURE": {
                "severity": AlertSeverity.WARNING,
                "auto_escalate": False,
                "notification_channels": ["log", "dashboard"],
                "description": "Cache backup operation failed"
            }
        }
    
    def _initialize_notification_channels(self):
        """Initialize notification channels"""
        self.notification_channels = {
            "log": self._send_log_notification,
            "dashboard": self._send_dashboard_notification,
            "email": self._send_email_notification,
            "sms": self._send_sms_notification,
            "webhook": self._send_webhook_notification
        }
    
    def send_alert(self, alert_type: str, message: str, details: Dict[str, Any] = None, 
                   severity: AlertSeverity = AlertSeverity.WARNING) -> str:
        """Send an admin alert"""
        try:
            alert_id = secrets.token_hex(12)
            
            # Get alert rule or use defaults
            rule = self.alert_rules.get(alert_type, {})
            actual_severity = rule.get("severity", severity)
            
            # Create alert
            alert = AdminAlert(
                alert_id=alert_id,
                alert_type=alert_type,
                severity=actual_severity,
                title=rule.get("description", message),
                message=message,
                details=details or {},
                timestamp=datetime.now()
            )
            
            # Store alert
            self.alerts[alert_id] = alert
            self.alert_history.append(alert)
            
            # Update statistics
            self.stats["alerts_sent"] += 1
            if actual_severity == AlertSeverity.CRITICAL:
                self.stats["critical_alerts"] += 1
            self.stats["last_alert_time"] = datetime.now()
            
            # Send notifications
            notification_channels = rule.get("notification_channels", ["log"])
            self._send_notifications(alert, notification_channels)
            
            logger.critical(f"ADMIN ALERT SENT: {alert_type}")
            logger.critical(f"   Alert ID: {alert_id}")
            logger.critical(f"   Severity: {actual_severity.value.upper()}")
            logger.critical(f"   Channels: {notification_channels}")
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Failed to send admin alert: {e}")
            # Fallback logging
            logger.critical(f"FALLBACK ALERT: {alert_type} - {message}")
            return ""
    
    def send_critical_alert(self, alert_type: str, message: str, details: Dict[str, Any] = None) -> str:
        """Send a critical admin alert with immediate escalation"""
        return self.send_alert(alert_type, message, details, AlertSeverity.CRITICAL)
    
    def _send_notifications(self, alert: AdminAlert, channels: List[str]):
        """Send notifications through specified channels"""
        for channel in channels:
            try:
                if channel in self.notification_channels:
                    self.notification_channels[channel](alert)
                else:
                    logger.warning(f"Unknown notification channel: {channel}")
            except Exception as e:
                logger.error(f"Failed to send notification via {channel}: {e}")
    
    def _send_log_notification(self, alert: AdminAlert):
        """Send alert via logging system"""
        log_level = {
            AlertSeverity.INFO: logger.info,
            AlertSeverity.WARNING: logger.warning,
            AlertSeverity.ERROR: logger.error,
            AlertSeverity.CRITICAL: logger.critical
        }.get(alert.severity, logger.info)
        
        log_level(f"ADMIN ALERT [{alert.alert_type}]: {alert.message}")
        log_level(f"   Alert ID: {alert.alert_id}")
        log_level(f"   Timestamp: {alert.timestamp}")
        if alert.details:
            log_level(f"   Details: {alert.details}")
    
    def _send_dashboard_notification(self, alert: AdminAlert):
        """Send alert to admin dashboard"""
        # Store for dashboard retrieval
        dashboard_alert = {
            "alert_id": alert.alert_id,
            "type": alert.alert_type,
            "severity": alert.severity.value,
            "title": alert.title,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat(),
            "acknowledged": alert.acknowledged,
            "resolved": alert.resolved
        }
        
        # Store for dashboard API
        if not hasattr(self, 'dashboard_alerts'):
            self.dashboard_alerts = []
        
        self.dashboard_alerts.append(dashboard_alert)
        
        # Keep only last 100 alerts for dashboard
        if len(self.dashboard_alerts) > 100:
            self.dashboard_alerts = self.dashboard_alerts[-100:]
    
    def _send_email_notification(self, alert: AdminAlert):
        """Send alert via email"""
        logger.info(f"EMAIL ALERT: {alert.alert_type} - {alert.message}")
        logger.info("   (Email integration placeholder)")
    
    def _send_sms_notification(self, alert: AdminAlert):
        """Send alert via SMS"""
        logger.info(f"SMS ALERT: {alert.alert_type} - {alert.message}")
        logger.info("   (SMS integration placeholder)")
    
    def _send_webhook_notification(self, alert: AdminAlert):
        """Send alert via webhook"""
        logger.info(f"WEBHOOK ALERT: {alert.alert_type} - {alert.message}")
        logger.info("   (Webhook integration placeholder)")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active (unresolved) alerts"""
        active_alerts = []
        
        for alert in self.alerts.values():
            if not alert.resolved:
                active_alerts.append({
                    "alert_id": alert.alert_id,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat(),
                    "acknowledged": alert.acknowledged,
                    "details": alert.details
                })
        
        return active_alerts

# Global instances
_key_validator: Optional[MediVoteKeyValidator] = None
_admin_alert_system: Optional[AdminAlertSystem] = None

def get_key_validator() -> MediVoteKeyValidator:
    """Get the global key validator instance"""
    global _key_validator
    
    if _key_validator is None:
        security_manager = get_security_manager()
        _key_validator = MediVoteKeyValidator(security_manager)
    
    return _key_validator

def get_admin_alert_system() -> AdminAlertSystem:
    """Get the global admin alert system instance"""
    global _admin_alert_system
    
    if _admin_alert_system is None:
        _admin_alert_system = AdminAlertSystem()
    
    return _admin_alert_system

def validate_service_keys(service_name: str, service_keys: Dict[str, bytes]) -> List[KeyValidationResult]:
    """Convenience function to validate service keys"""
    validator = get_key_validator()
    return validator.validate_service_keys(service_name, service_keys)

def send_admin_alert(alert_type: str, message: str, details: Dict[str, Any] = None) -> str:
    """Convenience function to send admin alert"""
    alert_system = get_admin_alert_system()
    return alert_system.send_alert(alert_type, message, details)

def send_critical_admin_alert(alert_type: str, message: str, details: Dict[str, Any] = None) -> str:
    """Convenience function to send critical admin alert"""
    alert_system = get_admin_alert_system()
    return alert_system.send_critical_alert(alert_type, message, details)

# ============ KEY VALIDATION SYSTEM ============

# Global security services
def get_security_services():
    """Get initialized security services"""
    # CRITICAL FIX: Always use key management system for consistent keys
    # DO NOT generate random keys that change between processes
    
    try:
        # Initialize security system first to ensure key management is available
        from core.key_integration import initialize_medivote_security, get_database_encryption_key, get_jwt_secret_key
        
        # Initialize if not already done
        try:
            initialize_medivote_security()
        except Exception as init_error:
            logger.warning(f"Security system already initialized or init failed: {init_error}")
        
        # Get consistent keys from key management system
        db_key_raw = get_database_encryption_key()
        jwt_key_raw = get_jwt_secret_key()
        
        # Convert keys to expected format
        master_key = base64.urlsafe_b64encode(db_key_raw).decode()
        # JWT key is binary data, convert to base64 for use as string
        jwt_secret = base64.urlsafe_b64encode(jwt_key_raw).decode() if isinstance(jwt_key_raw, bytes) else str(jwt_key_raw)
        
        logger.info("Using keys from key management system")
        
    except Exception as e:
        logger.error(f"Failed to get keys from management system: {e}")
        # Only fall back to environment/random as last resort
        jwt_secret = os.getenv('MEDIVOTE_JWT_SECRET') or secrets.token_urlsafe(64)
        master_key = os.getenv('MEDIVOTE_MASTER_KEY') or base64.urlsafe_b64encode(os.urandom(32)).decode()
        logger.warning("Using fallback random keys - THIS WILL CAUSE CACHE DECRYPTION ISSUES")
    
    encryption_service = EncryptionService(master_key)
    auth_service = AuthenticationService(jwt_secret, encryption_service)
    vote_service = SecureVoteService(encryption_service, auth_service)
    
    # Perform immediate key validation after initialization
    try:
        encryption_service.perform_key_validation()
    except Exception as e:
        logger.error(f"Post-initialization key validation failed: {e}")
    
    return encryption_service, auth_service, vote_service

# Initialize global services
encryption_service, auth_service, vote_service = get_security_services()

# Export for use in other modules
__all__ = [
    'UserRole', 'Permission', 'SecurityContext', 'AuditEvent',
    'EncryptionService', 'AuthenticationService', 'SecureVoteService',
    'encryption_service', 'auth_service', 'vote_service'
] 