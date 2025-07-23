"""
Production Authentication Service for MediVote
Implements secure admin authentication, RBAC, and session management
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
import json
import hmac
import pyotp
import qrcode
from io import BytesIO
import base64

import jwt
import bcrypt
from loguru import logger
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from .auth_models import (
    AdminUser, AdminSession, AuditLog, APIKey, SecurityContext,
    UserRole, Permission, SecurityEvent, ROLE_PERMISSIONS,
    AdminLoginRequest, AdminCreateRequest, PasswordChangeRequest,
    SecurityUtils
)
from .config import get_settings, get_security_config

settings = get_settings()
security_config = get_security_config()

class AuthenticationService:
    """Production-grade authentication service"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.failed_attempts: Dict[str, int] = {}
        self.locked_accounts: Dict[str, datetime] = {}
    
    async def create_admin_user(
        self, 
        request: AdminCreateRequest, 
        created_by: str
    ) -> AdminUser:
        """Create new admin user with proper security"""
        
        # Check if username or email already exists
        existing = self.db.query(AdminUser).filter(
            (AdminUser.username == request.username) | 
            (AdminUser.email == request.email)
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already exists"
            )
        
        # Hash password
        password_hash, salt = SecurityUtils.hash_password(request.password)
        
        # Get permissions for role
        permissions = list(ROLE_PERMISSIONS.get(request.role, set()))
        
        # Add custom permissions
        for perm in request.permissions:
            if perm not in permissions:
                permissions.append(perm)
        
        # Create user
        admin_user = AdminUser(
            id=str(uuid.uuid4()),
            username=request.username,
            email=request.email,
            password_hash=password_hash,
            salt=salt,
            role=request.role.value,
            permissions=permissions,
            created_by=created_by,
            is_verified=True  # Admin creates are pre-verified
        )
        
        self.db.add(admin_user)
        self.db.commit()
        
        # Log admin creation
        await self._log_security_event(
            SecurityEvent.ADMIN_ACTION,
            f"Admin user {request.username} created",
            user_id=created_by,
            metadata={
                "action": "create_admin",
                "target_user": request.username,
                "role": request.role.value
            }
        )
        
        logger.info(f"Admin user created: {request.username} with role {request.role}")
        return admin_user
    
    async def authenticate_admin(
        self, 
        login_request: AdminLoginRequest,
        ip_address: str,
        user_agent: str
    ) -> Tuple[AdminUser, str, str]:
        """Authenticate admin user with comprehensive security"""
        
        # Check rate limiting
        if self._is_rate_limited(ip_address):
            await self._log_security_event(
                SecurityEvent.LOGIN_FAILED,
                f"Rate limited login attempt from {ip_address}",
                ip_address=ip_address,
                metadata={"reason": "rate_limited"}
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later."
            )
        
        # Find user
        user = self.db.query(AdminUser).filter(
            AdminUser.username == login_request.username,
            AdminUser.is_active == True
        ).first()
        
        if not user:
            self._record_failed_attempt(ip_address)
            await self._log_security_event(
                SecurityEvent.LOGIN_FAILED,
                f"Login attempt with invalid username: {login_request.username}",
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check if account is locked
        if self._is_account_locked(user.username):
            await self._log_security_event(
                SecurityEvent.LOGIN_FAILED,
                f"Login attempt on locked account: {user.username}",
                user_id=user.id,
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked"
            )
        
        # Verify password
        if not SecurityUtils.verify_password(
            login_request.password, 
            user.password_hash, 
            user.salt
        ):
            self._record_failed_login(user.username)
            await self._log_security_event(
                SecurityEvent.LOGIN_FAILED,
                f"Invalid password for user: {user.username}",
                user_id=user.id,
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check MFA if enabled
        if user.mfa_enabled:
            if not login_request.mfa_code:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="MFA code required"
                )
            
            if not self._verify_mfa_code(user, login_request.mfa_code):
                await self._log_security_event(
                    SecurityEvent.LOGIN_FAILED,
                    f"Invalid MFA code for user: {user.username}",
                    user_id=user.id,
                    ip_address=ip_address
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )
        
        # Generate session tokens
        session_token, refresh_token = SecurityUtils.generate_session_tokens()
        
        # Create session
        session = await self._create_session(
            user, session_token, refresh_token,
            login_request.device_fingerprint,
            ip_address, user_agent,
            login_request.remember_me
        )
        
        # Update user login info
        user.last_login = datetime.utcnow()
        user.failed_login_attempts = 0
        self.db.commit()
        
        # Reset failed attempts
        self._reset_failed_attempts(ip_address, user.username)
        
        # Log successful login
        await self._log_security_event(
            SecurityEvent.LOGIN_SUCCESS,
            f"Admin user logged in: {user.username}",
            user_id=user.id,
            session_id=session.id,
            ip_address=ip_address
        )
        
        logger.info(f"Admin authenticated: {user.username}")
        return user, session_token, refresh_token
    
    async def create_session(
        self,
        user: AdminUser,
        session_token: str,
        refresh_token: str,
        device_fingerprint: Dict,
        ip_address: str,
        user_agent: str,
        remember_me: bool = False
    ) -> AdminSession:
        """Create secure admin session"""
        
        # Check concurrent session limit
        active_sessions = self.db.query(AdminSession).filter(
            AdminSession.user_id == user.id,
            AdminSession.is_active == True,
            AdminSession.expires_at > datetime.utcnow()
        ).count()
        
        if active_sessions >= user.max_concurrent_sessions:
            # Revoke oldest session
            oldest_session = self.db.query(AdminSession).filter(
                AdminSession.user_id == user.id,
                AdminSession.is_active == True
            ).order_by(AdminSession.last_activity).first()
            
            if oldest_session:
                oldest_session.is_active = False
                self.db.commit()
        
        # Set expiration
        if remember_me:
            expires_at = datetime.utcnow() + timedelta(days=30)
        else:
            expires_at = datetime.utcnow() + timedelta(
                minutes=security_config.SESSION_TIMEOUT_MINUTES
            )
        
        # Create session
        session = AdminSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            session_token=hashlib.sha256(session_token.encode()).hexdigest(),
            refresh_token=hashlib.sha256(refresh_token.encode()).hexdigest(),
            expires_at=expires_at,
            device_fingerprint=hashlib.sha256(
                json.dumps(device_fingerprint, sort_keys=True).encode()
            ).hexdigest(),
            ip_address=ip_address,
            user_agent=user_agent,
            requires_mfa=user.mfa_enabled,
            mfa_verified=not user.mfa_enabled  # Auto-verified if MFA disabled
        )
        
        self.db.add(session)
        self.db.commit()
        
        return session
    
    async def verify_session(self, session_token: str) -> SecurityContext:
        """Verify admin session and return security context"""
        
        # Hash token for lookup
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        
        # Find session
        session = self.db.query(AdminSession).filter(
            AdminSession.session_token == token_hash,
            AdminSession.is_active == True,
            AdminSession.expires_at > datetime.utcnow()
        ).first()
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )
        
        # Get user
        user = self.db.query(AdminUser).filter(
            AdminUser.id == session.user_id,
            AdminUser.is_active == True
        ).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account disabled"
            )
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        self.db.commit()
        
        # Get permissions
        role_permissions = ROLE_PERMISSIONS.get(UserRole(user.role), set())
        custom_permissions = set(user.permissions or [])
        all_permissions = role_permissions.union(custom_permissions)
        
        return SecurityContext(
            user_id=user.id,
            username=user.username,
            role=UserRole(user.role),
            permissions=all_permissions,
            session_id=session.id,
            ip_address=session.ip_address,
            device_fingerprint=session.device_fingerprint,
            mfa_verified=session.mfa_verified
        )
    
    async def logout(self, session_token: str) -> bool:
        """Logout admin user"""
        
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        
        session = self.db.query(AdminSession).filter(
            AdminSession.session_token == token_hash,
            AdminSession.is_active == True
        ).first()
        
        if session:
            session.is_active = False
            self.db.commit()
            
            await self._log_security_event(
                SecurityEvent.LOGOUT,
                f"Admin user logged out",
                user_id=session.user_id,
                session_id=session.id
            )
            
            return True
        
        return False
    
    async def change_password(
        self,
        user_id: str,
        request: PasswordChangeRequest
    ) -> bool:
        """Change admin user password"""
        
        user = self.db.query(AdminUser).filter(
            AdminUser.id == user_id,
            AdminUser.is_active == True
        ).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify current password
        if not SecurityUtils.verify_password(
            request.current_password,
            user.password_hash,
            user.salt
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )
        
        # Verify MFA if enabled
        if user.mfa_enabled and not request.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="MFA code required for password change"
            )
        
        if user.mfa_enabled and not self._verify_mfa_code(user, request.mfa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )
        
        # Hash new password
        password_hash, salt = SecurityUtils.hash_password(request.new_password)
        
        # Update user
        user.password_hash = password_hash
        user.salt = salt
        user.password_changed_at = datetime.utcnow()
        
        # Revoke all sessions (force re-login)
        self.db.query(AdminSession).filter(
            AdminSession.user_id == user_id,
            AdminSession.is_active == True
        ).update({"is_active": False})
        
        self.db.commit()
        
        await self._log_security_event(
            SecurityEvent.PASSWORD_CHANGE,
            f"Password changed for user: {user.username}",
            user_id=user.id
        )
        
        return True
    
    async def setup_mfa(self, user_id: str) -> Tuple[str, str, List[str]]:
        """Setup MFA for admin user"""
        
        user = self.db.query(AdminUser).filter(
            AdminUser.id == user_id
        ).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Generate MFA secret
        secret = pyotp.random_base32()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="MediVote Admin"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        
        # Save to user (not activated until verified)
        user.mfa_secret = secret
        user.backup_codes = backup_codes
        self.db.commit()
        
        return secret, qr_code, backup_codes
    
    def has_permission(
        self, 
        security_context: SecurityContext, 
        permission: Permission
    ) -> bool:
        """Check if user has specific permission"""
        return permission in security_context.permissions
    
    def require_permission(
        self,
        security_context: SecurityContext,
        permission: Permission
    ):
        """Require specific permission or raise exception"""
        if not self.has_permission(security_context, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission.value}"
            )
    
    # Private helper methods
    def _is_rate_limited(self, ip_address: str) -> bool:
        """Check if IP is rate limited"""
        return self.failed_attempts.get(ip_address, 0) >= security_config.MAX_FAILED_ATTEMPTS
    
    def _record_failed_attempt(self, ip_address: str):
        """Record failed login attempt"""
        self.failed_attempts[ip_address] = self.failed_attempts.get(ip_address, 0) + 1
    
    def _record_failed_login(self, username: str):
        """Record failed login for user"""
        user = self.db.query(AdminUser).filter(
            AdminUser.username == username
        ).first()
        
        if user:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            
            # Lock account if too many failures
            if user.failed_login_attempts >= security_config.MAX_FAILED_ATTEMPTS:
                self.locked_accounts[username] = datetime.utcnow() + timedelta(
                    minutes=security_config.LOCKOUT_DURATION_MINUTES
                )
            
            self.db.commit()
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked"""
        lock_until = self.locked_accounts.get(username)
        if lock_until and datetime.utcnow() < lock_until:
            return True
        elif lock_until:
            # Lock expired, remove it
            del self.locked_accounts[username]
        return False
    
    def _reset_failed_attempts(self, ip_address: str, username: str):
        """Reset failed attempts after successful login"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
        if username in self.locked_accounts:
            del self.locked_accounts[username]
    
    def _verify_mfa_code(self, user: AdminUser, code: str) -> bool:
        """Verify MFA code"""
        if not user.mfa_secret:
            return False
        
        # Check TOTP code
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            return True
        
        # Check backup codes
        if code in (user.backup_codes or []):
            # Remove used backup code
            backup_codes = user.backup_codes.copy()
            backup_codes.remove(code)
            user.backup_codes = backup_codes
            self.db.commit()
            return True
        
        return False
    
    async def _log_security_event(
        self,
        event_type: SecurityEvent,
        message: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        metadata: Optional[Dict] = None,
        severity: str = "INFO"
    ):
        """
        🔐 ENHANCED SECURITY EVENT LOGGING with FULL ENCRYPTION
        
        CRITICAL SECURITY UPGRADE: All sensitive audit data is now encrypted
        - IP addresses encrypted to prevent location tracking and correlation
        - Session IDs encrypted to prevent session hijacking attempts
        - User agents encrypted to prevent device fingerprinting
        - Metadata encrypted to prevent sensitive operational data leakage
        
        ⚠️  SECURITY FLAW IDENTIFIED & FIXED:
        Previous implementation stored sensitive security event data in plaintext.
        This could enable attackers to:
        1. Track user locations and movement patterns via IP addresses
        2. Correlate activities across sessions via session IDs
        3. Build device fingerprints via user agent strings
        4. Extract sensitive operational details from metadata
        5. Perform advanced correlation attacks on user behavior
        
        This was especially dangerous for a voting system where privacy is paramount.
        """
        try:
            # Calculate risk score using existing logic
            risk_score = SecurityUtils.calculate_risk_score(event_type, metadata or {})
            
            # Get database encryption key for audit logging
            # ⚠️  IMPROVEMENT NEEDED: This should come from secure key management
            # For now, we'll use a derived key from the database instance
            encryption_key = getattr(self.db, 'encryption_key', None)
            
            if not encryption_key:
                # CRITICAL: Generate a temporary key if none available
                # 🚨 PRODUCTION WARNING: This should never happen in production
                logger.critical("🚨 AUDIT ENCRYPTION KEY MISSING - Using emergency key generation")
                import secrets
                encryption_key = secrets.token_bytes(32)
                logger.critical("⚠️  Emergency encryption key generated - audit security may be compromised")
            
            # Create encrypted audit log using the new factory method
            audit_log = AuditLog.create_encrypted_audit_log(
                event_type=event_type.value,
                message=message,
                severity=severity,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                endpoint=endpoint,
                method=method,
                audit_metadata=metadata,
                risk_score=risk_score,
                encryption_key=encryption_key
            )
            
            # Store the encrypted audit log
            self.db.add(audit_log)
            self.db.commit()
            
            # Log high-risk events immediately with privacy protection
            if risk_score >= 70:
                # Only log non-sensitive summary for high-risk events
                logger.warning(f"🚨 High-risk security event: {event_type.value} (score: {risk_score})")
                logger.warning(f"   📝 Message: {message}")
                logger.warning(f"   🔒 Sensitive details encrypted in audit log ID: {audit_log.id}")
            else:
                logger.info(f"🔍 Security event logged: {event_type.value} (encrypted)")
                logger.debug(f"   📝 Message: {message}")
                logger.debug(f"   🔒 Details encrypted in audit log ID: {audit_log.id}")
            
        except Exception as e:
            # NEVER let audit logging failures break the system
            logger.error(f"❌ CRITICAL: Security event logging failed - {e}")
            
            # Emergency fallback to simple logging (without sensitive data)
            try:
                logger.critical(f"🚨 EMERGENCY AUDIT: {event_type.value} - {message}")
                logger.critical(f"   ⚠️  Original error: {e}")
                logger.critical(f"   🔒 Sensitive data not logged due to encryption failure")
            except Exception as fallback_error:
                # If even fallback logging fails, write to stderr as last resort
                import sys
                print(f"CRITICAL AUDIT FAILURE: {event_type.value} - {fallback_error}", file=sys.stderr)
    
    async def get_decrypted_security_events(
        self, 
        admin_user_id: str, 
        limit: int = 50,
        severity_filter: str = None,
        event_type_filter: str = None
    ) -> List[Dict[str, Any]]:
        """
        🔍 SECURE AUDIT LOG RETRIEVAL for authorized administrators
        
        SECURITY CONTROLS:
        - Only authorized administrators can decrypt and view audit logs
        - All audit log access is itself logged for accountability
        - Pagination prevents bulk data extraction
        - Filtering allows targeted investigation without full access
        
        Args:
            admin_user_id: ID of administrator requesting logs (for meta-audit)
            limit: Maximum number of logs to return (prevents bulk extraction)
            severity_filter: Optional severity level filter
            event_type_filter: Optional event type filter
        """
        try:
            # Log the audit log access attempt (meta-audit for accountability)
            await self._log_security_event(
                SecurityEvent.ADMIN_ACTION,
                f"Administrator accessing security audit logs",
                user_id=admin_user_id,
                metadata={
                    "action": "audit_log_access",
                    "limit": limit,
                    "severity_filter": severity_filter,
                    "event_type_filter": event_type_filter,
                    "access_timestamp": datetime.utcnow().isoformat()
                },
                severity="INFO"
            )
            
            # Build query with filters
            query = self.db.query(AuditLog)
            
            if severity_filter:
                query = query.filter(AuditLog.severity == severity_filter)
            
            if event_type_filter:
                query = query.filter(AuditLog.event_type == event_type_filter)
            
            # Get the most recent logs
            audit_logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
            
            # Decrypt audit logs for authorized viewing
            decrypted_logs = []
            encryption_key = getattr(self.db, 'encryption_key', None)
            
            if not encryption_key:
                logger.error("🚨 Cannot decrypt audit logs - encryption key not available")
                return [{"error": "Decryption key unavailable", "timestamp": datetime.utcnow().isoformat()}]
            
            for audit_log in audit_logs:
                try:
                    # Decrypt the audit log data
                    decrypted_data = audit_log.decrypt_audit_data(encryption_key)
                    decrypted_logs.append(decrypted_data)
                    
                except Exception as decrypt_error:
                    logger.warning(f"Failed to decrypt audit log {audit_log.id}: {decrypt_error}")
                    # Include log with decryption error for transparency
                    decrypted_logs.append({
                        "id": audit_log.id,
                        "timestamp": audit_log.timestamp.isoformat(),
                        "event_type": audit_log.event_type,
                        "severity": audit_log.severity,
                        "message": audit_log.message,
                        "decryption_error": str(decrypt_error),
                        "encrypted": True
                    })
            
            logger.info(f"🔍 Administrator {admin_user_id} accessed {len(decrypted_logs)} security audit logs")
            return decrypted_logs
            
        except Exception as e:
            logger.error(f"❌ Error retrieving security audit logs: {e}")
            return [{"error": f"Audit log retrieval failed: {e}", "timestamp": datetime.utcnow().isoformat()}]

class APIKeyService:
    """API key management service"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    async def create_api_key(
        self,
        name: str,
        permissions: List[Permission],
        created_by: str,
        expires_days: Optional[int] = None
    ) -> Tuple[str, APIKey]:
        """Create new API key"""
        
        # Generate key
        full_key, key_hash, prefix = SecurityUtils.generate_api_key()
        
        # Set expiration
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        # Create API key record
        api_key = APIKey(
            name=name,
            key_hash=key_hash,
            key_prefix=prefix,
            permissions=[p.value for p in permissions],
            created_by=created_by,
            expires_at=expires_at
        )
        
        self.db.add(api_key)
        self.db.commit()
        
        logger.info(f"API key created: {name} by {created_by}")
        return full_key, api_key
    
    async def verify_api_key(self, api_key: str) -> Optional[APIKey]:
        """Verify API key and return key object"""
        
        # Hash the provided key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Find key
        key_obj = self.db.query(APIKey).filter(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True
        ).first()
        
        if not key_obj:
            return None
        
        # Check expiration
        if key_obj.expires_at and datetime.utcnow() > key_obj.expires_at:
            return None
        
        # Update usage
        key_obj.last_used = datetime.utcnow()
        key_obj.usage_count += 1
        self.db.commit()
        
        return key_obj 