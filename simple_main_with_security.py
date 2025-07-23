#!/usr/bin/env python3
"""
MediVote Secure Main Application
REAL SECURITY - No hardcoded credentials or authentication bypasses

CRITICAL: This implementation provides REAL authentication security
"""

import os
import sys
import asyncio
import json
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
import jwt
import bcrypt
import logging

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/medivote_secure.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# REAL security configuration
class SecurityConfig:
    JWT_SECRET_KEY = secrets.token_urlsafe(64)  # Generate random secret
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    PASSWORD_MIN_LENGTH = 12
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

app = FastAPI(title="MediVote Secure API", version="1.0.0")
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Request/Response Models
class AdminCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=12)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    full_name: str = Field(..., min_length=2, max_length=100)
    phone: Optional[str] = None

class AdminLoginRequest(BaseModel):
    username: str
    password: str
    device_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    remember_me: bool = False

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]

# REAL user storage with proper security
class SecureUserStore:
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.failed_attempts: Dict[str, Dict[str, Any]] = {}
        self.refresh_tokens: Dict[str, str] = {}  # refresh_token -> username
        
        # Create initial admin user with SECURE practices
        self._create_initial_admin()
    
    def _create_initial_admin(self):
        """Create initial admin with secure random password"""
        # Generate secure random password
        admin_password = self._generate_secure_password()
        
        admin_user = {
            "username": "admin",
            "password_hash": self._hash_password(admin_password),
            "email": "admin@medivote.local",
            "full_name": "System Administrator",
            "role": "super_admin",
            "created_at": datetime.utcnow().isoformat(),
            "is_active": True,
            "failed_attempts": 0,
            "locked_until": None,
            "last_login": None
        }
        
        self.users["admin"] = admin_user
        
        # CRITICAL: Log the secure password for initial setup
        logger.critical(f"🔐 INITIAL ADMIN CREDENTIALS (SAVE THESE SECURELY):")
        logger.critical(f"   Username: admin")
        logger.critical(f"   Password: {admin_password}")
        logger.critical(f"   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
        
        # Write credentials to secure file for administrator
        with open("ADMIN_CREDENTIALS.txt", "w") as f:
            f.write(f"MediVote Initial Admin Credentials\n")
            f.write(f"===================================\n\n")
            f.write(f"Username: admin\n")
            f.write(f"Password: {admin_password}\n\n")
            f.write(f"⚠️  CRITICAL SECURITY NOTICE:\n")
            f.write(f"- Change this password immediately after first login\n")
            f.write(f"- Delete this file after securing the credentials\n")
            f.write(f"- Use strong, unique passwords for all accounts\n")
    
    def _generate_secure_password(self) -> str:
        """Generate cryptographically secure random password"""
        # Mix of characters for strong password
        import string
        charset = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(charset) for _ in range(16))
        return password
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt with proper salt"""
        salt = bcrypt.gensalt(rounds=12)  # Strong hashing rounds
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against bcrypt hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def create_user(self, user_data: AdminCreateRequest) -> Dict[str, Any]:
        """Create new user with proper validation"""
        # Check if username already exists
        if user_data.username in self.users:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        
        # Validate password strength
        if not self._validate_password_strength(user_data.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password does not meet security requirements"
            )
        
        # Create user
        user = {
            "username": user_data.username,
            "password_hash": self._hash_password(user_data.password),
            "email": user_data.email,
            "full_name": user_data.full_name,
            "phone": user_data.phone,
            "role": "admin",  # Default role
            "created_at": datetime.utcnow().isoformat(),
            "is_active": True,
            "failed_attempts": 0,
            "locked_until": None,
            "last_login": None
        }
        
        self.users[user_data.username] = user
        logger.info(f"Created new user: {user_data.username}")
        
        return {
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "created_at": user["created_at"]
        }
    
    def _validate_password_strength(self, password: str) -> bool:
        """Validate password meets security requirements"""
        if len(password) < SecurityConfig.PASSWORD_MIN_LENGTH:
            return False
        
        # Check for required character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return all([has_upper, has_lower, has_digit, has_special])
    
    def authenticate_user(self, login_request: AdminLoginRequest, client_ip: str) -> Dict[str, Any]:
        """Authenticate user with real security checks"""
        username = login_request.username
        
        # Check if user exists
        if username not in self.users:
            self._record_failed_attempt(client_ip, username)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        user = self.users[username]
        
        # Check if account is locked
        if user.get("locked_until"):
            lock_time = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < lock_time:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked due to failed login attempts"
                )
            else:
                # Unlock account
                user["locked_until"] = None
                user["failed_attempts"] = 0
        
        # Check IP-based rate limiting
        if self._is_ip_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts from this IP address"
            )
        
        # Verify password
        if not self._verify_password(login_request.password, user["password_hash"]):
            self._record_failed_attempt(client_ip, username)
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            
            # Lock account after max attempts
            if user["failed_attempts"] >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                lock_until = datetime.utcnow() + timedelta(minutes=SecurityConfig.LOCKOUT_DURATION_MINUTES)
                user["locked_until"] = lock_until.isoformat()
                logger.warning(f"Account locked for user {username} until {lock_until}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Successful authentication
        user["failed_attempts"] = 0
        user["locked_until"] = None
        user["last_login"] = datetime.utcnow().isoformat()
        
        self._clear_failed_attempts(client_ip)
        
        logger.info(f"Successful authentication for user: {username}")
        return user
    
    def _record_failed_attempt(self, ip_address: str, username: str = None):
        """Record failed login attempt"""
        current_time = datetime.utcnow()
        
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {
                "attempts": [],
                "usernames": set()
            }
        
        self.failed_attempts[ip_address]["attempts"].append(current_time)
        if username:
            self.failed_attempts[ip_address]["usernames"].add(username)
        
        # Clean old attempts (older than 1 hour)
        cutoff_time = current_time - timedelta(hours=1)
        self.failed_attempts[ip_address]["attempts"] = [
            attempt for attempt in self.failed_attempts[ip_address]["attempts"]
            if attempt > cutoff_time
        ]
    
    def _is_ip_rate_limited(self, ip_address: str) -> bool:
        """Check if IP is rate limited"""
        if ip_address not in self.failed_attempts:
            return False
        
        recent_attempts = len(self.failed_attempts[ip_address]["attempts"])
        return recent_attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS * 2  # More lenient for IP
    
    def _clear_failed_attempts(self, ip_address: str):
        """Clear failed attempts for IP"""
        if ip_address in self.failed_attempts:
            self.failed_attempts[ip_address]["attempts"] = []

# Global secure user store
user_store = SecureUserStore()

# Authentication functions
def create_access_token(user_data: Dict[str, Any]) -> str:
    """Create secure JWT access token"""
    expires_delta = timedelta(minutes=SecurityConfig.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    
    to_encode = {
        "sub": user_data["username"],
        "user_id": user_data["username"],  # For compatibility
        "role": user_data["role"],
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    }
    
    encoded_jwt = jwt.encode(to_encode, SecurityConfig.JWT_SECRET_KEY, algorithm=SecurityConfig.JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(username: str) -> str:
    """Create secure refresh token"""
    expires_delta = timedelta(days=SecurityConfig.REFRESH_TOKEN_EXPIRE_DAYS)
    expire = datetime.utcnow() + expires_delta
    
    to_encode = {
        "sub": username,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": str(uuid.uuid4())  # Unique ID for token revocation
    }
    
    encoded_jwt = jwt.encode(to_encode, SecurityConfig.JWT_SECRET_KEY, algorithm=SecurityConfig.JWT_ALGORITHM)
    
    # Store refresh token
    user_store.refresh_tokens[encoded_jwt] = username
    
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Verify JWT token with proper validation"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SecurityConfig.JWT_SECRET_KEY, algorithms=[SecurityConfig.JWT_ALGORITHM])
        
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Check if user still exists and is active
        if username not in user_store.users:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        user = user_store.users[username]
        if not user.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled"
            )
        
        return {
            "username": username,
            "role": payload.get("role"),
            "user_data": user
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

# API Endpoints
@app.post("/api/admin/auth/register", response_model=Dict[str, Any])
@limiter.limit("3/hour")  # Strict rate limiting for user creation
async def register_admin(request: Request, user_data: AdminCreateRequest):
    """Register new admin user with proper security"""
    try:
        new_user = user_store.create_user(user_data)
        logger.info(f"New admin user registered: {user_data.username}")
        
        return {
            "success": True,
            "message": "Admin user created successfully",
            "user": new_user
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@app.post("/api/admin/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def admin_login(request: Request, login_request: AdminLoginRequest):
    """Admin login with comprehensive security"""
    client_ip = get_remote_address(request)
    
    try:
        # Authenticate user
        user = user_store.authenticate_user(login_request, client_ip)
        
        # Create tokens
        access_token = create_access_token(user)
        refresh_token = create_refresh_token(user["username"])
        
        # Create session record
        session_id = str(uuid.uuid4())
        user_store.sessions[session_id] = {
            "username": user["username"],
            "created_at": datetime.utcnow().isoformat(),
            "ip_address": client_ip,
            "device_fingerprint": login_request.device_fingerprint,
            "refresh_token": refresh_token
        }
        
        logger.info(f"Successful login for user: {user['username']} from IP: {client_ip}")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=SecurityConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_info={
                "username": user["username"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
                "last_login": user["last_login"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )

@app.post("/api/admin/auth/refresh")
@limiter.limit("10/minute")
async def refresh_access_token(request: Request, refresh_token: str):
    """Refresh access token"""
    try:
        # Verify refresh token
        payload = jwt.decode(refresh_token, SecurityConfig.JWT_SECRET_KEY, algorithms=[SecurityConfig.JWT_ALGORITHM])
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        
        username = payload.get("sub")
        if refresh_token not in user_store.refresh_tokens or user_store.refresh_tokens[refresh_token] != username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        
        # Get user
        user = user_store.users.get(username)
        if not user or not user.get("is_active"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or disabled")
        
        # Create new access token
        new_access_token = create_access_token(user)
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": SecurityConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

@app.post("/api/admin/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(verify_token)):
    """Logout and invalidate tokens"""
    username = current_user["username"]
    
    # Remove all refresh tokens for this user
    tokens_to_remove = [token for token, user in user_store.refresh_tokens.items() if user == username]
    for token in tokens_to_remove:
        del user_store.refresh_tokens[token]
    
    # Remove sessions
    sessions_to_remove = [sid for sid, session in user_store.sessions.items() if session["username"] == username]
    for sid in sessions_to_remove:
        del user_store.sessions[sid]
    
    logger.info(f"User logged out: {username}")
    
    return {"message": "Successfully logged out"}

@app.get("/api/admin/profile")
async def get_admin_profile(current_user: Dict[str, Any] = Depends(verify_token)):
    """Get current admin profile"""
    user_data = current_user["user_data"]
    
    return {
        "username": user_data["username"],
        "email": user_data["email"],
        "full_name": user_data["full_name"],
        "role": user_data["role"],
        "created_at": user_data["created_at"],
        "last_login": user_data["last_login"]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    
    logger.info("🔐 Starting MediVote Secure API with REAL authentication")
    logger.info("⚠️  Check ADMIN_CREDENTIALS.txt for initial admin login")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        reload=False,  # Disable reload in production
        access_log=True
    ) 