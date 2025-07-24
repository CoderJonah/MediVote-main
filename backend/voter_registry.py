#!/usr/bin/env python3
"""
MediVote Voter Registry with Encrypted Persistent Storage
Handles voter registration, authentication, and credential management
"""

import json
import os
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Import security services
from security_service import encryption_service, auth_service

logger = logging.getLogger(__name__)

@dataclass
class VoterCredentials:
    """Voter credential structure"""
    voter_id: str
    username: str
    email: str
    full_name: str
    password_hash: str
    voter_did: str
    registration_date: str
    last_login: Optional[str] = None
    is_active: bool = True
    verified: bool = False
    verification_token: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    date_of_birth: Optional[str] = None
    identity_document: Optional[str] = None
    id_number: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VoterCredentials':
        """Create from dictionary"""
        return cls(**data)

@dataclass 
class LoginSession:
    """Voter login session"""
    session_id: str
    voter_id: str
    username: str
    voter_did: str
    created_at: str
    expires_at: str
    ip_address: str
    user_agent: str
    is_active: bool = True

class VoterRegistry:
    """Manages voter registration and authentication with encrypted storage"""
    
    def __init__(self, registry_dir: str = "voter_data"):
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(exist_ok=True)
        
        # Storage files (encrypted)
        self.credentials_file = self.registry_dir / "voter_credentials.json"
        self.sessions_file = self.registry_dir / "active_sessions.json" 
        self.audit_file = self.registry_dir / "voter_audit.json"
        
        # In-memory storage
        self.voter_credentials: Dict[str, VoterCredentials] = {}
        self.active_sessions: Dict[str, LoginSession] = {}
        self.audit_events: List[Dict[str, Any]] = []
        
        # Load existing data
        self._load_encrypted_data()
        
        logger.info(f"Voter Registry initialized with {len(self.voter_credentials)} registered voters")
    
    def _load_encrypted_data(self):
        """Load and decrypt voter data from files"""
        try:
            # Load voter credentials
            if self.credentials_file.exists():
                with open(self.credentials_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    data = json.loads(decrypted_data)
                    self.voter_credentials = {
                        voter_id: VoterCredentials.from_dict(voter_data)
                        for voter_id, voter_data in data.items()
                    }
                    logger.info(f"Loaded {len(self.voter_credentials)} voter credentials from encrypted storage")
                except Exception as decrypt_error:
                    print(f"Decryption error: ")
                    print(f"Could not decrypt voter credentials, starting fresh: ")
                    print(f"Decryption error: {decrypt_error}")
                    self.voter_credentials = {}
            
            # Load active sessions  
            if self.sessions_file.exists():
                with open(self.sessions_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    data = json.loads(decrypted_data)
                    self.active_sessions = {
                        session_id: LoginSession(**session_data)
                        for session_id, session_data in data.items()
                    }
                    # Clean expired sessions
                    self._cleanup_expired_sessions()
                    logger.info(f"Loaded {len(self.active_sessions)} active sessions from encrypted storage")
                except Exception as decrypt_error:
                    print(f"Decryption error:")
                    print(f"Could not decrypt sessions, starting fresh:")
                    print(f"Decryption error: {decrypt_error}")
                    self.active_sessions = {}
            
            # Load audit events
            if self.audit_file.exists():
                with open(self.audit_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    self.audit_events = json.loads(decrypted_data)
                    logger.info(f"Loaded {len(self.audit_events)} audit events from encrypted storage")
                except Exception as decrypt_error:
                    print(f"Decryption error:")
                    print(f"Could not decrypt audit data, starting fresh:")
                    print(f"Decryption error: {decrypt_error}")
                    self.audit_events = []
                    
        except Exception as e:
            logger.error(f"Error loading encrypted voter data: {e}")
            # Initialize empty data on error
            self.voter_credentials = {}
            self.active_sessions = {}
            self.audit_events = []
    
    def _save_encrypted_data(self):
        """Save encrypted voter data to files"""
        try:
            # Save voter credentials (ENCRYPTED)
            credentials_data = {
                voter_id: voter.to_dict()
                for voter_id, voter in self.voter_credentials.items()
            }
            encrypted_credentials = encryption_service.encrypt_data(json.dumps(credentials_data))
            with open(self.credentials_file, 'w') as f:
                f.write(encrypted_credentials)
            
            # Save active sessions (ENCRYPTED)
            sessions_data = {
                session_id: asdict(session)
                for session_id, session in self.active_sessions.items()
            }
            encrypted_sessions = encryption_service.encrypt_data(json.dumps(sessions_data))
            with open(self.sessions_file, 'w') as f:
                f.write(encrypted_sessions)
            
            # Save audit events (ENCRYPTED)
            encrypted_audit = encryption_service.encrypt_data(json.dumps(self.audit_events))
            with open(self.audit_file, 'w') as f:
                f.write(encrypted_audit)
                
            logger.debug("Encrypted voter data saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving encrypted voter data: {e}")
    
    def _audit_event(self, event_type: str, voter_id: str, username: str, details: Dict[str, Any], success: bool):
        """Record audit event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "voter_id": voter_id,
            "username": username,
            "details": details,
            "success": success
        }
        self.audit_events.append(event)
        
        # Keep only last 1000 events
        if len(self.audit_events) > 1000:
            self.audit_events = self.audit_events[-1000:]
        
        # Save after each audit event
        self._save_encrypted_data()
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions"""
        current_time = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            expires_at = datetime.fromisoformat(session.expires_at)
            if current_time > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
            logger.debug(f"Removed expired session: {session_id}")
    
    def register_voter(self, registration_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new voter"""
        try:
            # Validate required fields
            required_fields = ["username", "email", "full_name", "password"]
            for field in required_fields:
                if field not in registration_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Check if username/email already exists
            username = registration_data["username"].lower().strip()
            email = registration_data["email"].lower().strip()
            
            for voter in self.voter_credentials.values():
                if voter.username.lower() == username:
                    raise ValueError("Username already exists")
                if voter.email.lower() == email:
                    raise ValueError("Email already registered")
            
            # Generate voter credentials
            voter_id = f"voter_{len(self.voter_credentials) + 1:06d}"
            voter_did = f"did:medivote:{secrets.token_hex(16)}"
            password_hash = self._hash_password(registration_data["password"])
            verification_token = secrets.token_hex(16)
            
            # Create voter record
            voter = VoterCredentials(
                voter_id=voter_id,
                username=username,
                email=email,
                full_name=registration_data["full_name"],
                password_hash=password_hash,
                voter_did=voter_did,
                registration_date=datetime.now().isoformat(),
                verification_token=verification_token,
                phone=registration_data.get("phone", ""),
                address=registration_data.get("address", ""),
                date_of_birth=registration_data.get("date_of_birth", ""),
                identity_document=registration_data.get("identity_document", ""),
                id_number=registration_data.get("id_number", "")
            )
            
            # Store voter
            self.voter_credentials[voter_id] = voter
            self._save_encrypted_data()
            
            # Audit registration
            self._audit_event("VOTER_REGISTRATION", voter_id, username, {
                "email": email,
                "full_name": registration_data["full_name"]
            }, True)
            
            logger.info(f"New voter registered: {username} ({voter_id})")
            
            return {
                "success": True,
                "voter_id": voter_id,
                "username": username,
                "voter_did": voter_did,
                "verification_required": True,
                "verification_token": verification_token,
                "message": "Registration successful! Please save your Voter DID for future logins."
            }
            
        except Exception as e:
            self._audit_event("VOTER_REGISTRATION", "", registration_data.get("username", ""), {
                "error": str(e)
            }, False)
            logger.error(f"Voter registration failed: {e}")
            raise
    
    def authenticate_voter(self, username: str, password: str, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Authenticate voter and create session"""
        try:
            # Find voter by username or email
            voter = None
            for cred in self.voter_credentials.values():
                if cred.username.lower() == username.lower() or cred.email.lower() == username.lower():
                    voter = cred
                    break
            
            if not voter:
                self._audit_event("VOTER_LOGIN", "", username, {
                    "reason": "voter_not_found",
                    "ip_address": ip_address
                }, False)
                raise ValueError("Invalid username/email or password")
            
            # Verify password
            if not self._verify_password(password, voter.password_hash):
                self._audit_event("VOTER_LOGIN", voter.voter_id, username, {
                    "reason": "invalid_password",
                    "ip_address": ip_address
                }, False)
                raise ValueError("Invalid username/email or password")
            
            # Check if voter is active
            if not voter.is_active:
                self._audit_event("VOTER_LOGIN", voter.voter_id, username, {
                    "reason": "account_disabled",
                    "ip_address": ip_address
                }, False)
                raise ValueError("Account is disabled")
            
            # Create login session
            session_id = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=24)  # 24 hour sessions
            
            session = LoginSession(
                session_id=session_id,
                voter_id=voter.voter_id,
                username=voter.username,
                voter_did=voter.voter_did,
                created_at=datetime.now().isoformat(),
                expires_at=expires_at.isoformat(),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.active_sessions[session_id] = session
            
            # Update last login
            voter.last_login = datetime.now().isoformat()
            self._save_encrypted_data()
            
            # Audit successful login
            self._audit_event("VOTER_LOGIN", voter.voter_id, username, {
                "ip_address": ip_address,
                "session_id": session_id
            }, True)
            
            logger.info(f"🔓 Voter logged in: {username} ({voter.voter_id})")
            
            return {
                "success": True,
                "session_id": session_id,
                "voter_id": voter.voter_id,
                "username": voter.username,
                "voter_did": voter.voter_did,
                "full_name": voter.full_name,
                "expires_at": expires_at.isoformat(),
                "message": "Login successful!"
            }
            
        except Exception as e:
            logger.error(f"Voter authentication failed: {e}")
            raise
    
    def get_voter_credentials(self, session_id: str) -> Dict[str, Any]:
        """Get voter credentials by session"""
        try:
            self._cleanup_expired_sessions()
            
            if session_id not in self.active_sessions:
                raise ValueError("Invalid or expired session")
            
            session = self.active_sessions[session_id]
            voter = self.voter_credentials[session.voter_id]
            
            return {
                "voter_id": voter.voter_id,
                "username": voter.username,
                "voter_did": voter.voter_did,
                "full_name": voter.full_name,
                "email": voter.email,
                "phone": voter.phone,
                "registration_date": voter.registration_date,
                "last_login": voter.last_login,
                "verified": voter.verified
            }
            
        except Exception as e:
            logger.error(f"Error retrieving voter credentials: {e}")
            raise
    
    def validate_session(self, session_id: str) -> Optional[VoterCredentials]:
        """Validate session and return voter credentials"""
        try:
            self._cleanup_expired_sessions()
            
            if session_id not in self.active_sessions:
                return None
            
            session = self.active_sessions[session_id]
            return self.voter_credentials.get(session.voter_id)
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None
    
    def logout_voter(self, session_id: str):
        """Logout voter by removing session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            self._save_encrypted_data()
            
            self._audit_event("VOTER_LOGOUT", session.voter_id, session.username, {
                "session_id": session_id
            }, True)
            
            logger.info(f"Voter logged out: {session.username}")
    
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
    
    def get_registration_stats(self) -> Dict[str, Any]:
        """Get voter registration statistics"""
        active_voters = len([v for v in self.voter_credentials.values() if v.is_active])
        verified_voters = len([v for v in self.voter_credentials.values() if v.verified])
        
        return {
            "total_registered": len(self.voter_credentials),
            "active_voters": active_voters,
            "verified_voters": verified_voters,
            "active_sessions": len(self.active_sessions)
        }

# Global voter registry instance
voter_registry = VoterRegistry() 