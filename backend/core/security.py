"""
Security Service for MediVote
Handles device fingerprinting, rate limiting, and security controls
"""

import hashlib
import hmac
import secrets
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import ipaddress

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from loguru import logger
import user_agents

from core.config import get_settings, get_security_config

settings = get_settings()
security_config = get_security_config()


@dataclass
class DeviceFingerprintData:
    """Device fingerprint data structure"""
    user_agent: str
    screen_resolution: str
    timezone: str
    language: str
    platform: str
    webgl_vendor: str
    webgl_renderer: str
    canvas_fingerprint: str
    audio_fingerprint: str
    plugins: List[str]
    fonts: List[str]
    timestamp: datetime


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    severity: str
    ip_address: str
    user_agent: str
    timestamp: datetime
    details: Dict[str, Any]
    user_did: Optional[str] = None
    session_id: Optional[str] = None


class DeviceFingerprint:
    """Device fingerprinting service"""
    
    def __init__(self):
        self.known_devices: Dict[str, DeviceFingerprintData] = {}
        self.suspicious_devices: Set[str] = set()
    
    def generate_fingerprint(self, data: Dict[str, Any]) -> str:
        """Generate device fingerprint from client data"""
        try:
            # Normalize and sort data for consistent fingerprinting
            normalized_data = {
                'user_agent': data.get('userAgent', '').lower(),
                'screen_resolution': data.get('screenResolution', ''),
                'timezone': data.get('timezone', ''),
                'language': data.get('language', ''),
                'platform': data.get('platform', '').lower(),
                'webgl_vendor': data.get('webglVendor', ''),
                'webgl_renderer': data.get('webglRenderer', ''),
                'canvas_fingerprint': data.get('canvasFingerprint', ''),
                'audio_fingerprint': data.get('audioFingerprint', ''),
                'plugins': sorted(data.get('plugins', [])),
                'fonts': sorted(data.get('fonts', []))
            }
            
            # Create fingerprint hash
            fingerprint_string = json.dumps(normalized_data, sort_keys=True)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            # Store device data
            self.known_devices[fingerprint_hash] = DeviceFingerprintData(
                user_agent=normalized_data['user_agent'],
                screen_resolution=normalized_data['screen_resolution'],
                timezone=normalized_data['timezone'],
                language=normalized_data['language'],
                platform=normalized_data['platform'],
                webgl_vendor=normalized_data['webgl_vendor'],
                webgl_renderer=normalized_data['webgl_renderer'],
                canvas_fingerprint=normalized_data['canvas_fingerprint'],
                audio_fingerprint=normalized_data['audio_fingerprint'],
                plugins=normalized_data['plugins'],
                fonts=normalized_data['fonts'],
                timestamp=datetime.utcnow()
            )
            
            return fingerprint_hash
            
        except Exception as e:
            logger.error(f"Device fingerprint generation failed: {e}")
            return ""
    
    def verify_fingerprint(self, data: Dict[str, Any]) -> bool:
        """Verify device fingerprint against known devices"""
        try:
            fingerprint = self.generate_fingerprint(data)
            
            if not fingerprint:
                return False
            
            # Check if device is known
            if fingerprint in self.known_devices:
                # Update timestamp for known device
                self.known_devices[fingerprint].timestamp = datetime.utcnow()
                return True
            
            # Check for suspicious patterns
            if self._is_suspicious_device(data):
                self.suspicious_devices.add(fingerprint)
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Device fingerprint verification failed: {e}")
            return False
    
    def _is_suspicious_device(self, data: Dict[str, Any]) -> bool:
        """Check for suspicious device patterns"""
        try:
            user_agent = data.get('userAgent', '')
            
            # Check for headless browsers
            headless_indicators = ['headless', 'phantomjs', 'selenium', 'webdriver']
            if any(indicator in user_agent.lower() for indicator in headless_indicators):
                return True
            
            # Check for unusual canvas fingerprint
            canvas_fp = data.get('canvasFingerprint', '')
            if not canvas_fp or len(canvas_fp) < 10:
                return True
            
            # Check for missing expected properties
            required_properties = ['screenResolution', 'timezone', 'language', 'platform']
            if not all(data.get(prop) for prop in required_properties):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Suspicious device check failed: {e}")
            return True  # Err on the side of caution
    
    def get_device_risk_score(self, fingerprint: str) -> float:
        """Calculate risk score for a device (0.0 = low risk, 1.0 = high risk)"""
        try:
            if fingerprint in self.suspicious_devices:
                return 1.0
            
            if fingerprint not in self.known_devices:
                return 0.8  # Unknown device has moderate risk
            
            device_data = self.known_devices[fingerprint]
            
            # Calculate risk based on various factors
            risk_score = 0.0
            
            # Age of fingerprint (newer = higher risk)
            age_hours = (datetime.utcnow() - device_data.timestamp).total_seconds() / 3600
            if age_hours < 1:
                risk_score += 0.3
            elif age_hours < 24:
                risk_score += 0.1
            
            # Check user agent
            ua = user_agents.parse(device_data.user_agent)
            if not ua.is_mobile and not ua.is_pc:
                risk_score += 0.2
            
            # Check for common fingerprint evasion
            if not device_data.canvas_fingerprint or not device_data.audio_fingerprint:
                risk_score += 0.3
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Risk score calculation failed: {e}")
            return 0.8


class RateLimiter:
    """Rate limiting service"""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, datetime] = {}
    
    def is_rate_limited(self, client_ip: str, endpoint: str, limit: int, window: int) -> bool:
        """Check if client is rate limited"""
        try:
            key = f"{client_ip}:{endpoint}"
            current_time = time.time()
            
            # Check if IP is temporarily blocked
            if client_ip in self.blocked_ips:
                if datetime.utcnow() < self.blocked_ips[client_ip]:
                    return True
                else:
                    del self.blocked_ips[client_ip]
            
            # Initialize or clean old requests
            if key not in self.requests:
                self.requests[key] = []
            
            # Remove old requests outside the window
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if current_time - req_time < window
            ]
            
            # Check if limit exceeded
            if len(self.requests[key]) >= limit:
                # Block IP for extended period on repeated violations
                if len(self.requests[key]) > limit * 2:
                    self.blocked_ips[client_ip] = datetime.utcnow() + timedelta(hours=1)
                return True
            
            # Add current request
            self.requests[key].append(current_time)
            return False
            
        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
            return False  # Allow request if check fails
    
    def get_remaining_requests(self, client_ip: str, endpoint: str, limit: int, window: int) -> int:
        """Get remaining requests for client"""
        try:
            key = f"{client_ip}:{endpoint}"
            current_time = time.time()
            
            if key not in self.requests:
                return limit
            
            # Count valid requests in window
            valid_requests = [
                req_time for req_time in self.requests[key]
                if current_time - req_time < window
            ]
            
            return max(0, limit - len(valid_requests))
            
        except Exception as e:
            logger.error(f"Remaining requests calculation failed: {e}")
            return 0


class SecurityService:
    """Main security service"""
    
    def __init__(self):
        self.device_fingerprint = DeviceFingerprint()
        self.rate_limiter = RateLimiter()
        self.security_events: List[SecurityEvent] = []
        self.encryption_key = None
        self.failed_attempts: Dict[str, int] = {}
    
    async def initialize(self):
        """Initialize security service"""
        try:
            # Generate or load encryption key
            if hasattr(settings, 'ENCRYPTION_KEY') and settings.ENCRYPTION_KEY:
                self.encryption_key = settings.ENCRYPTION_KEY.encode()[:32]
            else:
                self.encryption_key = secrets.token_bytes(32)
            
            logger.info("Security service initialized successfully")
            
        except Exception as e:
            logger.error(f"Security service initialization failed: {e}")
            raise
    
    async def log_security_event(
        self,
        event_type: str,
        severity: str,
        ip_address: str,
        user_agent: str,
        details: Dict[str, Any],
        user_did: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log security event"""
        try:
            event = SecurityEvent(
                event_type=event_type,
                severity=severity,
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=datetime.utcnow(),
                details=details,
                user_did=user_did,
                session_id=session_id
            )
            
            self.security_events.append(event)
            
            # Log to file/database
            logger.log(
                severity.upper(),
                f"Security Event: {event_type} from {ip_address} - {details}"
            )
            
            # Trigger alerts for high-severity events
            if severity in ['ERROR', 'CRITICAL']:
                await self._trigger_security_alert(event)
                
        except Exception as e:
            logger.error(f"Security event logging failed: {e}")
    
    async def _trigger_security_alert(self, event: SecurityEvent):
        """Trigger security alert for high-severity events"""
        # In production, this would send alerts to security team
        logger.critical(f"SECURITY ALERT: {event.event_type} - {event.details}")
    
    def validate_ip_address(self, ip_address: str) -> bool:
        """Validate and check IP address"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Block private/localhost IPs in production
            if not settings.DEBUG and ip.is_private:
                return False
            
            # Block known malicious IPs (would integrate with threat intelligence)
            malicious_ips = set()  # Load from external source
            if ip_address in malicious_ips:
                return False
            
            return True
            
        except ValueError:
            return False
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            if not self.encryption_key:
                raise ValueError("Encryption key not initialized")
            
            fernet = Fernet(Fernet.generate_key())  # Use proper key derivation
            encrypted_data = fernet.encrypt(data.encode())
            return encrypted_data.decode()
            
        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            return ""
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            if not self.encryption_key:
                raise ValueError("Encryption key not initialized")
            
            # This is simplified - in production use proper key management
            return encrypted_data  # Placeholder
            
        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            return ""
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    def verify_token_signature(self, token: str, signature: str, secret: str) -> bool:
        """Verify HMAC signature of token"""
        try:
            expected_signature = hmac.new(
                secret.encode(),
                token.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(expected_signature, signature)
            
        except Exception as e:
            logger.error(f"Token signature verification failed: {e}")
            return False
    
    def record_failed_attempt(self, ip_address: str) -> int:
        """Record failed authentication attempt"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = 0
        
        self.failed_attempts[ip_address] += 1
        return self.failed_attempts[ip_address]
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked due to failed attempts"""
        return self.failed_attempts.get(ip_address, 0) >= security_config.MAX_FAILED_ATTEMPTS
    
    def reset_failed_attempts(self, ip_address: str):
        """Reset failed attempts for IP"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        return security_config.get_security_headers()
    
    async def close(self):
        """Close security service"""
        logger.info("Security service closed")


# Utility functions
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password with salt"""
    if not salt:
        salt = secrets.token_hex(16)
    
    # Use PBKDF2 with high iteration count
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=security_config.KDF_ITERATIONS,
    )
    
    key = kdf.derive(password.encode())
    return key.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash"""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=security_config.KDF_ITERATIONS,
        )
        
        kdf.verify(password.encode(), bytes.fromhex(hashed))
        return True
    except Exception:
        return False


def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return secrets.token_urlsafe(32)


def validate_csrf_token(token: str, session_token: str) -> bool:
    """Validate CSRF token"""
    # Simple validation - in production use more sophisticated approach
    return len(token) == 43 and token.replace('-', '').replace('_', '').isalnum()


def sanitize_input(input_data: str) -> str:
    """Sanitize user input"""
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
    sanitized = input_data
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()


def is_valid_did(did: str) -> bool:
    """Validate DID format"""
    if not did or not isinstance(did, str):
        return False
    
    # Basic DID format validation
    parts = did.split(':')
    if len(parts) < 3 or parts[0] != 'did':
        return False
    
    return True 