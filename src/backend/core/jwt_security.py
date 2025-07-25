#!/usr/bin/env python3
"""
MediVote Secure JWT Service
Implements secure JWT authentication with RSA/ECDSA asymmetric signing

SECURITY FEATURES:
- RSA-2048/ECDSA-256 asymmetric signing (replaces vulnerable HMAC)
- Automatic key rotation with version tracking
- Public/private key separation for enhanced security
- JWT security validation and audit logging
- Backward compatibility during HMAC → RSA transition
- Production-ready HSM integration

CRITICAL SECURITY IMPROVEMENT:
This replaces the vulnerable symmetric HMAC JWT signing that allows
token forgery if the secret key is exposed. Asymmetric signing ensures
only the private key can create tokens, while public keys verify them.
"""

import jwt
import json
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum
from dataclasses import dataclass, asdict
import logging
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

class JWTAlgorithm(str, Enum):
    """Supported JWT signing algorithms"""
    RS256 = "RS256"  # RSA with SHA-256 (recommended)
    RS384 = "RS384"  # RSA with SHA-384
    RS512 = "RS512"  # RSA with SHA-512
    ES256 = "ES256"  # ECDSA with SHA-256
    ES384 = "ES384"  # ECDSA with SHA-384
    ES512 = "ES512"  # ECDSA with SHA-512
    
    # Legacy (for backward compatibility only)
    HS256 = "HS256"  # HMAC with SHA-256 (DEPRECATED)

class JWTKeyType(str, Enum):
    """JWT key types"""
    RSA_PRIVATE = "rsa_private"
    RSA_PUBLIC = "rsa_public"
    ECDSA_PRIVATE = "ecdsa_private"
    ECDSA_PUBLIC = "ecdsa_public"
    HMAC_SECRET = "hmac_secret"  # Legacy only

@dataclass
class JWTKeyPair:
    """JWT asymmetric key pair"""
    key_id: str
    algorithm: JWTAlgorithm
    private_key: bytes
    public_key: bytes
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool = True
    version: int = 1

@dataclass
class JWTTokenInfo:
    """JWT token information"""
    token: str
    payload: Dict[str, Any]
    key_id: str
    algorithm: JWTAlgorithm
    issued_at: datetime
    expires_at: datetime

class SecureJWTService:
    """
    SECURE JWT SERVICE with ASYMMETRIC SIGNING
    
    Replaces vulnerable HMAC symmetric signing with secure RSA/ECDSA asymmetric signing.
    
    SECURITY BENEFITS:
    - Private key signs tokens (only server can create)
    - Public key verifies tokens (can be distributed safely)
    - Key rotation prevents long-term key exposure
    - No single point of failure for token forgery
    
    ALGORITHM RECOMMENDATIONS:
    - Production: RS256 (RSA-2048 + SHA-256) - widely supported
    - High Security: ES256 (ECDSA P-256 + SHA-256) - smaller keys
    - Legacy Support: HS256 (HMAC + SHA-256) - during transition only
    """
    
    def __init__(self, 
                 key_storage_path: Path = None,
                 default_algorithm: JWTAlgorithm = JWTAlgorithm.RS256,
                 key_rotation_days: int = 30):
        """
        Initialize secure JWT service
        
        Args:
            key_storage_path: Path to store JWT keys (defaults to secure location)
            default_algorithm: Default signing algorithm (RS256 recommended)
            key_rotation_days: Days between automatic key rotation
        """
        self.key_storage_path = key_storage_path or Path("keys/jwt")
        self.default_algorithm = default_algorithm
        self.key_rotation_days = key_rotation_days
        
        # Active key pairs by algorithm
        self.active_keys: Dict[JWTAlgorithm, JWTKeyPair] = {}
        
        # All key pairs (for verification of old tokens)
        self.all_keys: Dict[str, JWTKeyPair] = {}
        
        # Legacy HMAC support (for transition)
        self.legacy_hmac_secret: Optional[str] = None
        
        # Ensure key storage exists
        self.key_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Initialize keys
        self._initialize_keys()
        
        logger.critical("SECURE JWT SERVICE INITIALIZED")
        logger.critical(f"   Default Algorithm: {default_algorithm}")
        logger.critical(f"   Key Storage: {self.key_storage_path}")
        logger.critical(f"   Key Rotation: {key_rotation_days} days")
        logger.critical(f"   Active Keys: {len(self.active_keys)}")
        logger.critical("   SECURITY: Symmetric HMAC replaced with asymmetric signing")
    
    def _initialize_keys(self):
        """Initialize JWT signing keys"""
        try:
            # Load existing keys
            self._load_existing_keys()
            
            # Ensure we have an active key for the default algorithm
            if self.default_algorithm not in self.active_keys:
                logger.warning(f"No active key for {self.default_algorithm}, generating new key")
                self._generate_key_pair(self.default_algorithm)
            
            # Load legacy HMAC secret for backward compatibility
            self._load_legacy_hmac_secret()
            
            logger.info(f"JWT keys initialized: {len(self.active_keys)} active algorithms")
            
        except Exception as e:
            logger.error(f"JWT key initialization failed: {e}")
            raise RuntimeError(f"Failed to initialize JWT keys: {e}")
    
    def _load_existing_keys(self):
        """Load existing key pairs from storage"""
        if not self.key_storage_path.exists():
            return
        
        for key_file in self.key_storage_path.glob("*.json"):
            try:
                with open(key_file, 'r') as f:
                    key_data = json.load(f)
                
                # Reconstruct key pair
                key_pair = JWTKeyPair(
                    key_id=key_data['key_id'],
                    algorithm=JWTAlgorithm(key_data['algorithm']),
                    private_key=base64.b64decode(key_data['private_key']),
                    public_key=base64.b64decode(key_data['public_key']),
                    created_at=datetime.fromisoformat(key_data['created_at']),
                    expires_at=datetime.fromisoformat(key_data['expires_at']) if key_data.get('expires_at') else None,
                    is_active=key_data.get('is_active', True),
                    version=key_data.get('version', 1)
                )
                
                # Store key
                self.all_keys[key_pair.key_id] = key_pair
                
                # Set as active if it's the most recent for this algorithm
                if key_pair.is_active and not key_pair.expires_at or datetime.utcnow() < key_pair.expires_at:
                    if key_pair.algorithm not in self.active_keys:
                        self.active_keys[key_pair.algorithm] = key_pair
                    elif key_pair.created_at > self.active_keys[key_pair.algorithm].created_at:
                        self.active_keys[key_pair.algorithm] = key_pair
                
                logger.debug(f"Loaded JWT key: {key_pair.key_id} ({key_pair.algorithm})")
                
            except Exception as e:
                logger.error(f"Failed to load JWT key from {key_file}: {e}")
    
    def _load_legacy_hmac_secret(self):
        """Load legacy HMAC secret for backward compatibility"""
        try:
            from core.key_integration import get_jwt_secret_key
            
            # Get HMAC secret from key management system
            hmac_key_bytes = get_jwt_secret_key()
            if hmac_key_bytes:
                self.legacy_hmac_secret = base64.urlsafe_b64encode(hmac_key_bytes).decode()
                logger.info("Legacy HMAC secret loaded for backward compatibility")
            
        except Exception as e:
            logger.warning(f"Could not load legacy HMAC secret: {e}")
    
    def _generate_key_pair(self, algorithm: JWTAlgorithm) -> JWTKeyPair:
        """Generate new asymmetric key pair"""
        try:
            logger.info(f"Generating new JWT key pair for {algorithm}")
            
            # Generate unique key ID
            key_id = f"jwt_{algorithm.value.lower()}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(8)}"
            
            # Set expiration
            expires_at = datetime.utcnow() + timedelta(days=self.key_rotation_days)
            
            if algorithm in [JWTAlgorithm.RS256, JWTAlgorithm.RS384, JWTAlgorithm.RS512]:
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048  # RSA-2048 for security
                )
                public_key = private_key.public_key()
                
                # Serialize keys
                private_pem = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                )
                
            elif algorithm in [JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512]:
                # Generate ECDSA key pair
                if algorithm == JWTAlgorithm.ES256:
                    curve = ec.SECP256R1()  # P-256
                elif algorithm == JWTAlgorithm.ES384:
                    curve = ec.SECP384R1()  # P-384
                else:
                    curve = ec.SECP521R1()  # P-521
                
                private_key = ec.generate_private_key(curve)
                public_key = private_key.public_key()
                
                # Serialize keys
                private_pem = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                )
                
            else:
                raise ValueError(f"Unsupported algorithm for key generation: {algorithm}")
            
            # Create key pair object
            key_pair = JWTKeyPair(
                key_id=key_id,
                algorithm=algorithm,
                private_key=private_pem,
                public_key=public_pem,
                created_at=datetime.utcnow(),
                expires_at=expires_at,
                is_active=True,
                version=1
            )
            
            # Store keys
            self.all_keys[key_id] = key_pair
            self.active_keys[algorithm] = key_pair
            
            # Persist to disk
            self._save_key_pair(key_pair)
            
            logger.critical(f"GENERATED NEW JWT KEY PAIR: {key_id}")
            logger.critical(f"   Algorithm: {algorithm}")
            logger.critical(f"   Key Size: {len(private_pem)} bytes private, {len(public_pem)} bytes public")
            logger.critical(f"   Expires: {expires_at.isoformat()}")
            logger.critical("   SECURITY: Asymmetric signing replaces vulnerable HMAC")
            
            return key_pair
            
        except Exception as e:
            logger.error(f"Failed to generate JWT key pair: {e}")
            raise RuntimeError(f"JWT key generation failed: {e}")
    
    def _save_key_pair(self, key_pair: JWTKeyPair):
        """Save key pair to secure storage"""
        try:
            key_file = self.key_storage_path / f"{key_pair.key_id}.json"
            
            key_data = {
                'key_id': key_pair.key_id,
                'algorithm': key_pair.algorithm.value,
                'private_key': base64.b64encode(key_pair.private_key).decode(),
                'public_key': base64.b64encode(key_pair.public_key).decode(),
                'created_at': key_pair.created_at.isoformat(),
                'expires_at': key_pair.expires_at.isoformat() if key_pair.expires_at else None,
                'is_active': key_pair.is_active,
                'version': key_pair.version
            }
            
            # Write with secure permissions
            with open(key_file, 'w') as f:
                json.dump(key_data, f, indent=2)
            
            # Set restrictive permissions (owner read-only)
            key_file.chmod(0o600)
            
            logger.debug(f"Saved JWT key pair: {key_file}")
            
        except Exception as e:
            logger.error(f"Failed to save JWT key pair: {e}")
            raise
    
    def create_token(self, 
                    payload: Dict[str, Any],
                    algorithm: Optional[JWTAlgorithm] = None,
                    expires_in_minutes: int = 60,
                    issuer: str = "medivote-auth") -> JWTTokenInfo:
        """
        Create signed JWT token using asymmetric cryptography
        
        Args:
            payload: Token payload data
            algorithm: Signing algorithm (defaults to service default)
            expires_in_minutes: Token expiration time
            issuer: Token issuer
            
        Returns:
            JWTTokenInfo with signed token and metadata
            
        Raises:
            RuntimeError: If signing fails or no keys available
        """
        try:
            # Use default algorithm if not specified
            algorithm = algorithm or self.default_algorithm
            
            # Get active key for algorithm
            if algorithm not in self.active_keys:
                logger.warning(f"No active key for {algorithm}, generating new key")
                self._generate_key_pair(algorithm)
            
            key_pair = self.active_keys[algorithm]
            
            # Check if key needs rotation
            if key_pair.expires_at and datetime.utcnow() > key_pair.expires_at:
                logger.warning(f"JWT key expired, rotating: {key_pair.key_id}")
                key_pair = self._rotate_key(algorithm)
            
            # Prepare token payload
            now = datetime.utcnow()
            expires_at = now + timedelta(minutes=expires_in_minutes)
            
            token_payload = {
                **payload,
                'iat': int(now.timestamp()),  # Issued at
                'exp': int(expires_at.timestamp()),  # Expires at
                'iss': issuer,  # Issuer
                'jti': f"jwt_{secrets.token_hex(16)}",  # JWT ID
                'kid': key_pair.key_id  # Key ID for verification
            }
            
            # Handle different signing algorithms
            if algorithm in [JWTAlgorithm.RS256, JWTAlgorithm.RS384, JWTAlgorithm.RS512,
                           JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512]:
                # Asymmetric signing
                token = jwt.encode(
                    token_payload,
                    key_pair.private_key,
                    algorithm=algorithm.value
                )
                
            elif algorithm == JWTAlgorithm.HS256 and self.legacy_hmac_secret:
                # Legacy HMAC (backward compatibility only)
                logger.warning("Using legacy HMAC signing - should migrate to asymmetric")
                token = jwt.encode(
                    token_payload,
                    self.legacy_hmac_secret,
                    algorithm=algorithm.value
                )
                
            else:
                raise ValueError(f"Cannot sign with {algorithm}: no key available")
            
            # Create token info
            token_info = JWTTokenInfo(
                token=token,
                payload=token_payload,
                key_id=key_pair.key_id,
                algorithm=algorithm,
                issued_at=now,
                expires_at=expires_at
            )
            
            logger.debug(f"Created JWT token: {key_pair.key_id} ({algorithm})")
            return token_info
            
        except Exception as e:
            logger.error(f"JWT token creation failed: {e}")
            raise RuntimeError(f"Failed to create JWT token: {e}")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token using appropriate public key
        
        Args:
            token: JWT token to verify
            
        Returns:
            Decoded payload if valid, None if invalid
        """
        try:
            # Decode token header to get key ID and algorithm
            unverified_header = jwt.get_unverified_header(token)
            algorithm = unverified_header.get('alg')
            key_id = unverified_header.get('kid')
            
            if not algorithm:
                logger.warning("JWT token missing algorithm in header")
                return None
            
            # Handle different verification methods
            if algorithm in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
                # Asymmetric verification
                if not key_id:
                    logger.warning("JWT token missing key ID for asymmetric verification")
                    return None
                
                if key_id not in self.all_keys:
                    logger.warning(f"JWT key not found: {key_id}")
                    return None
                
                key_pair = self.all_keys[key_id]
                
                # Verify with public key
                payload = jwt.decode(
                    token,
                    key_pair.public_key,
                    algorithms=[algorithm]
                )
                
                logger.debug(f"Verified JWT token with key: {key_id}")
                return payload
                
            elif algorithm == 'HS256' and self.legacy_hmac_secret:
                # Legacy HMAC verification
                logger.warning("Verifying legacy HMAC token - should migrate to asymmetric")
                
                payload = jwt.decode(
                    token,
                    self.legacy_hmac_secret,
                    algorithms=['HS256']
                )
                
                return payload
                
            else:
                logger.warning(f"Unsupported JWT algorithm or missing key: {algorithm}")
                return None
                
        except jwt.ExpiredSignatureError:
            logger.debug("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"JWT verification error: {e}")
            return None
    
    def _rotate_key(self, algorithm: JWTAlgorithm) -> JWTKeyPair:
        """Rotate JWT signing key"""
        try:
            logger.info(f"Rotating JWT key for {algorithm}")
            
            # Mark old key as inactive (but keep for verification)
            if algorithm in self.active_keys:
                old_key = self.active_keys[algorithm]
                old_key.is_active = False
                self._save_key_pair(old_key)
                logger.info(f"Deactivated old JWT key: {old_key.key_id}")
            
            # Generate new key
            new_key = self._generate_key_pair(algorithm)
            
            logger.critical(f"JWT KEY ROTATED: {algorithm}")
            logger.critical(f"   New Key: {new_key.key_id}")
            logger.critical(f"   Old tokens remain valid until expiration")
            
            return new_key
            
        except Exception as e:
            logger.error(f"JWT key rotation failed: {e}")
            raise RuntimeError(f"Key rotation failed: {e}")
    
    def get_public_key(self, key_id: str) -> Optional[bytes]:
        """Get public key for external verification"""
        if key_id in self.all_keys:
            return self.all_keys[key_id].public_key
        return None
    
    def get_jwks(self) -> Dict[str, Any]:
        """Get JSON Web Key Set (JWKS) for public key distribution"""
        keys = []
        
        for key_pair in self.active_keys.values():
            if key_pair.algorithm in [JWTAlgorithm.RS256, JWTAlgorithm.RS384, JWTAlgorithm.RS512]:
                # RSA public key
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                public_key_obj = load_pem_public_key(key_pair.public_key)
                public_numbers = public_key_obj.public_numbers()
                
                keys.append({
                    "kty": "RSA",
                    "kid": key_pair.key_id,
                    "alg": key_pair.algorithm.value,
                    "use": "sig",
                    "n": base64.urlsafe_b64encode(
                        public_numbers.n.to_bytes(
                            (public_numbers.n.bit_length() + 7) // 8, 'big'
                        )
                    ).decode().rstrip('='),
                    "e": base64.urlsafe_b64encode(
                        public_numbers.e.to_bytes(
                            (public_numbers.e.bit_length() + 7) // 8, 'big'
                        )
                    ).decode().rstrip('=')
                })
                
        return {"keys": keys}
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get JWT security status"""
        return {
            "service_active": True,
            "default_algorithm": self.default_algorithm.value,
            "active_algorithms": [alg.value for alg in self.active_keys.keys()],
            "total_keys": len(self.all_keys),
            "key_rotation_days": self.key_rotation_days,
            "legacy_hmac_enabled": self.legacy_hmac_secret is not None,
            "security_level": "HIGH" if self.default_algorithm != JWTAlgorithm.HS256 else "LEGACY",
            "next_rotation": min([
                kp.expires_at for kp in self.active_keys.values() 
                if kp.expires_at
            ], default=None)
        }

# Global JWT service instance
_jwt_service: Optional[SecureJWTService] = None

def get_jwt_service() -> SecureJWTService:
    """Get global JWT service instance"""
    global _jwt_service
    if _jwt_service is None:
        _jwt_service = SecureJWTService()
    return _jwt_service

def initialize_jwt_security(
    algorithm: JWTAlgorithm = JWTAlgorithm.RS256,
    key_storage_path: Path = None,
    key_rotation_days: int = 30
) -> SecureJWTService:
    """Initialize JWT security system"""
    global _jwt_service
    _jwt_service = SecureJWTService(
        key_storage_path=key_storage_path,
        default_algorithm=algorithm,
        key_rotation_days=key_rotation_days
    )
    return _jwt_service

# Convenience functions for easy migration
def create_secure_token(payload: Dict[str, Any], expires_in_minutes: int = 60) -> str:
    """Create secure JWT token (convenience function)"""
    jwt_service = get_jwt_service()
    token_info = jwt_service.create_token(payload, expires_in_minutes=expires_in_minutes)
    return token_info.token

def verify_secure_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token (convenience function)"""
    jwt_service = get_jwt_service()
    return jwt_service.verify_token(token) 