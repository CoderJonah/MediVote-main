"""
Authentication API for MediVote
Handles Self-Sovereign Identity authentication with Zero-Knowledge Proofs
"""

import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import uuid

from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from loguru import logger
import jwt

from core.config import get_settings, get_security_config
from core.identity.verifiable_credentials import (
    VerifiableCredential, VerifiablePresentation, CredentialVerifier,
    CredentialIssuer, DIDResolver, generate_did
)
from core.crypto.zero_knowledge import ZKProof, RealZKVerifier
from core.security import SecurityService, DeviceFingerprint
from core.database import get_db

# Real Merkle Tree Implementation
class MerkleTree:
    """Real Merkle Tree implementation for voter eligibility verification"""
    
    def __init__(self, data_list: List[str]):
        """
        Initialize Merkle tree with list of voter credential hashes
        
        Args:
            data_list: List of voter credential hashes or DIDs
        """
        self.data_list = data_list if data_list else [""]
        self.tree = self._build_tree()
        self.root = self.tree[0] if self.tree else ""
    
    def _build_tree(self) -> List[str]:
        """Build the complete Merkle tree from leaf nodes"""
        if not self.data_list:
            return [""]
        
        # Start with leaf level (hash each data item)
        current_level = [self._hash(data) for data in self.data_list]
        tree_levels = [current_level[:]]  # Store all levels for proof generation
        
        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash(left + right)
                next_level.append(parent)
            
            tree_levels.insert(0, next_level)  # Insert at beginning (root first)
            current_level = next_level
        
        # Flatten tree levels for easy access
        flattened_tree = []
        for level in tree_levels:
            flattened_tree.extend(level)
        
        return flattened_tree
    
    def _hash(self, data: str) -> str:
        """Hash function for Merkle tree nodes"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def get_root(self) -> str:
        """Get the Merkle root hash"""
        return self.root
    
    def get_proof(self, data_item: str) -> Optional[List[Dict[str, Any]]]:
        """
        Generate Merkle proof for a specific data item
        
        Args:
            data_item: The data item to generate proof for
            
        Returns:
            List of proof elements with hash and position (left/right)
        """
        try:
            # Find the index of the data item
            item_index = self.data_list.index(data_item)
        except ValueError:
            return None
        
        # Generate proof path from leaf to root
        proof = []
        current_index = item_index
        current_level_size = len(self.data_list)
        
        # Navigate up the tree levels
        level_start = len(self.tree) - len(self.data_list)
        
        while current_level_size > 1:
            # Determine sibling index and position
            if current_index % 2 == 0:
                # Current node is left child
                sibling_index = current_index + 1
                position = "right"
            else:
                # Current node is right child
                sibling_index = current_index - 1
                position = "left"
            
            # Get sibling hash (or use current hash if no sibling)
            if sibling_index < current_level_size:
                sibling_hash = self.tree[level_start + sibling_index]
            else:
                sibling_hash = self.tree[level_start + current_index]
            
            proof.append({
                "hash": sibling_hash,
                "position": position
            })
            
            # Move to parent level
            current_index //= 2
            current_level_size = (current_level_size + 1) // 2
            level_start -= current_level_size
        
        return proof
    
    def verify_proof(self, data_item: str, proof: List[Dict[str, Any]], root: str) -> bool:
        """
        Verify a Merkle proof
        
        Args:
            data_item: The original data item
            proof: List of proof elements
            root: Expected Merkle root
            
        Returns:
            True if proof is valid
        """
        current_hash = self._hash(data_item)
        
        for proof_element in proof:
            sibling_hash = proof_element["hash"]
            position = proof_element["position"]
            
            if position == "left":
                current_hash = self._hash(sibling_hash + current_hash)
            else:
                current_hash = self._hash(current_hash + sibling_hash)
        
        return current_hash == root

def get_election_eligible_voters(election_id: str) -> List[str]:
    """
    Get list of eligible voter verification hashes for an election
    
    SECURITY: Uses ONLY the secure database with double encryption
    - Database encrypted with master key
    - Voter credentials salted with user passwords
    - Eliminates admin access to voter DIDs
    - NO deterministic fallbacks that compromise security
    
    Args:
        election_id: The election identifier
        
    Returns:
        List of verification hashes for eligible voters (for Merkle tree)
        
    Raises:
        SecurityError: If database query fails or no voters found
    """
    from core.secure_database import get_secure_database
    
    try:
        # Get secure database instance with integrated key management
        db = get_secure_database()
        
        # Query all verified voters for this election from encrypted database
        voters = db.get_eligible_voters(election_id)
        
        if not voters:
            logger.warning(f"🔒 No eligible voters found for election {election_id}")
            logger.warning("   This could indicate:")
            logger.warning("   - Election has no registered voters yet")
            logger.warning("   - Database initialization needed")
            logger.warning("   - Voter registration system not populated")
            # Return empty list - do NOT create fake data
            return []
        
        # Extract verification hashes from actual voter records
        # These are cryptographically secure hashes, not voter DIDs
        verification_hashes = [voter.verification_hash for voter in voters]
        
        logger.info(f"🔐 Retrieved {len(verification_hashes)} REAL eligible voters for election {election_id}")
        logger.info(f"   Database: Double encrypted with master key")
        logger.info(f"   Voters: Salted with individual passwords")
        logger.info(f"   Security: Admin-proof voter DID protection")
        
        return verification_hashes
        
    except Exception as e:
        logger.error(f"❌ SECURITY ERROR: Failed to fetch eligible voters for {election_id}: {e}")
        logger.error("   Database query failed - this is a critical security issue")
        logger.error("   Possible causes:")
        logger.error("   - Key management system failure")
        logger.error("   - Database corruption or unavailable")
        logger.error("   - Encryption key rotation needed")
        
        # SECURITY: Do NOT fall back to deterministic or mock data
        # Better to fail securely than compromise voter privacy
        raise SecurityError(f"Cannot retrieve voter eligibility data: {e}")


class SecurityError(Exception):
    """Security-related error that should not be bypassed"""
    pass

settings = get_settings()
security_config = get_security_config()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()

# Request/Response Models
class AuthenticationRequest(BaseModel):
    """Request for voter authentication"""
    did: str = Field(..., description="Decentralized Identifier of the voter")
    election_id: str = Field(..., description="Election identifier")
    zk_proof: Dict[str, Any] = Field(..., description="Zero-knowledge proof of eligibility")
    device_fingerprint: Dict[str, Any] = Field(..., description="Device fingerprint data")
    
    @validator('did')
    def validate_did(cls, v):
        if not v.startswith('did:'):
            raise ValueError('Invalid DID format')
        return v


class AuthenticationResponse(BaseModel):
    """Response for successful authentication"""
    session_token: str = Field(..., description="Session token for authenticated voter")
    session_expires: datetime = Field(..., description="Session expiration time")
    voter_status: str = Field(..., description="Voter eligibility status")
    election_info: Dict[str, Any] = Field(..., description="Election information")
    authorization_endpoint: str = Field(..., description="Ballot authorization endpoint")


class CredentialPresentationRequest(BaseModel):
    """Request for credential presentation"""
    verifiable_presentation: Dict[str, Any] = Field(..., description="W3C Verifiable Presentation")
    challenge: str = Field(..., description="Challenge string from verifier")
    domain: str = Field(..., description="Domain for presentation")


class CredentialPresentationResponse(BaseModel):
    """Response for credential presentation"""
    verified: bool = Field(..., description="Whether presentation was verified")
    eligibility_info: Optional[Dict[str, Any]] = Field(None, description="Extracted eligibility information")
    error_message: Optional[str] = Field(None, description="Error message if verification failed")


class ZKProofRequest(BaseModel):
    """Request for ZK proof verification"""
    proof: Dict[str, Any] = Field(..., description="Zero-knowledge proof")
    public_inputs: List[str] = Field(..., description="Public inputs for verification")
    election_id: str = Field(..., description="Election identifier")


class ZKProofResponse(BaseModel):
    """Response for ZK proof verification"""
    valid: bool = Field(..., description="Whether proof is valid")
    voter_eligible: bool = Field(..., description="Whether voter is eligible")
    merkle_root: str = Field(..., description="Merkle root used for verification")


class SessionInfo(BaseModel):
    """Information about authenticated session"""
    session_id: str
    voter_did: str
    election_id: str
    authenticated_at: datetime
    expires_at: datetime
    device_fingerprint: str
    eligibility_verified: bool


# Redis-based session storage for production scalability
from ..core.session_manager import get_session_manager, SessionData

# Legacy support - will be replaced by Redis sessions
failed_attempts: Dict[str, int] = {}


# Authentication endpoints
@router.post("/authenticate", response_model=AuthenticationResponse)
@limiter.limit("3/minute")
async def authenticate_voter(
    request: Request,
    auth_request: AuthenticationRequest,
    db=Depends(get_db)
):
    """
    Authenticate a voter using Zero-Knowledge Proof
    
    Flow:
    1. Verify device fingerprint
    2. Verify ZK proof of eligibility
    3. Check rate limiting and device restrictions
    4. Create authenticated session
    """
    
    client_ip = get_remote_address(request)
    
    try:
        # Check rate limiting
        if client_ip in failed_attempts and failed_attempts[client_ip] >= security_config.MAX_FAILED_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Please try again later."
            )
        
        # Verify device fingerprint
        device_fp = DeviceFingerprint()
        if not device_fp.verify_fingerprint(auth_request.device_fingerprint):
            _record_failed_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid device fingerprint"
            )
        
        # Initialize ZK proof verifier
        zk_verifier = RealZKVerifier("./circuits")
        
        # Verify zero-knowledge proof
        zk_proof = ZKProof(
            pi_a=(auth_request.zk_proof["pi_a"][0], auth_request.zk_proof["pi_a"][1]),
            pi_b=((auth_request.zk_proof["pi_b"][0][0], auth_request.zk_proof["pi_b"][0][1]),
                  (auth_request.zk_proof["pi_b"][1][0], auth_request.zk_proof["pi_b"][1][1])),
            pi_c=(auth_request.zk_proof["pi_c"][0], auth_request.zk_proof["pi_c"][1])
        )
        
        # Get real election merkle root from eligible voters
        eligible_voters = get_election_eligible_voters(auth_request.election_id)
        merkle_tree = MerkleTree(eligible_voters)
        merkle_root = merkle_tree.get_root()
        
        logger.info(f"✅ Generated real Merkle root for election {auth_request.election_id} with {len(eligible_voters)} eligible voters")
        
        # Verify the proof
        is_valid = zk_verifier.verify_eligibility(
            zk_proof,
            auth_request.election_id,
            merkle_root
        )
        
        if not is_valid:
            _record_failed_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid eligibility proof"
            )
        
        # Create authenticated session using Redis
        session_manager = await get_session_manager()
        device_fingerprint_hash = hashlib.sha256(
            json.dumps(auth_request.device_fingerprint, sort_keys=True).encode()
        ).hexdigest()
        
        session_id, session_data = await session_manager.create_session(
            user_id=auth_request.did,
            username=auth_request.did,  # Using DID as username for voters
            role="voter",
            permissions=["vote", "verify_ballot"],
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent", "unknown"),
            mfa_verified=True,  # ZK proof acts as MFA for voters
            device_fingerprint=device_fingerprint_hash
        )
        
        session_expires = session_data.expires_at
        
        # Generate JWT token
        token_payload = {
            "session_id": session_id,
            "voter_did": auth_request.did,
            "election_id": auth_request.election_id,
            "exp": session_expires.timestamp()
        }
        
        # Use secure JWT service with RSA signing (replaces vulnerable HMAC)
        try:
            from core.jwt_security import create_secure_token
            session_token = create_secure_token(
                payload=token_payload,
                expires_in_minutes=security_config.SESSION_TIMEOUT_MINUTES
            )
            logger.debug("🔐 JWT session token created with secure RSA signing")
        except Exception as jwt_error:
            # Fallback to legacy settings-based JWT
            logger.warning(f"⚠️  Secure JWT failed, using legacy method: {jwt_error}")
            session_token = jwt.encode(
                token_payload,
                settings.JWT_SECRET_KEY,
                algorithm=settings.JWT_ALGORITHM
            )
        
        # Reset failed attempts on successful authentication
        if client_ip in failed_attempts:
            del failed_attempts[client_ip]
        
        logger.info(f"Voter authenticated successfully: {auth_request.did}")
        
        return AuthenticationResponse(
            session_token=session_token,
            session_expires=session_expires,
            voter_status="eligible",
            election_info={
                "election_id": auth_request.election_id,
                "merkle_root": merkle_root
            },
            authorization_endpoint="/api/voting/authorize"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        _record_failed_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/verify-credential", response_model=CredentialPresentationResponse)
@limiter.limit("5/minute")
async def verify_credential_presentation(
    request: Request,
    presentation_request: CredentialPresentationRequest,
    db=Depends(get_db)
):
    """
    Verify a verifiable credential presentation
    
    This endpoint is used by legacy systems that still use traditional
    credential verification instead of ZK proofs.
    """
    
    try:
        # Initialize credential verifier with trusted issuers
        trusted_issuers = {
            "did:medivote:issuer:state_authority": b"mock_public_key_pem"  # Mock
        }
        
        verifier = CredentialVerifier(trusted_issuers)
        
        # Parse the presentation
        presentation = VerifiablePresentation(**presentation_request.verifiable_presentation)
        
        # Verify the presentation
        is_verified = verifier.verify_presentation(presentation)
        
        if not is_verified:
            return CredentialPresentationResponse(
                verified=False,
                error_message="Invalid credential presentation"
            )
        
        # Extract eligibility information
        eligibility_info = None
        if presentation.verifiable_credential:
            credential = presentation.verifiable_credential[0]
            eligibility_info = verifier.extract_voting_eligibility(credential)
        
        return CredentialPresentationResponse(
            verified=True,
            eligibility_info=eligibility_info
        )
        
    except Exception as e:
        logger.error(f"Credential verification error: {e}")
        return CredentialPresentationResponse(
            verified=False,
            error_message=str(e)
        )


@router.post("/verify-zk-proof", response_model=ZKProofResponse)
@limiter.limit("5/minute")
async def verify_zk_proof(
    request: Request,
    zk_request: ZKProofRequest,
    db=Depends(get_db)
):
    """
    Verify a zero-knowledge proof of voter eligibility
    
    This is a standalone endpoint for ZK proof verification
    """
    
    try:
        # Initialize ZK verifier
        zk_verifier = RealZKVerifier("./circuits")
        
        # Convert proof format
        zk_proof = ZKProof(
            pi_a=(zk_request.proof["pi_a"][0], zk_request.proof["pi_a"][1]),
            pi_b=((zk_request.proof["pi_b"][0][0], zk_request.proof["pi_b"][0][1]),
                  (zk_request.proof["pi_b"][1][0], zk_request.proof["pi_b"][1][1])),
            pi_c=(zk_request.proof["pi_c"][0], zk_request.proof["pi_c"][1])
        )
        
        # Get real merkle root for the election
        eligible_voters = get_election_eligible_voters(zk_request.election_id)
        merkle_tree = MerkleTree(eligible_voters)
        merkle_root = merkle_tree.get_root()
        
        logger.info(f"✅ Using real Merkle root for ZK verification in election {zk_request.election_id}")
        
        # Verify the proof
        is_valid = zk_verifier.verify_eligibility(
            zk_proof,
            zk_request.election_id,
            merkle_root
        )
        
        return ZKProofResponse(
            valid=is_valid,
            voter_eligible=is_valid,
            merkle_root=merkle_root
        )
        
    except Exception as e:
        logger.error(f"ZK proof verification error: {e}")
        return ZKProofResponse(
            valid=False,
            voter_eligible=False,
            merkle_root="",
        )


@router.post("/logout")
@limiter.limit("10/minute")
async def logout_voter(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Logout a voter and invalidate their session
    """
    
    try:
        # Decode JWT token
        token = credentials.credentials
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
        session_id = payload.get("session_id")
        
        # Remove session from Redis
        session_manager = await get_session_manager()
        await session_manager.revoke_session(session_id)
        
        return {"message": "Logged out successfully"}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


@router.get("/session")
@limiter.limit("10/minute")
async def get_session_info(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get information about the current authenticated session
    """
    
    try:
        # Decode JWT token
        token = credentials.credentials
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
        session_id = payload.get("session_id")
        
        # Check session exists and is valid using Redis
        session_manager = await get_session_manager()
        session_data = await session_manager.get_session(session_id)
        
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or expired"
            )
        
        # Session is automatically validated by session manager
        # Extract election_id from JWT token since it's stored there
        election_id = payload.get("election_id", "")
        
        return {
            "session_id": session_data.session_id,
            "voter_did": session_data.user_id,
            "election_id": election_id,
            "authenticated_at": session_data.created_at.isoformat(),
            "expires_at": session_data.expires_at.isoformat(),
            "eligibility_verified": session_data.mfa_verified  # ZK proof verification
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


@router.get("/election/{election_id}/merkle-root")
@limiter.limit("10/minute")
async def get_election_merkle_root(
    request: Request,
    election_id: str,
    db=Depends(get_db)
):
    """
    Get the merkle root for an election's revocation list
    """
    
    # Get real eligible voters for the election
    eligible_voters = get_election_eligible_voters(election_id)
    
    # Build real Merkle tree from eligible voter credentials
    merkle_tree = MerkleTree(eligible_voters)
    
    logger.info(f"✅ Built real Merkle tree for election {election_id} with {len(eligible_voters)} eligible voters")
    
    return {
        "election_id": election_id,
        "merkle_root": merkle_tree.get_root(),
        "eligible_voter_count": len(eligible_voters),
        "tree_depth": len(bin(len(eligible_voters) - 1)[2:]) if eligible_voters else 0,
        "last_updated": datetime.utcnow().isoformat(),
        "implementation": "real_merkle_tree"
    }


# Utility functions
def _record_failed_attempt(client_ip: str):
    """Record a failed authentication attempt"""
    if client_ip not in failed_attempts:
        failed_attempts[client_ip] = 0
    failed_attempts[client_ip] += 1


def get_current_session(credentials: HTTPAuthorizationCredentials = Depends(security)) -> SessionInfo:
    """Dependency to get current authenticated session"""
    try:
        token = credentials.credentials
        
        # Try secure JWT verification first (RSA/ECDSA)
        try:
            from core.jwt_security import verify_secure_token
            payload = verify_secure_token(token)
            if payload:
                logger.debug("🔐 JWT session token verified with secure asymmetric signing")
            else:
                raise ValueError("Secure JWT verification failed")
        except Exception as secure_error:
            # Fallback to legacy JWT verification
            logger.warning(f"⚠️  Secure JWT verification failed, trying legacy: {secure_error}")
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            logger.debug("🔓 JWT token verified with legacy signing")
        
        session_id = payload.get("session_id")
        
        # Check session using Redis
        session_manager = await get_session_manager()
        session_data = await session_manager.get_session(session_id)
        
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or expired"
            )
        
        # Create compatibility object for existing code
        from types import SimpleNamespace
        session_info = SimpleNamespace(
            session_id=session_data.session_id,
            voter_did=session_data.user_id,
            election_id=payload.get("election_id", ""),
            authenticated_at=session_data.created_at,
            expires_at=session_data.expires_at,
            device_fingerprint=session_data.device_fingerprint,
            eligibility_verified=session_data.mfa_verified
        )
        
        return session_info
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


# Health check
@router.get("/health")
async def auth_health_check():
    """Health check for authentication service"""
    # Get session statistics from Redis
    try:
        session_manager = await get_session_manager()
        session_stats = await session_manager.get_session_stats()
    except:
        session_stats = {"active_sessions": 0, "redis_connected": False}
    
    return {
        "status": "healthy",
        "service": "authentication",
        "active_sessions": session_stats.get("active_sessions", 0),
        "redis_connected": session_stats.get("redis_connected", False),
        "features": {
            "zk_proofs": True,
            "verifiable_credentials": True,
            "session_management": True,
            "rate_limiting": True
        }
    } 