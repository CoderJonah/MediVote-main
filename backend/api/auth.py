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
from core.crypto.zero_knowledge import VoterEligibilityProof, ZKProof, MerkleTree
from core.security import SecurityService, DeviceFingerprint
from core.database import get_db

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


# In-memory session storage (in production, use Redis or database)
active_sessions: Dict[str, SessionInfo] = {}
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
        zk_verifier = VoterEligibilityProof("./circuits")
        
        # Verify zero-knowledge proof
        zk_proof = ZKProof(
            pi_a=(auth_request.zk_proof["pi_a"][0], auth_request.zk_proof["pi_a"][1]),
            pi_b=((auth_request.zk_proof["pi_b"][0][0], auth_request.zk_proof["pi_b"][0][1]),
                  (auth_request.zk_proof["pi_b"][1][0], auth_request.zk_proof["pi_b"][1][1])),
            pi_c=(auth_request.zk_proof["pi_c"][0], auth_request.zk_proof["pi_c"][1])
        )
        
        # Get election merkle root (mock for now)
        merkle_root = "mock_merkle_root_" + auth_request.election_id
        
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
        
        # Create authenticated session
        session_id = str(uuid.uuid4())
        session_expires = datetime.utcnow() + timedelta(minutes=security_config.SESSION_TIMEOUT_MINUTES)
        
        session_info = SessionInfo(
            session_id=session_id,
            voter_did=auth_request.did,
            election_id=auth_request.election_id,
            authenticated_at=datetime.utcnow(),
            expires_at=session_expires,
            device_fingerprint=hashlib.sha256(
                json.dumps(auth_request.device_fingerprint, sort_keys=True).encode()
            ).hexdigest(),
            eligibility_verified=True
        )
        
        active_sessions[session_id] = session_info
        
        # Generate JWT token
        token_payload = {
            "session_id": session_id,
            "voter_did": auth_request.did,
            "election_id": auth_request.election_id,
            "exp": session_expires.timestamp()
        }
        
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
        zk_verifier = VoterEligibilityProof("./circuits")
        
        # Convert proof format
        zk_proof = ZKProof(
            pi_a=(zk_request.proof["pi_a"][0], zk_request.proof["pi_a"][1]),
            pi_b=((zk_request.proof["pi_b"][0][0], zk_request.proof["pi_b"][0][1]),
                  (zk_request.proof["pi_b"][1][0], zk_request.proof["pi_b"][1][1])),
            pi_c=(zk_request.proof["pi_c"][0], zk_request.proof["pi_c"][1])
        )
        
        # Get merkle root for the election
        merkle_root = "mock_merkle_root_" + zk_request.election_id
        
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
        
        # Remove session
        if session_id in active_sessions:
            del active_sessions[session_id]
        
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
        
        # Check session exists and is valid
        if session_id not in active_sessions:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found"
            )
        
        session_info = active_sessions[session_id]
        
        # Check expiration
        if datetime.utcnow() > session_info.expires_at:
            del active_sessions[session_id]
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired"
            )
        
        return {
            "session_id": session_info.session_id,
            "voter_did": session_info.voter_did,
            "election_id": session_info.election_id,
            "authenticated_at": session_info.authenticated_at.isoformat(),
            "expires_at": session_info.expires_at.isoformat(),
            "eligibility_verified": session_info.eligibility_verified
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
    
    # In a real implementation, this would query the database
    # For now, return a mock merkle root
    mock_credentials = [
        f"credential_hash_{i}" for i in range(10)
    ]
    
    merkle_tree = MerkleTree(mock_credentials)
    
    return {
        "election_id": election_id,
        "merkle_root": merkle_tree.get_root(),
        "credential_count": len(mock_credentials),
        "last_updated": datetime.utcnow().isoformat()
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
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
        session_id = payload.get("session_id")
        
        if session_id not in active_sessions:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found"
            )
        
        session_info = active_sessions[session_id]
        
        if datetime.utcnow() > session_info.expires_at:
            del active_sessions[session_id]
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired"
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
    return {
        "status": "healthy",
        "service": "authentication",
        "active_sessions": len(active_sessions),
        "features": {
            "zk_proofs": True,
            "verifiable_credentials": True,
            "session_management": True,
            "rate_limiting": True
        }
    } 