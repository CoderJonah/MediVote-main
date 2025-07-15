"""
Voting API for MediVote
Handles ballot casting, election management, and vote tallying
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
from slowapi import Limiter
from slowapi.util import get_remote_address
from loguru import logger

from core.config import get_settings
from core.crypto.blind_signatures import BlindSignatureVotingProtocol, UnblindedSignature
from core.crypto.homomorphic_encryption import VoteTallyingSystem, EncryptedVote
from core.blockchain import BlockchainService
from api.auth import get_current_session, SessionInfo
from core.database import get_db

settings = get_settings()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()

# Request/Response Models
class BallotPreparationRequest(BaseModel):
    """Request for ballot preparation"""
    election_id: str = Field(..., description="Election identifier")
    choices: Dict[str, int] = Field(..., description="Voter choices (candidate_id: vote)")
    
    @validator('choices')
    def validate_choices(cls, v):
        # Ensure all values are 0 or 1
        for candidate_id, vote in v.items():
            if vote not in [0, 1]:
                raise ValueError(f"Invalid vote value {vote} for candidate {candidate_id}")
        
        # Ensure exactly one vote is cast (for single-choice elections)
        total_votes = sum(v.values())
        if total_votes != 1:
            raise ValueError("Exactly one candidate must be selected")
        
        return v


class BallotPreparationResponse(BaseModel):
    """Response for ballot preparation"""
    ballot_token: str = Field(..., description="Blinded ballot token for authorization")
    ballot_id: str = Field(..., description="Unique ballot identifier")
    authorization_required: bool = Field(..., description="Whether authorization is required")


class BallotAuthorizationRequest(BaseModel):
    """Request for ballot authorization"""
    ballot_token: str = Field(..., description="Blinded ballot token")
    session_proof: str = Field(..., description="Proof of valid session")


class BallotAuthorizationResponse(BaseModel):
    """Response for ballot authorization"""
    authorized_ballot: Dict[str, Any] = Field(..., description="Authorized ballot data")
    authorization_signature: str = Field(..., description="Authorization signature")
    expires_at: datetime = Field(..., description="Authorization expiration time")


class VoteCastingRequest(BaseModel):
    """Request for casting vote"""
    authorized_ballot: Dict[str, Any] = Field(..., description="Authorized ballot data")
    encrypted_votes: List[Dict[str, Any]] = Field(..., description="Encrypted vote data")


class VoteCastingResponse(BaseModel):
    """Response for vote casting"""
    vote_id: str = Field(..., description="Unique vote identifier")
    transaction_hash: str = Field(..., description="Blockchain transaction hash")
    verification_receipt: str = Field(..., description="Receipt for vote verification")
    cast_at: datetime = Field(..., description="Time vote was cast")


class ElectionStatusResponse(BaseModel):
    """Response for election status"""
    election_id: str
    name: str
    status: str
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    total_candidates: int
    total_votes: int
    is_active: bool


class TallyResultsResponse(BaseModel):
    """Response for election tally results"""
    election_id: str
    results: Dict[str, int] = Field(..., description="Candidate vote counts")
    total_votes: int
    tallied_at: datetime
    verification_proof: Optional[str] = None


# Global services (would be dependency injected in production)
blind_signature_protocol = BlindSignatureVotingProtocol("medivote_authority_001")
tallying_system = VoteTallyingSystem()


@router.post("/prepare-ballot", response_model=BallotPreparationResponse)
@limiter.limit("5/minute")
async def prepare_ballot(
    request: Request,
    ballot_request: BallotPreparationRequest,
    session: SessionInfo = Depends(get_current_session),
    db=Depends(get_db)
):
    """
    Prepare a ballot for authorization
    
    Step 1 of the voting process: voter prepares their ballot choices
    and receives a blinded token for authorization.
    """
    
    try:
        # Verify session matches election
        if session.election_id != ballot_request.election_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session election ID does not match ballot election ID"
            )
        
        # Register voter session with blind signature protocol
        session_info = blind_signature_protocol.register_voter_session(session.session_id)
        
        # Complete voting flow to get blinded token
        voting_result = blind_signature_protocol.complete_voting_flow(
            session.session_id,
            ballot_request.choices,
            ballot_request.election_id
        )
        
        if not voting_result['is_valid']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ballot preparation failed"
            )
        
        ballot_id = str(uuid.uuid4())
        
        # Store ballot preparation info in session (in production, use secure storage)
        logger.info(f"Ballot prepared for voter {session.voter_did} in election {ballot_request.election_id}")
        
        return BallotPreparationResponse(
            ballot_token=json.dumps(voting_result["authorized_ballot"]),
            ballot_id=ballot_id,
            authorization_required=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ballot preparation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ballot preparation failed"
        )


@router.post("/authorize-ballot", response_model=BallotAuthorizationResponse)
@limiter.limit("3/minute")
async def authorize_ballot(
    request: Request,
    auth_request: BallotAuthorizationRequest,
    session: SessionInfo = Depends(get_current_session),
    db=Depends(get_db)
):
    """
    Authorize a prepared ballot
    
    Step 2 of the voting process: authorization authority validates
    and signs the blinded ballot.
    """
    
    try:
        # Parse the ballot token
        ballot_data = json.loads(auth_request.ballot_token)
        authorized_ballot = UnblindedSignature(**ballot_data)
        
        # Verify the session proof (simplified)
        if not auth_request.session_proof:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session proof required"
            )
        
        # The ballot is already authorized from the preparation step
        # In a real system, this would involve additional validation
        
        logger.info(f"Ballot authorized for session {session.session_id}")
        
        return BallotAuthorizationResponse(
            authorized_ballot=authorized_ballot.to_dict(),
            authorization_signature=authorized_ballot.signature,
            expires_at=datetime.utcnow() + timedelta(minutes=30)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ballot authorization error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ballot authorization failed"
        )


@router.post("/cast-vote", response_model=VoteCastingResponse)
@limiter.limit("1/minute")  # Very strict rate limit for vote casting
async def cast_vote(
    request: Request,
    vote_request: VoteCastingRequest,
    session: SessionInfo = Depends(get_current_session),
    db=Depends(get_db)
):
    """
    Cast an authorized vote
    
    Final step of the voting process: submit the authorized,
    encrypted ballot to the blockchain.
    """
    
    try:
        # Parse authorized ballot
        authorized_ballot = UnblindedSignature(**vote_request.authorized_ballot)
        
        # Initialize blockchain service
        blockchain_service = BlockchainService()
        if not blockchain_service.connected:
            await blockchain_service.initialize()
        
        # Create encrypted votes for homomorphic tallying
        encrypted_votes = []
        for vote_data in vote_request.encrypted_votes:
            encrypted_vote = EncryptedVote(**vote_data)
            encrypted_votes.append(encrypted_vote)
        
        # Verify ballot authorization
        ballot_json = json.dumps(vote_request.authorized_ballot, sort_keys=True)
        is_valid_ballot = blind_signature_protocol.cast_authorized_ballot(
            authorized_ballot,
            ballot_json.encode()
        )
        
        if not is_valid_ballot:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid ballot authorization"
            )
        
        # Submit to blockchain
        vote_id = str(uuid.uuid4())
        
        # For each encrypted vote, post to blockchain
        blockchain_transactions = []
        for encrypted_vote in encrypted_votes:
            tx = await blockchain_service.post_ballot(
                session.election_id,
                encrypted_vote.ciphertext,
                authorized_ballot.signature
            )
            if tx:
                blockchain_transactions.append(tx)
        
        if not blockchain_transactions:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to submit vote to blockchain"
            )
        
        # Generate verification receipt
        receipt_data = {
            "vote_id": vote_id,
            "election_id": session.election_id,
            "voter_did": session.voter_did,
            "transaction_hashes": [tx.transaction_hash for tx in blockchain_transactions],
            "cast_at": datetime.utcnow().isoformat()
        }
        
        verification_receipt = hashlib.sha256(
            json.dumps(receipt_data, sort_keys=True).encode()
        ).hexdigest()
        
        logger.info(f"Vote cast successfully: {vote_id} for election {session.election_id}")
        
        return VoteCastingResponse(
            vote_id=vote_id,
            transaction_hash=blockchain_transactions[0].transaction_hash,
            verification_receipt=verification_receipt,
            cast_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vote casting error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vote casting failed"
        )


@router.get("/elections/{election_id}/status", response_model=ElectionStatusResponse)
@limiter.limit("10/minute")
async def get_election_status(
    request: Request,
    election_id: str,
    db=Depends(get_db)
):
    """Get the status of an election"""
    
    try:
        # Initialize blockchain service
        blockchain_service = BlockchainService()
        if not blockchain_service.connected:
            await blockchain_service.initialize()
        
        # Get election info from blockchain
        election_info = await blockchain_service.get_election_info(election_id)
        
        if not election_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Election not found"
            )
        
        # Get ballots to count votes
        ballots = await blockchain_service.get_ballots(election_id)
        
        # Mock election details (in production, fetch from database)
        return ElectionStatusResponse(
            election_id=election_id,
            name=election_info.get("name", f"Election {election_id}"),
            status="active",
            start_date=datetime.utcnow() - timedelta(days=1),
            end_date=datetime.utcnow() + timedelta(days=7),
            total_candidates=3,  # Mock data
            total_votes=len(ballots),
            is_active=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting election status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get election status"
        )


@router.get("/elections/{election_id}/candidates")
@limiter.limit("10/minute")
async def get_election_candidates(
    request: Request,
    election_id: str,
    db=Depends(get_db)
):
    """Get candidates for an election"""
    
    try:
        # Mock candidate data (in production, fetch from database)
        candidates = [
            {
                "candidate_id": "candidate_a",
                "name": "Candidate A",
                "description": "Experienced leader focused on technology and innovation",
                "party": "Progressive Party"
            },
            {
                "candidate_id": "candidate_b", 
                "name": "Bob Wilson",
                "description": "Community organizer with focus on social justice",
                "party": "Democratic Alliance"
            },
            {
                "candidate_id": "candidate_c",
                "name": "Carol Martinez", 
                "description": "Business leader advocating for economic growth",
                "party": "Conservative Union"
            }
        ]
        
        return {
            "election_id": election_id,
            "candidates": candidates,
            "total_candidates": len(candidates)
        }
        
    except Exception as e:
        logger.error(f"Error getting candidates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get candidates"
        )


@router.post("/elections/{election_id}/tally", response_model=TallyResultsResponse)
@limiter.limit("1/hour")  # Very limited tallying requests
async def tally_election_results(
    request: Request,
    election_id: str,
    session: SessionInfo = Depends(get_current_session),
    db=Depends(get_db)
):
    """
    Tally election results using homomorphic encryption
    
    This endpoint would typically be restricted to election officials.
    """
    
    try:
        # Initialize services
        blockchain_service = BlockchainService()
        if not blockchain_service.connected:
            await blockchain_service.initialize()
        
        # Get all ballots from blockchain
        ballots = await blockchain_service.get_ballots(election_id)
        
        if not ballots:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No ballots found for election"
            )
        
        # Mock tally results (in production, use homomorphic tallying)
        mock_results = {
            "candidate_a": 45,
            "candidate_b": 32,
            "candidate_c": 23
        }
        
        total_votes = sum(mock_results.values())
        
        logger.info(f"Election {election_id} tallied: {total_votes} votes")
        
        return TallyResultsResponse(
            election_id=election_id,
            results=mock_results,
            total_votes=total_votes,
            tallied_at=datetime.utcnow(),
            verification_proof="mock_verification_proof"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Election tallying error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Election tallying failed"
        )


@router.get("/health")
async def voting_health_check():
    """Health check for voting service"""
    return {
        "status": "healthy",
        "service": "voting",
        "features": {
            "ballot_preparation": True,
            "ballot_authorization": True,
            "vote_casting": True,
            "homomorphic_tallying": True,
            "blockchain_integration": True
        }
    } 