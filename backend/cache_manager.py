"""
MediVote Secure Cache Manager
Handles encrypted vote persistence between backend → cache → blockchain
"""

import json
import os
import asyncio
import hashlib
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Import security services
try:
    from security_service import encryption_service
except ImportError:
    # Fallback for when running from different directory
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from security_service import encryption_service

logger = logging.getLogger(__name__)

@dataclass
class CachedVote:
    """Cached vote structure"""
    vote_id: str
    ballot_id: str
    choice: str
    voter_id: str
    timestamp: str
    vote_hash: str
    receipt_id: str
    verification_code: str
    verified: bool = True
    blockchain_hash: Optional[str] = None
    blockchain_block: Optional[int] = None
    cached_at: Optional[str] = None
    synced_to_blockchain: bool = False

@dataclass
class CachedBallot:
    """Cached ballot structure"""
    ballot_id: str
    title: str
    description: str
    candidates: List[Dict[str, str]]
    votes_count: int = 0
    created_at: Optional[str] = None
    cached_at: Optional[str] = None

class VoteCacheManager:
    """Manages vote and ballot caching with blockchain synchronization"""
    
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        # Cache files
        self.votes_cache_file = self.cache_dir / "votes.json"
        self.ballots_cache_file = self.cache_dir / "ballots.json"
        self.voters_cache_file = self.cache_dir / "voters.json"
        self.sync_status_file = self.cache_dir / "sync_status.json"
        
        # In-memory cache
        self.votes_cache: Dict[str, CachedVote] = {}
        self.ballots_cache: Dict[str, CachedBallot] = {}
        self.voters_cache: Dict[str, Dict[str, Any]] = {} 
        self.sync_status = {"last_sync": None, "pending_votes": []}
        
        # Load existing cache on initialization
        self._load_cache()
        
        logger.info(f"Cache Manager initialized with {len(self.votes_cache)} votes, {len(self.ballots_cache)} ballots")
    
    def _load_cache(self):
        """Load and decrypt cache from files"""
        try:
            # Load votes (DECRYPT)
            if self.votes_cache_file.exists():
                with open(self.votes_cache_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    data = json.loads(decrypted_data)
                    self.votes_cache = {
                        vote_id: CachedVote(**vote_data)
                        for vote_id, vote_data in data.items()
                    }
                    logger.info(f"🔓 Loaded {len(self.votes_cache)} encrypted votes from cache")
                except Exception as decrypt_error:
                    logger.warning(f"Could not decrypt votes cache, starting fresh: {decrypt_error}")
                    self.votes_cache = {}
            
            # Load ballots (DECRYPT)
            if self.ballots_cache_file.exists():
                with open(self.ballots_cache_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    data = json.loads(decrypted_data)
                    self.ballots_cache = {
                        ballot_id: CachedBallot(**ballot_data)
                        for ballot_id, ballot_data in data.items()
                    }
                    logger.info(f"🔓 Loaded {len(self.ballots_cache)} encrypted ballots from cache")
                except Exception as decrypt_error:
                    logger.warning(f"Could not decrypt ballots cache, starting fresh: {decrypt_error}")
                    self.ballots_cache = {}
            
            # Load voters (DECRYPT)
            if self.voters_cache_file.exists():
                with open(self.voters_cache_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    self.voters_cache = json.loads(decrypted_data)
                    logger.info(f"🔓 Loaded {len(self.voters_cache)} encrypted voters from cache")
                except Exception as decrypt_error:
                    logger.warning(f"Could not decrypt voters cache, starting fresh: {decrypt_error}")
                    self.voters_cache = {}
            
            # Load sync status (DECRYPT)
            if self.sync_status_file.exists():
                with open(self.sync_status_file, 'r') as f:
                    encrypted_data = f.read()
                try:
                    decrypted_data = encryption_service.decrypt_data(encrypted_data)
                    self.sync_status = json.loads(decrypted_data)
                except Exception as decrypt_error:
                    logger.warning(f"Could not decrypt sync status, starting fresh: {decrypt_error}")
                    self.sync_status = {"last_sync": None, "pending_votes": []}
                    
        except Exception as e:
            logger.error(f"Error loading encrypted cache: {e}")
            # Initialize empty cache on error
            self.votes_cache = {}
            self.ballots_cache = {}
            self.voters_cache = {}
            self.sync_status = {"last_sync": None, "pending_votes": []}
    
    def _save_cache(self):
        """Save encrypted cache to files"""
        try:
            # Save votes (ENCRYPTED)
            votes_data = {
                vote_id: asdict(vote)
                for vote_id, vote in self.votes_cache.items()
            }
            encrypted_votes = encryption_service.encrypt_data(json.dumps(votes_data))
            with open(self.votes_cache_file, 'w') as f:
                f.write(encrypted_votes)
            
            # Save ballots (ENCRYPTED)
            ballots_data = {
                ballot_id: asdict(ballot)
                for ballot_id, ballot in self.ballots_cache.items()
            }
            encrypted_ballots = encryption_service.encrypt_data(json.dumps(ballots_data))
            with open(self.ballots_cache_file, 'w') as f:
                f.write(encrypted_ballots)
            
            # Save voters (ENCRYPTED)
            encrypted_voters = encryption_service.encrypt_data(json.dumps(self.voters_cache))
            with open(self.voters_cache_file, 'w') as f:
                f.write(encrypted_voters)
            
            # Save sync status (ENCRYPTED)
            encrypted_sync = encryption_service.encrypt_data(json.dumps(self.sync_status))
            with open(self.sync_status_file, 'w') as f:
                f.write(encrypted_sync)
                
            logger.debug("🔒 Encrypted cache saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving encrypted cache: {e}")
    
    # ============ BACKEND → CACHE METHODS ============
    
    def cache_vote(self, vote_data: Dict[str, Any]) -> CachedVote:
        """Cache a vote from backend (Step 1: Backend → Cache)"""
        try:
            # Create cached vote
            cached_vote = CachedVote(
                vote_id=vote_data["id"],
                ballot_id=vote_data["ballot_id"],
                choice=vote_data["choice"],
                voter_id=vote_data.get("voter_id", "unknown"),
                timestamp=vote_data["timestamp"],
                vote_hash=vote_data["vote_hash"],
                receipt_id=vote_data["receipt_id"],
                verification_code=vote_data["verification_code"],
                verified=vote_data.get("verified", True),
                cached_at=datetime.now().isoformat(),
                synced_to_blockchain=False
            )
            
            # Store in cache
            self.votes_cache[cached_vote.vote_id] = cached_vote
            
            # Add to pending sync
            if cached_vote.vote_id not in self.sync_status["pending_votes"]:
                self.sync_status["pending_votes"].append(cached_vote.vote_id)
            
            # Save cache
            self._save_cache()
            
            logger.info(f"Cached vote: {cached_vote.vote_id} for ballot {cached_vote.ballot_id}")
            return cached_vote
            
        except Exception as e:
            logger.error(f"Error caching vote: {e}")
            raise
    
    def cache_ballot(self, ballot_data: Dict[str, Any]) -> CachedBallot:
        """Cache a ballot from backend"""
        try:
            cached_ballot = CachedBallot(
                ballot_id=ballot_data["id"],
                title=ballot_data["title"],
                description=ballot_data["description"],
                candidates=ballot_data["candidates"],
                votes_count=ballot_data.get("votes_count", 0),
                created_at=ballot_data.get("created_at"),
                cached_at=datetime.now().isoformat()
            )
            
            self.ballots_cache[cached_ballot.ballot_id] = cached_ballot
            self._save_cache()
            
            logger.info(f"Cached ballot: {cached_ballot.ballot_id}")
            return cached_ballot
            
        except Exception as e:
            logger.error(f"Error caching ballot: {e}")
            raise
    
    def cache_voter(self, voter_id: str, voter_data: Dict[str, Any]):
        """Cache voter data from backend"""
        try:
            self.voters_cache[voter_id] = {
                **voter_data,
                "cached_at": datetime.now().isoformat()
            }
            self._save_cache()
            logger.info(f"Cached voter: {voter_id}")
            
        except Exception as e:
            logger.error(f"Error caching voter: {e}")
    
    # ============ CACHE → BACKEND METHODS ============
    
    def restore_votes_to_backend(self) -> Dict[str, Dict[str, Any]]:
        """Restore votes from cache to backend format (Step 3: Cache → Backend)"""
        try:
            backend_votes = {}
            
            for vote_id, cached_vote in self.votes_cache.items():
                backend_votes[vote_id] = {
                    "id": cached_vote.vote_id,
                    "ballot_id": cached_vote.ballot_id,
                    "choice": cached_vote.choice,
                    "voter_id": cached_vote.voter_id,
                    "timestamp": cached_vote.timestamp,
                    "verified": cached_vote.verified,
                    "vote_hash": cached_vote.vote_hash,
                    "receipt_id": cached_vote.receipt_id,
                    "verification_code": cached_vote.verification_code,
                    "blockchain_hash": cached_vote.blockchain_hash,
                    "blockchain_block": cached_vote.blockchain_block
                }
            
            logger.info(f"Restored {len(backend_votes)} votes to backend format")
            return backend_votes
            
        except Exception as e:
            logger.error(f"Error restoring votes to backend: {e}")
            return {}
    
    def restore_ballots_to_backend(self) -> Dict[str, Dict[str, Any]]:
        """Restore ballots from cache to backend format"""
        try:
            backend_ballots = {}
            
            for ballot_id, cached_ballot in self.ballots_cache.items():
                backend_ballots[ballot_id] = {
                    "id": cached_ballot.ballot_id,
                    "title": cached_ballot.title,
                    "description": cached_ballot.description,
                    "candidates": cached_ballot.candidates,
                    "votes_count": cached_ballot.votes_count,
                    "created_at": cached_ballot.created_at
                }
            
            logger.info(f"Restored {len(backend_ballots)} ballots to backend format")
            return backend_ballots
            
        except Exception as e:
            logger.error(f"Error restoring ballots to backend: {e}")
            return {}
    
    def restore_voters_to_backend(self) -> Dict[str, Dict[str, Any]]:
        """Restore voters from cache to backend format"""
        try:
            # Remove cached_at field for backend compatibility
            backend_voters = {}
            for voter_id, voter_data in self.voters_cache.items():
                backend_voters[voter_id] = {
                    k: v for k, v in voter_data.items() 
                    if k != "cached_at"
                }
            
            logger.info(f"Restored {len(backend_voters)} voters to backend format")
            return backend_voters
            
        except Exception as e:
            logger.error(f"Error restoring voters to backend: {e}")
            return {}
    
    # ============ CACHE ↔ BLOCKCHAIN METHODS ============
    
    async def sync_to_blockchain(self, blockchain_service) -> int:
        """Sync pending votes to blockchain (Step 2: Cache → Blockchain)"""
        synced_count = 0
        
        try:
            if not blockchain_service:
                logger.warning("No blockchain service available for sync")
                return 0
            
            pending_votes = self.sync_status["pending_votes"].copy()
            
            for vote_id in pending_votes:
                if vote_id not in self.votes_cache:
                    # Remove invalid vote ID from pending
                    self.sync_status["pending_votes"].remove(vote_id)
                    continue
                
                cached_vote = self.votes_cache[vote_id]
                
                if cached_vote.synced_to_blockchain:
                    # Remove already synced vote from pending
                    self.sync_status["pending_votes"].remove(vote_id)
                    continue
                
                try:
                    # Post to blockchain
                    tx = await blockchain_service.post_ballot(
                        cached_vote.ballot_id,
                        json.dumps({
                            "vote_id": cached_vote.vote_id,
                            "choice": cached_vote.choice,
                            "timestamp": cached_vote.timestamp,
                            "vote_hash": cached_vote.vote_hash
                        }),
                        f"signature_{cached_vote.vote_hash[:16]}"
                    )
                    
                    if tx:
                        # Update cached vote with blockchain info
                        cached_vote.blockchain_hash = tx.transaction_hash
                        cached_vote.blockchain_block = tx.block_number
                        cached_vote.synced_to_blockchain = True
                        
                        # Remove from pending
                        self.sync_status["pending_votes"].remove(vote_id)
                        synced_count += 1
                        
                        logger.info(f"Synced vote {vote_id} to blockchain: {tx.transaction_hash}")
                    else:
                        logger.warning(f"Failed to sync vote {vote_id} to blockchain")
                        
                except Exception as e:
                    logger.error(f"Error syncing vote {vote_id} to blockchain: {e}")
            
            # Update sync status
            self.sync_status["last_sync"] = datetime.now().isoformat()
            self._save_cache()
            
            logger.info(f"Synced {synced_count} votes to blockchain")
            return synced_count
            
        except Exception as e:
            logger.error(f"Error during blockchain sync: {e}")
            return synced_count
    
    async def restore_from_blockchain(self, blockchain_service) -> int:
        """Restore votes from blockchain to cache (Step 1: Blockchain → Cache)"""
        restored_count = 0
        
        try:
            if not blockchain_service:
                logger.warning("No blockchain service available for restore")
                return 0
            
            # Get all ballots from blockchain
            all_ballots = []
            for ballot_id in self.ballots_cache:
                try:
                    ballots = await blockchain_service.get_ballots(ballot_id)
                    all_ballots.extend(ballots)
                except Exception as e:
                    logger.warning(f"Could not get ballots for {ballot_id}: {e}")
            
            # Process blockchain votes
            for ballot_tx in all_ballots:
                try:
                    if ballot_tx.get("type") != "post_ballot":
                        continue
                    
                    # Parse encrypted vote data
                    encrypted_vote = ballot_tx.get("encrypted_vote", "{}")
                    
                    try:
                        vote_data = json.loads(encrypted_vote)
                    except:
                        # Skip invalid vote data
                        continue
                    
                    vote_id = vote_data.get("vote_id")
                    if not vote_id:
                        continue
                    
                    # Check if we already have this vote
                    if vote_id in self.votes_cache:
                        # Update blockchain info if needed
                        cached_vote = self.votes_cache[vote_id]
                        if not cached_vote.blockchain_hash:
                            cached_vote.blockchain_hash = ballot_tx.get("hash")
                            cached_vote.synced_to_blockchain = True
                        continue
                    
                    # Create new cached vote from blockchain data
                    cached_vote = CachedVote(
                        vote_id=vote_id,
                        ballot_id=ballot_tx.get("election_id", "unknown"),
                        choice=vote_data.get("choice", "unknown"),
                        voter_id="blockchain_restore",
                        timestamp=vote_data.get("timestamp", datetime.now().isoformat()),
                        vote_hash=vote_data.get("vote_hash", "unknown"),
                        receipt_id=f"receipt_{vote_id}",
                        verification_code=f"verify_{vote_id}",
                        verified=True,
                        blockchain_hash=ballot_tx.get("hash"),
                        blockchain_block=ballot_tx.get("block_number", 0),
                        cached_at=datetime.now().isoformat(),
                        synced_to_blockchain=True
                    )
                    
                    self.votes_cache[vote_id] = cached_vote
                    restored_count += 1
                    
                    logger.info(f"Restored vote {vote_id} from blockchain")
                    
                except Exception as e:
                    logger.warning(f"Error processing blockchain vote: {e}")
            
            # Update ballot vote counts based on restored votes
            self._update_ballot_counts()
            
            # Save cache
            self._save_cache()
            
            logger.info(f"Restored {restored_count} votes from blockchain")
            return restored_count
            
        except Exception as e:
            logger.error(f"Error restoring from blockchain: {e}")
            return restored_count
    
    def _update_ballot_counts(self):
        """Update ballot vote counts based on cached votes"""
        try:
            # Reset counts
            for ballot in self.ballots_cache.values():
                ballot.votes_count = 0
            
            # Count votes
            for vote in self.votes_cache.values():
                if vote.ballot_id in self.ballots_cache:
                    self.ballots_cache[vote.ballot_id].votes_count += 1
            
            logger.debug("Updated ballot vote counts")
            
        except Exception as e:
            logger.error(f"Error updating ballot counts: {e}")
    
    # ============ UTILITY METHODS ============
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get synchronization status"""
        return {
            "total_votes": len(self.votes_cache),
            "synced_votes": len([v for v in self.votes_cache.values() if v.synced_to_blockchain]),
            "pending_votes": len(self.sync_status["pending_votes"]),
            "last_sync": self.sync_status["last_sync"],
            "cache_health": "healthy" if len(self.votes_cache) > 0 else "empty"
        }
    
    def clear_cache(self):
        """Clear all cache data (use with caution!)"""
        self.votes_cache.clear()
        self.ballots_cache.clear()  
        self.voters_cache.clear()
        self.sync_status = {"last_sync": None, "pending_votes": []}
        self._save_cache()
        logger.warning("Cache cleared!")
    
    def get_vote_by_receipt(self, receipt_id: str) -> Optional[CachedVote]:
        """Find vote by receipt ID"""
        for vote in self.votes_cache.values():
            if vote.receipt_id == receipt_id:
                return vote
        return None
    
    def get_votes_for_ballot(self, ballot_id: str) -> List[CachedVote]:
        """Get all votes for a specific ballot"""
        return [vote for vote in self.votes_cache.values() if vote.ballot_id == ballot_id]

# Global cache manager instance
cache_manager = VoteCacheManager() 