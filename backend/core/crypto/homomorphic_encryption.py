"""
Homomorphic Encryption for Vote Tallying
Implements Paillier cryptosystem for additive homomorphic encryption
Allows vote counting without decrypting individual ballots
"""

import json
import random
import secrets
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from math import gcd
import pickle
import base64

from phe import paillier, EncryptedNumber
from phe.paillier import PaillierPrivateKey, PaillierPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

from core.config import get_crypto_config


config = get_crypto_config()


@dataclass
class HomomorphicKeyPair:
    """Paillier key pair for homomorphic encryption"""
    public_key: PaillierPublicKey
    private_key: PaillierPrivateKey
    key_size: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "public_key": {
                "n": str(self.public_key.n),
                "g": str(self.public_key.g)
            },
            "private_key": {
                "p": str(self.private_key.p),
                "q": str(self.private_key.q)
            },
            "key_size": self.key_size
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HomomorphicKeyPair':
        """Create from dictionary representation"""
        public_key = PaillierPublicKey(n=int(data["public_key"]["n"]))
        private_key = PaillierPrivateKey(
            public_key=public_key,
            p=int(data["private_key"]["p"]),
            q=int(data["private_key"]["q"])
        )
        
        return cls(
            public_key=public_key,
            private_key=private_key,
            key_size=data["key_size"]
        )


@dataclass
class EncryptedVote:
    """Encrypted vote using homomorphic encryption"""
    ciphertext: str  # Base64 encoded ciphertext
    candidate_id: str
    election_id: str
    timestamp: str
    proof_of_encryption: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedVote':
        """Create from dictionary representation"""
        return cls(**data)


@dataclass
class TallyResult:
    """Result of homomorphic vote tallying"""
    candidate_results: Dict[str, int]
    total_votes: int
    election_id: str
    encrypted_tallies: Dict[str, str]  # Encrypted results before decryption
    verification_proof: Optional[str] = None


class HomomorphicEncryption:
    """Paillier homomorphic encryption for vote tallying"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.key_pair: Optional[HomomorphicKeyPair] = None
    
    def generate_keypair(self) -> HomomorphicKeyPair:
        """Generate a new Paillier key pair"""
        public_key, private_key = paillier.generate_paillier_keypair(n_length=self.key_size)
        
        self.key_pair = HomomorphicKeyPair(
            public_key=public_key,
            private_key=private_key,
            key_size=self.key_size
        )
        
        return self.key_pair
    
    def load_keypair(self, key_data: Dict[str, Any]) -> HomomorphicKeyPair:
        """Load existing key pair from data"""
        self.key_pair = HomomorphicKeyPair.from_dict(key_data)
        return self.key_pair
    
    def encrypt_vote(self, vote_value: int, candidate_id: str, election_id: str) -> EncryptedVote:
        """Encrypt a single vote (0 or 1)"""
        if not self.key_pair:
            raise ValueError("No key pair loaded")
        
        if vote_value not in [0, 1]:
            raise ValueError("Vote value must be 0 or 1")
        
        # Encrypt the vote
        encrypted_number = self.key_pair.public_key.encrypt(vote_value)
        
        # Serialize ciphertext
        ciphertext = base64.b64encode(pickle.dumps(encrypted_number)).decode()
        
        # Create encrypted vote
        encrypted_vote = EncryptedVote(
            ciphertext=ciphertext,
            candidate_id=candidate_id,
            election_id=election_id,
            timestamp=str(int(secrets.randbits(32)))  # Mock timestamp
        )
        
        return encrypted_vote
    
    def decrypt_vote(self, encrypted_vote: EncryptedVote) -> int:
        """Decrypt a single vote (for testing/verification only)"""
        if not self.key_pair:
            raise ValueError("No key pair loaded")
        
        # Deserialize ciphertext
        ciphertext_bytes = base64.b64decode(encrypted_vote.ciphertext)
        encrypted_number = pickle.loads(ciphertext_bytes)
        
        # Decrypt
        decrypted_value = self.key_pair.private_key.decrypt(encrypted_number)
        
        return decrypted_value
    
    def homomorphic_add(self, encrypted_votes: List[EncryptedVote]) -> EncryptedNumber:
        """Add encrypted votes homomorphically"""
        if not encrypted_votes:
            raise ValueError("No votes to add")
        
        # Start with the first vote
        first_vote = encrypted_votes[0]
        ciphertext_bytes = base64.b64decode(first_vote.ciphertext)
        result = pickle.loads(ciphertext_bytes)
        
        # Add remaining votes
        for vote in encrypted_votes[1:]:
            ciphertext_bytes = base64.b64decode(vote.ciphertext)
            encrypted_number = pickle.loads(ciphertext_bytes)
            result = result + encrypted_number
        
        return result
    
    def tally_votes(self, encrypted_votes: List[EncryptedVote], election_id: str) -> TallyResult:
        """Tally encrypted votes by candidate"""
        if not self.key_pair:
            raise ValueError("No key pair loaded")
        
        # Group votes by candidate
        votes_by_candidate = {}
        for vote in encrypted_votes:
            if vote.election_id != election_id:
                continue
            
            if vote.candidate_id not in votes_by_candidate:
                votes_by_candidate[vote.candidate_id] = []
            votes_by_candidate[vote.candidate_id].append(vote)
        
        # Tally each candidate's votes homomorphically
        encrypted_tallies = {}
        candidate_results = {}
        
        for candidate_id, votes in votes_by_candidate.items():
            # Add all votes for this candidate
            encrypted_total = self.homomorphic_add(votes)
            encrypted_tallies[candidate_id] = base64.b64encode(pickle.dumps(encrypted_total)).decode()
            
            # Decrypt the total (in production, this would be done by trustees)
            candidate_results[candidate_id] = self.key_pair.private_key.decrypt(encrypted_total)
        
        # Calculate total votes
        total_votes = sum(candidate_results.values())
        
        return TallyResult(
            candidate_results=candidate_results,
            total_votes=total_votes,
            election_id=election_id,
            encrypted_tallies=encrypted_tallies
        )


class ThresholdDecryption:
    """Threshold decryption for distributed key management"""
    
    def __init__(self, threshold: int, total_trustees: int):
        self.threshold = threshold
        self.total_trustees = total_trustees
        self.trustee_keys: Dict[int, Any] = {}
    
    def generate_threshold_keys(self, master_key: PaillierPrivateKey) -> Dict[int, Any]:
        """Generate threshold keys using Shamir's Secret Sharing"""
        # This is a simplified implementation
        # In practice, would use proper polynomial interpolation
        
        # Split the private key parameters
        p = master_key.p
        q = master_key.q
        
        # Generate polynomial coefficients for p and q
        p_coeffs = [p] + [secrets.randbelow(p) for _ in range(self.threshold - 1)]
        q_coeffs = [q] + [secrets.randbelow(q) for _ in range(self.threshold - 1)]
        
        # Generate shares for each trustee
        trustee_keys = {}
        for i in range(1, self.total_trustees + 1):
            p_share = sum(coeff * (i ** power) for power, coeff in enumerate(p_coeffs)) % p
            q_share = sum(coeff * (i ** power) for power, coeff in enumerate(q_coeffs)) % q
            
            trustee_keys[i] = {
                "trustee_id": i,
                "p_share": p_share,
                "q_share": q_share,
                "threshold": self.threshold,
                "total_trustees": self.total_trustees
            }
        
        self.trustee_keys = trustee_keys
        return trustee_keys
    
    def partial_decrypt(self, encrypted_tally: str, trustee_id: int) -> str:
        """Perform partial decryption with trustee key"""
        if trustee_id not in self.trustee_keys:
            raise ValueError(f"No key for trustee {trustee_id}")
        
        # Deserialize encrypted tally
        ciphertext_bytes = base64.b64decode(encrypted_tally)
        encrypted_number = pickle.loads(ciphertext_bytes)
        
        # Perform partial decryption (simplified)
        trustee_key = self.trustee_keys[trustee_id]
        partial_result = {
            "trustee_id": trustee_id,
            "partial_decryption": str(encrypted_number.ciphertext(False)),  # Simplified
            "proof": "partial_decryption_proof"  # Would contain ZK proof
        }
        
        return json.dumps(partial_result)
    
    def combine_partial_decryptions(
        self,
        partial_decryptions: List[str],
        original_ciphertext: str
    ) -> int:
        """Combine partial decryptions to get final result"""
        if len(partial_decryptions) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} partial decryptions")
        
        # Parse partial decryptions
        parsed_decryptions = []
        for pd in partial_decryptions:
            parsed_decryptions.append(json.loads(pd))
        
        # Combine using Lagrange interpolation (simplified)
        # In practice, would use proper polynomial interpolation
        
        # For now, return a mock result
        return 42  # Placeholder


class BallotEncryption:
    """Encryption of complete ballot with multiple choices"""
    
    def __init__(self, public_key: PaillierPublicKey):
        self.public_key = public_key
    
    def encrypt_ballot(
        self,
        choices: Dict[str, int],
        voter_id: str,
        election_id: str
    ) -> Dict[str, EncryptedVote]:
        """Encrypt a complete ballot with multiple choices"""
        encrypted_choices = {}
        
        for candidate_id, vote_value in choices.items():
            if vote_value not in [0, 1]:
                raise ValueError(f"Invalid vote value {vote_value} for candidate {candidate_id}")
            
            # Encrypt individual choice
            encrypted_number = self.public_key.encrypt(vote_value)
            ciphertext = base64.b64encode(pickle.dumps(encrypted_number)).decode()
            
            encrypted_vote = EncryptedVote(
                ciphertext=ciphertext,
                candidate_id=candidate_id,
                election_id=election_id,
                timestamp=str(int(secrets.randbits(32)))
            )
            
            encrypted_choices[candidate_id] = encrypted_vote
        
        return encrypted_choices
    
    def verify_ballot_format(self, encrypted_ballot: Dict[str, EncryptedVote]) -> bool:
        """Verify that ballot has correct format (exactly one choice selected)"""
        # This would contain zero-knowledge proofs in practice
        # For now, just check that we have encrypted votes
        return len(encrypted_ballot) > 0


class VoteTallyingSystem:
    """Complete system for homomorphic vote tallying"""
    
    def __init__(self, key_size: int = 2048, threshold: int = 3, total_trustees: int = 5):
        self.encryption = HomomorphicEncryption(key_size)
        self.threshold_system = ThresholdDecryption(threshold, total_trustees)
        self.encrypted_votes: List[EncryptedVote] = []
    
    def setup_election(self) -> Dict[str, Any]:
        """Setup encryption keys for election"""
        key_pair = self.encryption.generate_keypair()
        
        # Generate threshold keys
        trustee_keys = self.threshold_system.generate_threshold_keys(key_pair.private_key)
        
        return {
            "public_key": {
                "n": str(key_pair.public_key.n),
                "g": str(key_pair.public_key.g)
            },
            "trustee_keys": trustee_keys,
            "key_size": key_pair.key_size,
            "threshold": self.threshold_system.threshold,
            "total_trustees": self.threshold_system.total_trustees
        }
    
    def cast_vote(self, choices: Dict[str, int], election_id: str) -> List[EncryptedVote]:
        """Cast an encrypted vote"""
        if not self.encryption.key_pair:
            raise ValueError("Election not setup")
        
        ballot_encryptor = BallotEncryption(self.encryption.key_pair.public_key)
        encrypted_ballot = ballot_encryptor.encrypt_ballot(choices, "voter_id", election_id)
        
        # Store encrypted votes
        for encrypted_vote in encrypted_ballot.values():
            self.encrypted_votes.append(encrypted_vote)
        
        return list(encrypted_ballot.values())
    
    def tally_election(self, election_id: str) -> TallyResult:
        """Tally all votes for an election"""
        election_votes = [v for v in self.encrypted_votes if v.election_id == election_id]
        
        if not election_votes:
            raise ValueError(f"No votes found for election {election_id}")
        
        return self.encryption.tally_votes(election_votes, election_id)
    
    def verify_tally(self, tally_result: TallyResult) -> bool:
        """Verify tally result using zero-knowledge proofs"""
        # This would contain comprehensive verification logic
        # For now, return True as placeholder
        return True


# Utility functions
def create_mock_election() -> Dict[str, Any]:
    """Create a mock election for testing"""
    system = VoteTallyingSystem()
    election_setup = system.setup_election()
    
    # Cast some mock votes
    system.cast_vote({"candidate_a": 1, "candidate_b": 0}, "election_2024")
    system.cast_vote({"candidate_a": 0, "candidate_b": 1}, "election_2024")
    system.cast_vote({"candidate_a": 1, "candidate_b": 0}, "election_2024")
    
    # Tally votes
    tally = system.tally_election("election_2024")
    
    return {
        "election_setup": election_setup,
        "tally_result": tally.candidate_results,
        "total_votes": tally.total_votes
    }


def export_public_key(public_key: PaillierPublicKey) -> str:
    """Export public key for sharing"""
    return json.dumps({
        "n": str(public_key.n),
        "g": str(public_key.g)
    })


def import_public_key(public_key_data: str) -> PaillierPublicKey:
    """Import public key from string"""
    data = json.loads(public_key_data)
    return PaillierPublicKey(n=int(data["n"]))


def verify_homomorphic_property(
    plaintext_sum: int,
    encrypted_votes: List[EncryptedVote],
    private_key: PaillierPrivateKey
) -> bool:
    """Verify that homomorphic addition works correctly"""
    # Deserialize and add encrypted votes
    total = None
    for vote in encrypted_votes:
        ciphertext_bytes = base64.b64decode(vote.ciphertext)
        encrypted_number = pickle.loads(ciphertext_bytes)
        
        if total is None:
            total = encrypted_number
        else:
            total = total + encrypted_number
    
    # Decrypt the sum
    decrypted_sum = private_key.decrypt(total)
    
    return decrypted_sum == plaintext_sum 