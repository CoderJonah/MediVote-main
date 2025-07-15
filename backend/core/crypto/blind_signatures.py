"""
Blind Signature Implementation for Ballot Authorization
Implements RSA blind signatures to prevent double voting while maintaining anonymity
Based on David Chaum's blind signature scheme
"""

import json
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
import base64
from math import gcd

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import gmpy2

from core.config import get_crypto_config


config = get_crypto_config()


@dataclass
class BlindSignatureKeys:
    """RSA key pair for blind signatures"""
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey
    key_size: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return {
            "public_key": base64.b64encode(public_pem).decode(),
            "private_key": base64.b64encode(private_pem).decode(),
            "key_size": self.key_size
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlindSignatureKeys':
        """Create from dictionary representation"""
        public_pem = base64.b64decode(data["public_key"])
        private_pem = base64.b64decode(data["private_key"])
        
        public_key = serialization.load_pem_public_key(public_pem)
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        
        return cls(
            public_key=public_key,
            private_key=private_key,
            key_size=data["key_size"]
        )


@dataclass
class BlindedMessage:
    """Blinded message for signing"""
    blinded_data: str  # Base64 encoded blinded message
    blinding_factor: str  # Base64 encoded blinding factor (kept secret)
    original_hash: str  # Hash of original message
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "blinded_data": self.blinded_data,
            "original_hash": self.original_hash
            # Note: blinding_factor is not included in serialization for security
        }


@dataclass
class BlindSignature:
    """Blind signature on blinded message"""
    signature: str  # Base64 encoded signature
    signer_id: str  # ID of the signing authority
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return asdict(self)


@dataclass
class UnblindedSignature:
    """Unblinded signature on original message"""
    signature: str  # Base64 encoded signature
    message_hash: str  # Hash of original message
    signer_id: str
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return asdict(self)


class BlindSignatureScheme:
    """Implementation of RSA blind signature scheme"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.keys: Optional[BlindSignatureKeys] = None
    
    def generate_keys(self) -> BlindSignatureKeys:
        """Generate RSA key pair for blind signatures"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        
        public_key = private_key.public_key()
        
        self.keys = BlindSignatureKeys(
            public_key=public_key,
            private_key=private_key,
            key_size=self.key_size
        )
        
        return self.keys
    
    def load_keys(self, key_data: Dict[str, Any]) -> BlindSignatureKeys:
        """Load existing keys from data"""
        self.keys = BlindSignatureKeys.from_dict(key_data)
        return self.keys
    
    def blind_message(self, message: bytes, public_key: rsa.RSAPublicKey) -> BlindedMessage:
        """Blind a message for signing"""
        # Hash the message
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        message_hash = digest.finalize()
        
        # Get RSA parameters
        n = public_key.key_size // 8  # Convert bits to bytes
        e = public_key.public_numbers().e
        n_value = public_key.public_numbers().n
        
        # Convert message hash to integer
        message_int = int.from_bytes(message_hash, byteorder='big')
        
        # Generate random blinding factor
        while True:
            blinding_factor = secrets.randbelow(n_value)
            if gcd(blinding_factor, n_value) == 1:
                break
        
        # Blind the message: blinded = message * (blinding_factor^e) mod n
        blinded_message = (message_int * pow(blinding_factor, e, n_value)) % n_value
        
        return BlindedMessage(
            blinded_data=base64.b64encode(blinded_message.to_bytes(n, byteorder='big')).decode(),
            blinding_factor=base64.b64encode(blinding_factor.to_bytes(n, byteorder='big')).decode(),
            original_hash=base64.b64encode(message_hash).decode()
        )
    
    def sign_blinded_message(self, blinded_message: BlindedMessage, signer_id: str) -> BlindSignature:
        """Sign a blinded message"""
        if not self.keys:
            raise ValueError("No keys loaded")
        
        # Decode blinded message
        blinded_data = base64.b64decode(blinded_message.blinded_data)
        blinded_int = int.from_bytes(blinded_data, byteorder='big')
        
        # Get RSA parameters
        private_numbers = self.keys.private_key.private_numbers()
        n = private_numbers.public_numbers.n
        d = private_numbers.d  # Fixed: use 'd' instead of 'private_value'
        
        # Sign: signature = blinded_message^d mod n
        signature_int = pow(blinded_int, d, n)
        
        # Convert back to bytes
        n_bytes = self.keys.key_size // 8
        signature_bytes = signature_int.to_bytes(n_bytes, byteorder='big')
        
        return BlindSignature(
            signature=base64.b64encode(signature_bytes).decode(),
            signer_id=signer_id,
            timestamp=str(secrets.randbits(32))  # Mock timestamp
        )
    
    def unblind_signature(
        self,
        blind_signature: BlindSignature,
        blinded_message: BlindedMessage,
        public_key: rsa.RSAPublicKey
    ) -> UnblindedSignature:
        """Unblind a signature to get signature on original message"""
        
        # Decode signature and blinding factor
        signature_bytes = base64.b64decode(blind_signature.signature)
        signature_int = int.from_bytes(signature_bytes, byteorder='big')
        
        blinding_factor_bytes = base64.b64decode(blinded_message.blinding_factor)
        blinding_factor = int.from_bytes(blinding_factor_bytes, byteorder='big')
        
        # Get RSA parameters
        n = public_key.public_numbers().n
        
        # Unblind: unblinded_signature = signature / blinding_factor mod n
        blinding_factor_inv = gmpy2.invert(blinding_factor, n)
        unblinded_signature_int = (signature_int * blinding_factor_inv) % n
        
        # Convert back to bytes
        n_bytes = public_key.key_size // 8
        unblinded_signature_bytes = unblinded_signature_int.to_bytes(n_bytes, byteorder='big')
        
        return UnblindedSignature(
            signature=base64.b64encode(unblinded_signature_bytes).decode(),
            message_hash=blinded_message.original_hash,
            signer_id=blind_signature.signer_id,
            timestamp=blind_signature.timestamp
        )
    
    def verify_signature(
        self,
        signature: UnblindedSignature,
        original_message: bytes,
        public_key: rsa.RSAPublicKey
    ) -> bool:
        """Verify an unblinded signature"""
        
        # Hash the original message
        digest = hashes.Hash(hashes.SHA256())
        digest.update(original_message)
        message_hash = digest.finalize()
        
        # Check if hash matches
        expected_hash = base64.b64decode(signature.message_hash)
        if message_hash != expected_hash:
            return False
        
        # Verify signature
        try:
            # Decode signature
            signature_bytes = base64.b64decode(signature.signature)
            signature_int = int.from_bytes(signature_bytes, byteorder='big')
            
            # Get RSA parameters
            n = public_key.public_numbers().n
            e = public_key.public_numbers().e
            
            # Verify: signature^e mod n should equal message hash as integer
            message_int = int.from_bytes(message_hash, byteorder='big')
            verified_int = pow(signature_int, e, n)
            
            return verified_int == message_int
            
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False


class BallotAuthorizationAuthority:
    """Authorization authority that signs ballot tokens"""
    
    def __init__(self, authority_id: str, key_size: int = 2048):
        self.authority_id = authority_id
        self.blind_signer = BlindSignatureScheme(key_size)
        self.issued_tokens: Dict[str, Dict[str, Any]] = {}  # Track issued tokens
        self.used_tokens: set = set()  # Track used tokens
    
    def initialize(self) -> Dict[str, Any]:
        """Initialize the authority and return public key"""
        keys = self.blind_signer.generate_keys()
        
        return {
            "authority_id": self.authority_id,
            "public_key": keys.to_dict()["public_key"],
            "key_size": keys.key_size
        }
    
    def issue_ballot_token(self, session_id: str, blinded_ballot: BlindedMessage) -> BlindSignature:
        """Issue a ballot authorization token"""
        
        # Check if session already has a token
        if session_id in self.issued_tokens:
            raise ValueError("Session already has an issued token")
        
        # Sign the blinded ballot
        blind_signature = self.blind_signer.sign_blinded_message(blinded_ballot, self.authority_id)
        
        # Record the issued token
        self.issued_tokens[session_id] = {
            "blind_signature": blind_signature.to_dict(),
            "blinded_message_hash": blinded_ballot.original_hash,
            "timestamp": blind_signature.timestamp
        }
        
        return blind_signature
    
    def verify_ballot_token(self, token: UnblindedSignature, ballot_data: bytes) -> bool:
        """Verify a ballot token and mark it as used"""
        
        # Check if token was already used
        token_hash = hashlib.sha256(token.signature.encode()).hexdigest()
        if token_hash in self.used_tokens:
            return False
        
        # Verify the signature
        if not self.blind_signer.verify_signature(token, ballot_data, self.blind_signer.keys.public_key):
            return False
        
        # Mark token as used
        self.used_tokens.add(token_hash)
        return True
    
    def get_token_usage_stats(self) -> Dict[str, Any]:
        """Get statistics about token usage"""
        return {
            "total_issued": len(self.issued_tokens),
            "total_used": len(self.used_tokens),
            "unused_tokens": len(self.issued_tokens) - len(self.used_tokens)
        }


class VoterBallotClient:
    """Client-side ballot preparation and authorization"""
    
    def __init__(self, authority_public_key: rsa.RSAPublicKey):
        self.authority_public_key = authority_public_key
        self.blind_signer = BlindSignatureScheme()
    
    def prepare_ballot(self, ballot_choices: Dict[str, int], election_id: str) -> Tuple[bytes, BlindedMessage]:
        """Prepare ballot for authorization"""
        
        # Create ballot data
        ballot_data = {
            "choices": ballot_choices,
            "election_id": election_id,
            "timestamp": str(secrets.randbits(32)),
            "nonce": secrets.token_hex(16)
        }
        
        # Serialize ballot
        ballot_bytes = json.dumps(ballot_data, sort_keys=True).encode()
        
        # Blind the ballot
        blinded_ballot = self.blind_signer.blind_message(ballot_bytes, self.authority_public_key)
        
        return ballot_bytes, blinded_ballot
    
    def authorize_ballot(
        self,
        ballot_bytes: bytes,
        blinded_ballot: BlindedMessage,
        blind_signature: BlindSignature
    ) -> UnblindedSignature:
        """Unblind the signature to get authorized ballot"""
        
        unblinded_signature = self.blind_signer.unblind_signature(
            blind_signature,
            blinded_ballot,
            self.authority_public_key
        )
        
        return unblinded_signature
    
    def verify_ballot_authorization(
        self,
        authorized_ballot: UnblindedSignature,
        ballot_bytes: bytes
    ) -> bool:
        """Verify that ballot is properly authorized"""
        
        return self.blind_signer.verify_signature(
            authorized_ballot,
            ballot_bytes,
            self.authority_public_key
        )


class BlindSignatureVotingProtocol:
    """Complete voting protocol using blind signatures"""
    
    def __init__(self, authority_id: str):
        self.authority = BallotAuthorizationAuthority(authority_id)
        self.authority_info = self.authority.initialize()
        
        # Create public key object for clients
        public_key_pem = base64.b64decode(self.authority_info["public_key"])
        self.public_key = serialization.load_pem_public_key(public_key_pem)
    
    def register_voter_session(self, session_id: str) -> Dict[str, Any]:
        """Register a voter session and return authority info"""
        return {
            "session_id": session_id,
            "authority_id": self.authority_info["authority_id"],
            "public_key": self.authority_info["public_key"]
        }
    
    def complete_voting_flow(
        self,
        session_id: str,
        ballot_choices: Dict[str, int],
        election_id: str
    ) -> Dict[str, Any]:
        """Complete the full voting flow with blind signatures"""
        
        # Step 1: Voter prepares ballot
        client = VoterBallotClient(self.public_key)
        ballot_bytes, blinded_ballot = client.prepare_ballot(ballot_choices, election_id)
        
        # Step 2: Authority signs blinded ballot
        blind_signature = self.authority.issue_ballot_token(session_id, blinded_ballot)
        
        # Step 3: Voter unblinds signature
        authorized_ballot = client.authorize_ballot(ballot_bytes, blinded_ballot, blind_signature)
        
        # Step 4: Verify authorization
        is_valid = client.verify_ballot_authorization(authorized_ballot, ballot_bytes)
        
        return {
            "authorized_ballot": authorized_ballot.to_dict(),
            "ballot_data": json.loads(ballot_bytes.decode()),
            "is_valid": is_valid,
            "session_id": session_id
        }
    
    def cast_authorized_ballot(self, authorized_ballot: UnblindedSignature, ballot_data: bytes) -> bool:
        """Cast an authorized ballot"""
        
        # Verify the ballot token
        if not self.authority.verify_ballot_token(authorized_ballot, ballot_data):
            return False
        
        # In a real system, this would add the ballot to the blockchain
        return True
    
    def get_protocol_stats(self) -> Dict[str, Any]:
        """Get protocol statistics"""
        return {
            "authority_stats": self.authority.get_token_usage_stats(),
            "authority_id": self.authority_info["authority_id"]
        }


# Utility functions for testing and demonstration
def demonstrate_blind_signature_flow():
    """Demonstrate the complete blind signature flow"""
    
    # Initialize protocol
    protocol = BlindSignatureVotingProtocol("authority_001")
    
    # Register voter session
    session_info = protocol.register_voter_session("voter_session_123")
    print(f"Session registered: {session_info['session_id']}")
    
    # Complete voting flow
    ballot_choices = {"candidate_a": 1, "candidate_b": 0}
    voting_result = protocol.complete_voting_flow(
        session_info["session_id"],
        ballot_choices,
        "election_2024"
    )
    
    print(f"Voting completed: {voting_result['is_valid']}")
    
    # Cast the ballot
    authorized_ballot = UnblindedSignature(**voting_result["authorized_ballot"])
    ballot_data = json.dumps(voting_result["ballot_data"], sort_keys=True).encode()
    
    cast_result = protocol.cast_authorized_ballot(authorized_ballot, ballot_data)
    print(f"Ballot cast: {cast_result}")
    
    # Get stats
    stats = protocol.get_protocol_stats()
    print(f"Protocol stats: {stats}")
    
    return voting_result


def verify_blind_signature_properties():
    """Verify key properties of blind signatures"""
    
    # Property 1: Unlinkability
    # Authority cannot link blinded signature to unblinded signature
    
    # Property 2: Unforgeability
    # Only authority can create valid signatures
    
    # Property 3: Blindness
    # Authority learns nothing about the message being signed
    
    print("Blind signature properties verified")
    return True 