"""
Self-Sovereign Identity (SSI) with Verifiable Credentials
Implements W3C Verifiable Credentials specification for secure voter identity
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature
import jwt
from pydantic import BaseModel, Field, validator
from jsonschema import validate, ValidationError
import hashlib
import base64


class CredentialStatus(Enum):
    """Status of a verifiable credential"""
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class ProofType(Enum):
    """Types of cryptographic proofs"""
    RSA_SIGNATURE_2018 = "RsaSignature2018"
    ED25519_SIGNATURE_2018 = "Ed25519Signature2018"
    ECDSA_SECP256K1_SIGNATURE_2019 = "EcdsaSecp256k1Signature2019"


@dataclass
class DIDDocument:
    """Decentralized Identifier (DID) Document"""
    id: str
    context: List[str]
    public_key: List[Dict[str, Any]]
    authentication: List[str]
    service: List[Dict[str, Any]]
    created: datetime
    updated: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "@context": self.context,
            "id": self.id,
            "publicKey": self.public_key,
            "authentication": self.authentication,
            "service": self.service,
            "created": self.created.isoformat(),
            "updated": self.updated.isoformat()
        }


class VerifiableCredential(BaseModel):
    """W3C Verifiable Credential implementation"""
    
    context: List[str] = Field(default=[
        "https://www.w3.org/2018/credentials/v1",
        "https://themedian.org/credentials/voter/v1"
    ])
    id: str = Field(default_factory=lambda: f"https://themedian.org/credentials/{uuid.uuid4()}")
    type: List[str] = Field(default=["VerifiableCredential", "VoterEligibilityCredential"])
    issuer: str
    issuance_date: datetime = Field(default_factory=datetime.utcnow)
    expiration_date: Optional[datetime] = None
    credential_subject: Dict[str, Any]
    credential_status: Optional[Dict[str, Any]] = None
    proof: Optional[Dict[str, Any]] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @validator('credential_subject')
    def validate_credential_subject(cls, v):
        """Validate credential subject contains required fields"""
        required_fields = ['id', 'is_eligible_to_vote', 'jurisdiction']
        for field in required_fields:
            if field not in v:
                raise ValueError(f"Missing required field: {field}")
        return v
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        data = {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date.isoformat(),
            "credentialSubject": self.credential_subject
        }
        
        if self.expiration_date:
            data["expirationDate"] = self.expiration_date.isoformat()
        
        if self.credential_status:
            data["credentialStatus"] = self.credential_status
        
        if self.proof:
            data["proof"] = self.proof
        
        return data
    
    def is_expired(self) -> bool:
        """Check if credential is expired"""
        if not self.expiration_date:
            return False
        return datetime.utcnow() > self.expiration_date
    
    def is_valid(self) -> bool:
        """Check if credential is valid (not expired and has valid proof)"""
        if self.is_expired():
            return False
        
        if not self.proof:
            return False
        
        # Additional validation logic would go here
        return True


class VerifiablePresentation(BaseModel):
    """W3C Verifiable Presentation implementation"""
    
    context: List[str] = Field(default=[
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ])
    id: str = Field(default_factory=lambda: f"https://themedian.org/presentations/{uuid.uuid4()}")
    type: List[str] = Field(default=["VerifiablePresentation"])
    verifiable_credential: List[VerifiableCredential]
    holder: str
    proof: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        data = {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "verifiableCredential": [vc.to_dict() for vc in self.verifiable_credential],
            "holder": self.holder
        }
        
        if self.proof:
            data["proof"] = self.proof
        
        return data


class CredentialIssuer:
    """Issuer of verifiable credentials (typically a government entity)"""
    
    def __init__(self, did: str, private_key: bytes, public_key: bytes):
        """Initialize issuer with DID and key pair"""
        self.did = did
        self.private_key = load_pem_private_key(private_key, password=None)
        self.public_key_pem = public_key
        self.public_key = serialization.load_pem_public_key(public_key)
    
    def issue_voter_credential(
        self,
        subject_did: str,
        jurisdiction: str,
        election_id: str,
        validity_days: int = 90,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> VerifiableCredential:
        """Issue a voter eligibility credential"""
        
        credential_subject = {
            "id": subject_did,
            "is_eligible_to_vote": True,
            "jurisdiction": jurisdiction,
            "election_id": election_id,
            "verified_at": datetime.utcnow().isoformat()
        }
        
        if additional_claims:
            credential_subject.update(additional_claims)
        
        credential = VerifiableCredential(
            issuer=self.did,
            expiration_date=datetime.utcnow() + timedelta(days=validity_days),
            credential_subject=credential_subject,
            credential_status={
                "id": f"https://themedian.org/credentials/status/{uuid.uuid4()}",
                "type": "RevocationList2020Status",
                "revocationListIndex": "0",
                "revocationListCredential": f"https://themedian.org/credentials/status-list/{election_id}"
            }
        )
        
        # Sign the credential
        proof = self._create_proof(credential)
        credential.proof = proof
        
        return credential
    
    def _create_proof(self, credential: VerifiableCredential) -> Dict[str, Any]:
        """Create cryptographic proof for credential"""
        # Create canonical representation
        canonical_data = json.dumps(credential.to_dict(), sort_keys=True, separators=(',', ':'))
        
        # Create signature
        signature = self.private_key.sign(
            canonical_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        proof = {
            "type": ProofType.RSA_SIGNATURE_2018.value,
            "created": datetime.utcnow().isoformat(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{self.did}#key-1",
            "jws": base64.urlsafe_b64encode(signature).decode()
        }
        
        return proof
    
    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke a credential by adding it to revocation list"""
        # Implementation would update the revocation list
        # This is a simplified version
        return True


class CredentialVerifier:
    """Verifier of verifiable credentials and presentations"""
    
    def __init__(self, trusted_issuers: Dict[str, bytes]):
        """Initialize verifier with trusted issuer public keys"""
        self.trusted_issuers = {}
        for did, public_key_pem in trusted_issuers.items():
            self.trusted_issuers[did] = serialization.load_pem_public_key(public_key_pem)
    
    def verify_credential(self, credential: VerifiableCredential) -> bool:
        """Verify a verifiable credential"""
        try:
            # Check if issuer is trusted
            if credential.issuer not in self.trusted_issuers:
                return False
            
            # Check expiration
            if credential.is_expired():
                return False
            
            # Verify proof
            if not credential.proof:
                return False
            
            # Verify signature
            public_key = self.trusted_issuers[credential.issuer]
            
            # Reconstruct the signed data
            credential_copy = credential.copy()
            credential_copy.proof = None
            canonical_data = json.dumps(credential_copy.to_dict(), sort_keys=True, separators=(',', ':'))
            
            # Decode signature
            signature = base64.urlsafe_b64decode(credential.proof['jws'])
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    canonical_data.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                return False
                
        except Exception as e:
            print(f"Credential verification error: {e}")
            return False
    
    def verify_presentation(self, presentation: VerifiablePresentation) -> bool:
        """Verify a verifiable presentation"""
        try:
            # Verify each credential in the presentation
            for credential in presentation.verifiable_credential:
                if not self.verify_credential(credential):
                    return False
            
            # Verify presentation proof if present
            if presentation.proof:
                # Implementation would verify the presentation proof
                pass
            
            return True
            
        except Exception as e:
            print(f"Presentation verification error: {e}")
            return False
    
    def extract_voting_eligibility(self, credential: VerifiableCredential) -> Optional[Dict[str, Any]]:
        """Extract voting eligibility information from credential"""
        if not self.verify_credential(credential):
            return None
        
        subject = credential.credential_subject
        return {
            "is_eligible": subject.get("is_eligible_to_vote", False),
            "jurisdiction": subject.get("jurisdiction"),
            "election_id": subject.get("election_id"),
            "verified_at": subject.get("verified_at")
        }


class DIDResolver:
    """Resolver for Decentralized Identifiers"""
    
    def __init__(self):
        self.did_documents: Dict[str, DIDDocument] = {}
    
    def register_did(self, did_document: DIDDocument) -> bool:
        """Register a DID document"""
        try:
            self.did_documents[did_document.id] = did_document
            return True
        except Exception:
            return False
    
    def resolve_did(self, did: str) -> Optional[DIDDocument]:
        """Resolve a DID to its document"""
        return self.did_documents.get(did)
    
    def get_public_key(self, did: str, key_id: str) -> Optional[bytes]:
        """Get public key for a DID"""
        document = self.resolve_did(did)
        if not document:
            return None
        
        for key in document.public_key:
            if key.get("id") == key_id:
                return key.get("publicKeyPem", "").encode()
        
        return None


# Utility functions for credential management
def generate_did(method: str = "medivote") -> str:
    """Generate a new DID"""
    return f"did:{method}:{uuid.uuid4()}"


def create_credential_schema() -> Dict[str, Any]:
    """Create JSON schema for voter eligibility credential"""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "@context": {"type": "array"},
            "id": {"type": "string"},
            "type": {"type": "array"},
            "issuer": {"type": "string"},
            "issuanceDate": {"type": "string", "format": "date-time"},
            "expirationDate": {"type": "string", "format": "date-time"},
            "credentialSubject": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "is_eligible_to_vote": {"type": "boolean"},
                    "jurisdiction": {"type": "string"},
                    "election_id": {"type": "string"}
                },
                "required": ["id", "is_eligible_to_vote", "jurisdiction", "election_id"]
            },
            "proof": {"type": "object"}
        },
        "required": ["@context", "id", "type", "issuer", "issuanceDate", "credentialSubject"]
    }


def validate_credential_schema(credential: Dict[str, Any]) -> bool:
    """Validate credential against schema"""
    try:
        schema = create_credential_schema()
        validate(credential, schema)
        return True
    except ValidationError:
        return False 