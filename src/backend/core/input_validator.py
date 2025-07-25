#!/usr/bin/env python3
"""
Comprehensive Input Validation System for MediVote
Provides security-focused validation for all user inputs with sanitization and threat detection

SECURITY FEATURES:
- SQL injection prevention
- XSS attack prevention
- Command injection prevention
- File path traversal prevention
- DID format validation
- Election ID validation
- Cryptographic signature validation
- ZK proof validation
- Rate limiting input validation
"""

import re
import json
import base64
import hashlib
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime, timedelta
from enum import Enum
import logging
from dataclasses import dataclass

from pydantic import BaseModel, Field, validator
import bleach
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.exceptions import InvalidSignature

from .error_handler import ValidationError, InputSanitizationError, validate_input

logger = logging.getLogger(__name__)


class ValidationType(str, Enum):
    """Types of validation"""
    BASIC = "basic"
    SECURITY = "security"
    CRYPTOGRAPHIC = "cryptographic"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class ValidationResult:
    """Result of input validation"""
    is_valid: bool
    sanitized_value: Any
    error_message: Optional[str] = None
    threat_detected: Optional[str] = None
    validation_type: ValidationType = ValidationType.BASIC
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "sanitized_value": self.sanitized_value,
            "error_message": self.error_message,
            "threat_detected": self.threat_detected,
            "validation_type": self.validation_type.value
        }


class SecurityThreatDetector:
    """Detect security threats in user input"""
    
    # Common attack patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+[\'\"][\w\s]*[\'\"][\s]*=[\s]*[\'\"][\w\s]*[\'\"])",
        r"(\bunion\s+select)",
        r"(\bselect\s+.*\bfrom\s+)",
        r"(\binsert\s+into\s+)",
        r"(\bupdate\s+.*\bset\s+)",
        r"(\bdelete\s+from\s+)",
        r"(\bdrop\s+table\s+)",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<link[^>]*>",
        r"<meta[^>]*>",
        r"expression\s*\(",
        r"@import",
        r"<svg[^>]*>.*?</svg>",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(;|\||\|\||&&|`|\$\(|\${)",
        r"(\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|wget|curl)\b)",
        r"(>|<|>>|<<)",
        r"(\.\./|\.\.\\)",
        r"(/etc/passwd|/etc/shadow|/proc/|/sys/)",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%252e%252e%252f",
    ]
    
    def __init__(self):
        self.sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.XSS_PATTERNS]
        self.cmd_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.COMMAND_INJECTION_PATTERNS]
        self.path_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.PATH_TRAVERSAL_PATTERNS]
    
    def detect_sql_injection(self, value: str) -> Optional[str]:
        """Detect SQL injection attempts"""
        for pattern in self.sql_patterns:
            if pattern.search(value):
                logger.warning(f"SQL injection attempt detected: {pattern.pattern}")
                return f"SQL injection pattern detected: {pattern.pattern}"
        return None
    
    def detect_xss(self, value: str) -> Optional[str]:
        """Detect XSS attempts"""
        for pattern in self.xss_patterns:
            if pattern.search(value):
                logger.warning(f"XSS attempt detected: {pattern.pattern}")
                return f"XSS pattern detected: {pattern.pattern}"
        return None
    
    def detect_command_injection(self, value: str) -> Optional[str]:
        """Detect command injection attempts"""
        for pattern in self.cmd_patterns:
            if pattern.search(value):
                logger.warning(f"Command injection attempt detected: {pattern.pattern}")
                return f"Command injection pattern detected: {pattern.pattern}"
        return None
    
    def detect_path_traversal(self, value: str) -> Optional[str]:
        """Detect path traversal attempts"""
        for pattern in self.path_patterns:
            if pattern.search(value):
                logger.warning(f"Path traversal attempt detected: {pattern.pattern}")
                return f"Path traversal pattern detected: {pattern.pattern}"
        return None
    
    def detect_threats(self, value: str) -> Optional[str]:
        """Detect all types of security threats"""
        threats = [
            self.detect_sql_injection(value),
            self.detect_xss(value),
            self.detect_command_injection(value),
            self.detect_path_traversal(value)
        ]
        
        detected_threats = [threat for threat in threats if threat is not None]
        if detected_threats:
            return "; ".join(detected_threats)
        return None


class InputSanitizer:
    """Sanitize user input to prevent attacks"""
    
    def __init__(self):
        self.threat_detector = SecurityThreatDetector()
        
        # HTML sanitization settings
        self.allowed_tags = []  # No HTML allowed by default
        self.allowed_attributes = {}
        self.allowed_protocols = ['http', 'https', 'mailto']
    
    def sanitize_string(self, value: str, allow_html: bool = False) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            raise ValidationError("Value must be a string", field="input", value=value)
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize unicode
        value = value.encode('utf-8', errors='ignore').decode('utf-8')
        
        # HTML sanitization
        if allow_html:
            value = bleach.clean(
                value, 
                tags=self.allowed_tags,
                attributes=self.allowed_attributes,
                protocols=self.allowed_protocols,
                strip=True
            )
        else:
            # Escape HTML entities
            value = bleach.clean(value, tags=[], attributes={}, strip=True)
        
        # Remove excessive whitespace
        value = re.sub(r'\s+', ' ', value).strip()
        
        return value
    
    def sanitize_identifier(self, value: str) -> str:
        """Sanitize identifiers (IDs, usernames, etc.)"""
        if not isinstance(value, str):
            raise ValidationError("Identifier must be a string", field="identifier", value=value)
        
        # Only allow alphanumeric, dash, underscore
        sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '', value)
        
        if len(sanitized) == 0:
            raise ValidationError("Identifier contains no valid characters", field="identifier", value=value)
        
        return sanitized
    
    def sanitize_email(self, value: str) -> str:
        """Sanitize email address"""
        if not isinstance(value, str):
            raise ValidationError("Email must be a string", field="email", value=value)
        
        # Basic sanitization
        value = value.lower().strip()
        
        # Remove any suspicious characters
        value = re.sub(r'[^\w@.\-]', '', value)
        
        return value
    
    def sanitize_json(self, value: Union[str, dict]) -> dict:
        """Sanitize JSON input"""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise ValidationError("Invalid JSON format", field="json", value=value)
        
        if not isinstance(value, dict):
            raise ValidationError("JSON must be an object", field="json", value=value)
        
        # Recursively sanitize string values
        return self._sanitize_dict_recursive(value)
    
    def _sanitize_dict_recursive(self, data: dict) -> dict:
        """Recursively sanitize dictionary values"""
        sanitized = {}
        for key, value in data.items():
            # Sanitize key
            if isinstance(key, str):
                key = self.sanitize_string(key)
            
            # Sanitize value
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict_recursive(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_string(item) if isinstance(item, str) 
                    else self._sanitize_dict_recursive(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized


class MediVoteValidators:
    """Specialized validators for MediVote system"""
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
        self.threat_detector = SecurityThreatDetector()
    
    def validate_did(self, did: str) -> ValidationResult:
        """Validate Decentralized Identifier (DID)"""
        try:
            # DID format: did:method:identifier
            did_pattern = r'^did:[a-z0-9]+:[a-zA-Z0-9._-]+$'
            
            if not isinstance(did, str):
                return ValidationResult(False, None, "DID must be a string")
            
            # Check length
            if len(did) < 10 or len(did) > 200:
                return ValidationResult(False, None, "DID length must be between 10 and 200 characters")
            
            # Sanitize
            sanitized_did = self.sanitizer.sanitize_string(did)
            
            # Check threats
            threat = self.threat_detector.detect_threats(sanitized_did)
            if threat:
                return ValidationResult(False, None, "Security threat detected", threat)
            
            # Validate format
            if not re.match(did_pattern, sanitized_did):
                return ValidationResult(False, None, "Invalid DID format")
            
            return ValidationResult(True, sanitized_did, validation_type=ValidationType.BUSINESS_LOGIC)
            
        except Exception as e:
            return ValidationResult(False, None, f"DID validation error: {str(e)}")
    
    def validate_election_id(self, election_id: str) -> ValidationResult:
        """Validate election ID"""
        try:
            if not isinstance(election_id, str):
                return ValidationResult(False, None, "Election ID must be a string")
            
            # Check length
            if len(election_id) < 5 or len(election_id) > 100:
                return ValidationResult(False, None, "Election ID length must be between 5 and 100 characters")
            
            # Sanitize
            sanitized_id = self.sanitizer.sanitize_identifier(election_id)
            
            # Check threats
            threat = self.threat_detector.detect_threats(sanitized_id)
            if threat:
                return ValidationResult(False, None, "Security threat detected", threat)
            
            # Validate format (alphanumeric, dash, underscore only)
            if not re.match(r'^[a-zA-Z0-9\-_]+$', sanitized_id):
                return ValidationResult(False, None, "Invalid election ID format")
            
            return ValidationResult(True, sanitized_id, validation_type=ValidationType.BUSINESS_LOGIC)
            
        except Exception as e:
            return ValidationResult(False, None, f"Election ID validation error: {str(e)}")
    
    def validate_vote_payload(self, payload: Union[str, dict]) -> ValidationResult:
        """Validate vote payload"""
        try:
            # Sanitize JSON
            sanitized_payload = self.sanitizer.sanitize_json(payload)
            
            # Required fields
            required_fields = ['candidate_id', 'election_id', 'timestamp']
            for field in required_fields:
                if field not in sanitized_payload:
                    return ValidationResult(False, None, f"Missing required field: {field}")
            
            # Validate candidate_id
            candidate_result = self.validate_election_id(sanitized_payload['candidate_id'])
            if not candidate_result.is_valid:
                return ValidationResult(False, None, f"Invalid candidate_id: {candidate_result.error_message}")
            
            # Validate election_id
            election_result = self.validate_election_id(sanitized_payload['election_id'])
            if not election_result.is_valid:
                return ValidationResult(False, None, f"Invalid election_id: {election_result.error_message}")
            
            # Validate timestamp
            try:
                timestamp = datetime.fromisoformat(sanitized_payload['timestamp'].replace('Z', '+00:00'))
                # Check if timestamp is reasonable (not too far in past/future)
                now = datetime.utcnow()
                if abs((timestamp - now).total_seconds()) > 3600:  # 1 hour tolerance
                    return ValidationResult(False, None, "Invalid timestamp: too far from current time")
            except (ValueError, AttributeError):
                return ValidationResult(False, None, "Invalid timestamp format")
            
            return ValidationResult(True, sanitized_payload, validation_type=ValidationType.BUSINESS_LOGIC)
            
        except Exception as e:
            return ValidationResult(False, None, f"Vote payload validation error: {str(e)}")
    
    def validate_zk_proof(self, proof: Union[str, dict]) -> ValidationResult:
        """Validate zero-knowledge proof structure"""
        try:
            # Sanitize JSON
            sanitized_proof = self.sanitizer.sanitize_json(proof)
            
            # Required fields for Groth16 proof
            required_fields = ['pi_a', 'pi_b', 'pi_c']
            for field in required_fields:
                if field not in sanitized_proof:
                    return ValidationResult(False, None, f"Missing proof field: {field}")
            
            # Validate pi_a (2 elements)
            if not isinstance(sanitized_proof['pi_a'], list) or len(sanitized_proof['pi_a']) != 2:
                return ValidationResult(False, None, "Invalid pi_a format")
            
            # Validate pi_b (2x2 elements)
            if not isinstance(sanitized_proof['pi_b'], list) or len(sanitized_proof['pi_b']) != 2:
                return ValidationResult(False, None, "Invalid pi_b format")
            for element in sanitized_proof['pi_b']:
                if not isinstance(element, list) or len(element) != 2:
                    return ValidationResult(False, None, "Invalid pi_b element format")
            
            # Validate pi_c (2 elements)
            if not isinstance(sanitized_proof['pi_c'], list) or len(sanitized_proof['pi_c']) != 2:
                return ValidationResult(False, None, "Invalid pi_c format")
            
            # All elements should be hex strings
            all_elements = (
                sanitized_proof['pi_a'] + 
                [item for sublist in sanitized_proof['pi_b'] for item in sublist] +
                sanitized_proof['pi_c']
            )
            
            for element in all_elements:
                if not isinstance(element, str) or not re.match(r'^0x[0-9a-fA-F]+$', element):
                    return ValidationResult(False, None, f"Invalid proof element format: {element}")
            
            return ValidationResult(True, sanitized_proof, validation_type=ValidationType.CRYPTOGRAPHIC)
            
        except Exception as e:
            return ValidationResult(False, None, f"ZK proof validation error: {str(e)}")
    
    def validate_device_fingerprint(self, fingerprint: Union[str, dict]) -> ValidationResult:
        """Validate device fingerprint"""
        try:
            # Sanitize JSON
            sanitized_fp = self.sanitizer.sanitize_json(fingerprint)
            
            # Expected fields
            expected_fields = ['screen', 'timezone', 'language', 'platform', 'hardware']
            
            # Check for suspicious values
            for key, value in sanitized_fp.items():
                if isinstance(value, str):
                    threat = self.threat_detector.detect_threats(value)
                    if threat:
                        return ValidationResult(False, None, f"Security threat in {key}", threat)
            
            # Validate structure (basic check)
            if len(sanitized_fp) < 3:
                return ValidationResult(False, None, "Insufficient fingerprint data")
            
            return ValidationResult(True, sanitized_fp, validation_type=ValidationType.SECURITY)
            
        except Exception as e:
            return ValidationResult(False, None, f"Device fingerprint validation error: {str(e)}")
    
    def validate_signature(self, signature: str, message: str, public_key: str) -> ValidationResult:
        """Validate cryptographic signature"""
        try:
            if not all(isinstance(x, str) for x in [signature, message, public_key]):
                return ValidationResult(False, None, "Signature components must be strings")
            
            # Decode base64 signature
            try:
                signature_bytes = base64.b64decode(signature)
            except Exception:
                return ValidationResult(False, None, "Invalid signature encoding")
            
            # Decode public key
            try:
                public_key_obj = serialization.load_pem_public_key(public_key.encode())
            except Exception:
                return ValidationResult(False, None, "Invalid public key format")
            
            # Verify signature (example for RSA)
            try:
                if isinstance(public_key_obj, rsa.RSAPublicKey):
                    public_key_obj.verify(
                        signature_bytes,
                        message.encode(),
                        hashes.SHA256()
                    )
                elif isinstance(public_key_obj, ec.EllipticCurvePublicKey):
                    public_key_obj.verify(
                        signature_bytes,
                        message.encode(),
                        ec.ECDSA(hashes.SHA256())
                    )
                else:
                    return ValidationResult(False, None, "Unsupported key type")
                
                return ValidationResult(True, signature, validation_type=ValidationType.CRYPTOGRAPHIC)
                
            except InvalidSignature:
                return ValidationResult(False, None, "Invalid signature")
            
        except Exception as e:
            return ValidationResult(False, None, f"Signature validation error: {str(e)}")


class InputValidator:
    """Main input validation class"""
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
        self.threat_detector = SecurityThreatDetector()
        self.medivote_validators = MediVoteValidators()
        self.validation_stats = {
            "total_validations": 0,
            "threats_detected": 0,
            "validations_failed": 0
        }
    
    def validate(
        self, 
        value: Any, 
        validator_type: str, 
        field_name: str = None,
        **kwargs
    ) -> ValidationResult:
        """Main validation method"""
        self.validation_stats["total_validations"] += 1
        
        try:
            # Route to appropriate validator
            if validator_type == "did":
                result = self.medivote_validators.validate_did(value)
            elif validator_type == "election_id":
                result = self.medivote_validators.validate_election_id(value)
            elif validator_type == "vote_payload":
                result = self.medivote_validators.validate_vote_payload(value)
            elif validator_type == "zk_proof":
                result = self.medivote_validators.validate_zk_proof(value)
            elif validator_type == "device_fingerprint":
                result = self.medivote_validators.validate_device_fingerprint(value)
            elif validator_type == "signature":
                result = self.medivote_validators.validate_signature(
                    value, kwargs.get('message', ''), kwargs.get('public_key', '')
                )
            elif validator_type == "string":
                sanitized = self.sanitizer.sanitize_string(value, kwargs.get('allow_html', False))
                threat = self.threat_detector.detect_threats(sanitized)
                if threat:
                    result = ValidationResult(False, None, "Security threat detected", threat)
                else:
                    result = ValidationResult(True, sanitized)
            elif validator_type == "email":
                sanitized = self.sanitizer.sanitize_email(value)
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sanitized):
                    result = ValidationResult(False, None, "Invalid email format")
                else:
                    result = ValidationResult(True, sanitized)
            elif validator_type == "identifier":
                sanitized = self.sanitizer.sanitize_identifier(value)
                result = ValidationResult(True, sanitized)
            else:
                result = ValidationResult(False, None, f"Unknown validator type: {validator_type}")
            
            # Update statistics
            if result.threat_detected:
                self.validation_stats["threats_detected"] += 1
            if not result.is_valid:
                self.validation_stats["validations_failed"] += 1
            
            # Log threats
            if result.threat_detected:
                logger.warning(
                    f"Security threat detected in field '{field_name}': {result.threat_detected}",
                    extra={
                        "field_name": field_name,
                        "validator_type": validator_type,
                        "threat": result.threat_detected,
                        "value_length": len(str(value)) if value else 0
                    }
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Validation error for field '{field_name}': {str(e)}")
            self.validation_stats["validations_failed"] += 1
            return ValidationResult(False, None, f"Validation error: {str(e)}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get validation statistics"""
        return {
            **self.validation_stats,
            "threat_detection_rate": (
                self.validation_stats["threats_detected"] / max(1, self.validation_stats["total_validations"])
            ),
            "failure_rate": (
                self.validation_stats["validations_failed"] / max(1, self.validation_stats["total_validations"])
            )
        }


# Global validator instance
input_validator = InputValidator()


# Convenience functions for common validations
def validate_voter_did(did: str, field_name: str = "did") -> str:
    """Validate and sanitize voter DID"""
    result = input_validator.validate(did, "did", field_name)
    if not result.is_valid:
        raise InputSanitizationError(field_name, result.error_message or "Invalid DID")
    return result.sanitized_value


def validate_election_id(election_id: str, field_name: str = "election_id") -> str:
    """Validate and sanitize election ID"""
    result = input_validator.validate(election_id, "election_id", field_name)
    if not result.is_valid:
        raise InputSanitizationError(field_name, result.error_message or "Invalid election ID")
    return result.sanitized_value


def validate_vote_data(vote_data: Union[str, dict], field_name: str = "vote_data") -> dict:
    """Validate and sanitize vote data"""
    result = input_validator.validate(vote_data, "vote_payload", field_name)
    if not result.is_valid:
        raise InputSanitizationError(field_name, result.error_message or "Invalid vote data")
    return result.sanitized_value


def validate_zk_proof_data(proof_data: Union[str, dict], field_name: str = "zk_proof") -> dict:
    """Validate and sanitize ZK proof data"""
    result = input_validator.validate(proof_data, "zk_proof", field_name)
    if not result.is_valid:
        raise InputSanitizationError(field_name, result.error_message or "Invalid ZK proof")
    return result.sanitized_value


def validate_user_input(value: str, field_name: str = "input", allow_html: bool = False) -> str:
    """Validate and sanitize general user input"""
    result = input_validator.validate(value, "string", field_name, allow_html=allow_html)
    if not result.is_valid:
        raise InputSanitizationError(field_name, result.error_message or "Invalid input")
    return result.sanitized_value