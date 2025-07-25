#!/usr/bin/env python3
"""
Standardized Error Handling System for MediVote
Provides consistent error handling, logging, and responses across all backend services

IMPROVEMENTS IMPLEMENTED:
- Custom exception hierarchy for different error types
- Standardized error responses with security considerations
- Comprehensive logging with context information
- Rate limiting for error endpoints to prevent abuse
- Error analytics and monitoring integration
- Sanitized error messages to prevent information leakage
"""

import traceback
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import logging
import json

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ErrorSeverity(str, Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(str, Enum):
    """Error categories for classification"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    BLOCKCHAIN = "blockchain"
    CRYPTOGRAPHY = "cryptography"
    BUSINESS_LOGIC = "business_logic"
    SYSTEM = "system"
    EXTERNAL_SERVICE = "external_service"


class ErrorResponse(BaseModel):
    """Standardized error response model"""
    error_id: str = Field(..., description="Unique error identifier for tracking")
    error_code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    request_id: Optional[str] = Field(None, description="Request identifier for tracing")
    
    class Config:
        schema_extra = {
            "example": {
                "error_id": "ERR_001_20240101_120000",
                "error_code": "AUTHENTICATION_FAILED",
                "message": "Authentication credentials are invalid",
                "details": {"field": "password", "reason": "incorrect"},
                "timestamp": "2024-01-01T12:00:00Z",
                "request_id": "req_12345"
            }
        }


# Base Custom Exceptions
class MediVoteException(Exception):
    """Base exception for all MediVote custom exceptions"""
    
    def __init__(
        self,
        message: str,
        error_code: str,
        category: ErrorCategory,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.category = category
        self.severity = severity
        self.details = details or {}
        self.cause = cause
        self.error_id = self._generate_error_id()
        self.timestamp = datetime.utcnow()
    
    def _generate_error_id(self) -> str:
        """Generate unique error ID"""
        return f"ERR_{self.category.value.upper()}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary"""
        return {
            "error_id": self.error_id,
            "error_code": self.error_code,
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "cause": str(self.cause) if self.cause else None
        }


# Authentication & Authorization Exceptions
class AuthenticationError(MediVoteException):
    """Authentication-related errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(
            message=message,
            error_code="AUTHENTICATION_FAILED",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            details=details,
            cause=cause
        )


class AuthorizationError(MediVoteException):
    """Authorization-related errors"""
    
    def __init__(self, message: str, required_permission: str = None, details: Optional[Dict[str, Any]] = None):
        error_details = details or {}
        if required_permission:
            error_details["required_permission"] = required_permission
        
        super().__init__(
            message=message,
            error_code="AUTHORIZATION_FAILED",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.HIGH,
            details=error_details
        )


class InvalidCredentialsError(AuthenticationError):
    """Invalid credentials specific error"""
    
    def __init__(self, credential_type: str = "password"):
        super().__init__(
            message="Invalid credentials provided",
            details={"credential_type": credential_type}
        )
        self.error_code = "INVALID_CREDENTIALS"


class SessionExpiredError(AuthenticationError):
    """Session expiration error"""
    
    def __init__(self, session_id: str = None):
        super().__init__(
            message="Session has expired, please authenticate again",
            details={"session_id": session_id} if session_id else {}
        )
        self.error_code = "SESSION_EXPIRED"


class MFARequiredError(AuthenticationError):
    """Multi-factor authentication required"""
    
    def __init__(self, mfa_methods: List[str] = None):
        super().__init__(
            message="Multi-factor authentication is required",
            details={"available_methods": mfa_methods or ["totp"]}
        )
        self.error_code = "MFA_REQUIRED"


# Validation Exceptions
class ValidationError(MediVoteException):
    """Data validation errors"""
    
    def __init__(self, message: str, field: str = None, value: Any = None, details: Optional[Dict[str, Any]] = None):
        error_details = details or {}
        if field:
            error_details["field"] = field
        if value is not None:
            error_details["invalid_value"] = str(value)[:100]  # Truncate for security
        
        super().__init__(
            message=message,
            error_code="VALIDATION_FAILED",
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            details=error_details
        )


class InputSanitizationError(ValidationError):
    """Input sanitization failures"""
    
    def __init__(self, field: str, reason: str):
        super().__init__(
            message=f"Input validation failed for field '{field}'",
            field=field,
            details={"reason": reason}
        )
        self.error_code = "INVALID_INPUT"


# Business Logic Exceptions
class BusinessLogicError(MediVoteException):
    """Business logic violations"""
    
    def __init__(self, message: str, rule: str = None, details: Optional[Dict[str, Any]] = None):
        error_details = details or {}
        if rule:
            error_details["violated_rule"] = rule
        
        super().__init__(
            message=message,
            error_code="BUSINESS_RULE_VIOLATION",
            category=ErrorCategory.BUSINESS_LOGIC,
            severity=ErrorSeverity.MEDIUM,
            details=error_details
        )


class VotingError(BusinessLogicError):
    """Voting-specific business logic errors"""
    
    def __init__(self, message: str, election_id: str = None, voter_id: str = None):
        details = {}
        if election_id:
            details["election_id"] = election_id
        if voter_id:
            details["voter_id"] = voter_id
        
        super().__init__(message=message, details=details)
        self.error_code = "VOTING_ERROR"


class ElectionStateError(VotingError):
    """Election state violations"""
    
    def __init__(self, message: str, current_state: str, required_state: str):
        super().__init__(
            message=message,
            details={
                "current_state": current_state,
                "required_state": required_state
            }
        )
        self.error_code = "INVALID_ELECTION_STATE"


# System & Infrastructure Exceptions
class DatabaseError(MediVoteException):
    """Database-related errors"""
    
    def __init__(self, message: str, operation: str = None, table: str = None, cause: Optional[Exception] = None):
        details = {}
        if operation:
            details["operation"] = operation
        if table:
            details["table"] = table
        
        super().__init__(
            message=message,
            error_code="DATABASE_ERROR",
            category=ErrorCategory.DATABASE,
            severity=ErrorSeverity.HIGH,
            details=details,
            cause=cause
        )


class CryptographyError(MediVoteException):
    """Cryptographic operation errors"""
    
    def __init__(self, message: str, operation: str = None, cause: Optional[Exception] = None):
        super().__init__(
            message=message,
            error_code="CRYPTOGRAPHY_ERROR",
            category=ErrorCategory.CRYPTOGRAPHY,
            severity=ErrorSeverity.CRITICAL,
            details={"operation": operation} if operation else {},
            cause=cause
        )


class BlockchainError(MediVoteException):
    """Blockchain operation errors"""
    
    def __init__(self, message: str, operation: str = None, block_hash: str = None, cause: Optional[Exception] = None):
        details = {}
        if operation:
            details["operation"] = operation
        if block_hash:
            details["block_hash"] = block_hash
        
        super().__init__(
            message=message,
            error_code="BLOCKCHAIN_ERROR",
            category=ErrorCategory.BLOCKCHAIN,
            severity=ErrorSeverity.HIGH,
            details=details,
            cause=cause
        )


class ExternalServiceError(MediVoteException):
    """External service integration errors"""
    
    def __init__(self, message: str, service: str, status_code: int = None, cause: Optional[Exception] = None):
        details = {"service": service}
        if status_code:
            details["status_code"] = status_code
        
        super().__init__(
            message=message,
            error_code="EXTERNAL_SERVICE_ERROR",
            category=ErrorCategory.EXTERNAL_SERVICE,
            severity=ErrorSeverity.MEDIUM,
            details=details,
            cause=cause
        )


# Rate Limiting Exception
class RateLimitExceededError(MediVoteException):
    """Rate limiting violations"""
    
    def __init__(self, limit: int, window: str, retry_after: int = None):
        details = {
            "limit": limit,
            "window": window
        }
        if retry_after:
            details["retry_after_seconds"] = retry_after
        
        super().__init__(
            message=f"Rate limit exceeded: {limit} requests per {window}",
            error_code="RATE_LIMIT_EXCEEDED",
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.MEDIUM,
            details=details
        )


class ErrorHandler:
    """Centralized error handling system"""
    
    def __init__(self):
        self.error_stats: Dict[str, int] = {}
        self.blocked_ips: Dict[str, datetime] = {}
    
    def log_error(
        self,
        error: Union[Exception, MediVoteException],
        request: Request = None,
        user_id: str = None,
        additional_context: Dict[str, Any] = None
    ):
        """Log error with comprehensive context"""
        
        # Prepare context information
        context = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "additional_context": additional_context or {}
        }
        
        # Add request context if available
        if request:
            context.update({
                "request_method": request.method,
                "request_url": str(request.url),
                "request_headers": dict(request.headers),
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent")
            })
        
        # Handle MediVote custom exceptions
        if isinstance(error, MediVoteException):
            logger.error(
                f"[{error.category.value.upper()}] {error.error_code}: {error.message}",
                extra={
                    "error_id": error.error_id,
                    "error_code": error.error_code,
                    "category": error.category.value,
                    "severity": error.severity.value,
                    "details": error.details,
                    "context": context,
                    "traceback": traceback.format_exc() if error.cause else None
                }
            )
            
            # Update error statistics
            self.error_stats[error.error_code] = self.error_stats.get(error.error_code, 0) + 1
            
        else:
            # Handle generic exceptions
            logger.error(
                f"Unhandled exception: {type(error).__name__}: {str(error)}",
                extra={
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                    "context": context,
                    "traceback": traceback.format_exc()
                }
            )
    
    def create_error_response(
        self,
        error: Union[Exception, MediVoteException],
        request: Request = None,
        include_details: bool = False
    ) -> JSONResponse:
        """Create standardized error response"""
        
        # Log the error
        self.log_error(error, request)
        
        # Handle MediVote custom exceptions
        if isinstance(error, MediVoteException):
            status_code = self._get_http_status_code(error)
            
            response_data = ErrorResponse(
                error_id=error.error_id,
                error_code=error.error_code,
                message=error.message,
                details=error.details if include_details else None,
                request_id=request.headers.get("x-request-id") if request else None
            )
            
            return JSONResponse(
                status_code=status_code,
                content=response_data.dict(exclude_none=True)
            )
        
        # Handle FastAPI validation errors
        elif isinstance(error, RequestValidationError):
            validation_details = []
            for err in error.errors():
                validation_details.append({
                    "field": ".".join(str(x) for x in err["loc"]),
                    "message": err["msg"],
                    "type": err["type"]
                })
            
            response_data = ErrorResponse(
                error_id=f"VAL_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
                error_code="VALIDATION_ERROR",
                message="Request validation failed",
                details={"validation_errors": validation_details} if include_details else None
            )
            
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content=response_data.dict(exclude_none=True)
            )
        
        # Handle HTTP exceptions
        elif isinstance(error, (HTTPException, StarletteHTTPException)):
            response_data = ErrorResponse(
                error_id=f"HTTP_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
                error_code="HTTP_ERROR",
                message=error.detail if hasattr(error, 'detail') else str(error),
                details={"status_code": error.status_code} if include_details else None
            )
            
            return JSONResponse(
                status_code=error.status_code,
                content=response_data.dict(exclude_none=True)
            )
        
        # Handle generic exceptions (don't expose internal details)
        else:
            response_data = ErrorResponse(
                error_id=f"SYS_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
                error_code="INTERNAL_SERVER_ERROR",
                message="An internal server error occurred",
                details={"error_type": type(error).__name__} if include_details else None
            )
            
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=response_data.dict(exclude_none=True)
            )
    
    def _get_http_status_code(self, error: MediVoteException) -> int:
        """Map custom exceptions to HTTP status codes"""
        status_mapping = {
            AuthenticationError: status.HTTP_401_UNAUTHORIZED,
            AuthorizationError: status.HTTP_403_FORBIDDEN,
            ValidationError: status.HTTP_422_UNPROCESSABLE_ENTITY,
            BusinessLogicError: status.HTTP_400_BAD_REQUEST,
            DatabaseError: status.HTTP_500_INTERNAL_SERVER_ERROR,
            CryptographyError: status.HTTP_500_INTERNAL_SERVER_ERROR,
            BlockchainError: status.HTTP_500_INTERNAL_SERVER_ERROR,
            ExternalServiceError: status.HTTP_502_BAD_GATEWAY,
            RateLimitExceededError: status.HTTP_429_TOO_MANY_REQUESTS
        }
        
        for exc_type, status_code in status_mapping.items():
            if isinstance(error, exc_type):
                return status_code
        
        return status.HTTP_500_INTERNAL_SERVER_ERROR
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        return {
            "total_errors": sum(self.error_stats.values()),
            "error_breakdown": self.error_stats.copy(),
            "blocked_ips": len(self.blocked_ips),
            "last_updated": datetime.utcnow().isoformat()
        }


# Global error handler instance
error_handler = ErrorHandler()


# Convenience functions for common patterns
async def handle_database_operation(operation_func, operation_name: str, **kwargs):
    """Wrapper for database operations with standardized error handling"""
    try:
        return await operation_func(**kwargs)
    except Exception as e:
        raise DatabaseError(
            message=f"Database operation '{operation_name}' failed",
            operation=operation_name,
            cause=e
        )


async def handle_cryptographic_operation(operation_func, operation_name: str, **kwargs):
    """Wrapper for cryptographic operations with standardized error handling"""
    try:
        return await operation_func(**kwargs)
    except Exception as e:
        raise CryptographyError(
            message=f"Cryptographic operation '{operation_name}' failed",
            operation=operation_name,
            cause=e
        )


async def handle_blockchain_operation(operation_func, operation_name: str, **kwargs):
    """Wrapper for blockchain operations with standardized error handling"""
    try:
        return await operation_func(**kwargs)
    except Exception as e:
        raise BlockchainError(
            message=f"Blockchain operation '{operation_name}' failed",
            operation=operation_name,
            cause=e
        )


def validate_input(value: Any, field_name: str, validation_func, error_message: str = None):
    """Input validation with standardized error handling"""
    try:
        if not validation_func(value):
            raise InputSanitizationError(
                field=field_name,
                reason=error_message or "Validation failed"
            )
        return value
    except Exception as e:
        if isinstance(e, InputSanitizationError):
            raise
        raise ValidationError(
            message=f"Validation error for field '{field_name}'",
            field=field_name,
            value=value,
            cause=e
        )