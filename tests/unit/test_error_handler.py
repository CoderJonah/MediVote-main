#!/usr/bin/env python3
"""
Unit Tests for Error Handling System
Tests all custom exceptions, error responses, and error handling functionality
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from core.error_handler import (
    # Enums
    ErrorSeverity, ErrorCategory,
    
    # Models
    ErrorResponse,
    
    # Base Exception
    MediVoteException,
    
    # Custom Exceptions
    AuthenticationError, AuthorizationError, InvalidCredentialsError,
    SessionExpiredError, MFARequiredError, ValidationError,
    InputSanitizationError, BusinessLogicError, VotingError,
    ElectionStateError, DatabaseError, CryptographyError,
    BlockchainError, ExternalServiceError, RateLimitExceededError,
    
    # Error Handler
    ErrorHandler, error_handler,
    
    # Utility Functions
    handle_database_operation, handle_cryptographic_operation,
    handle_blockchain_operation, validate_input
)


class TestErrorEnums:
    """Test error severity and category enums"""
    
    def test_error_severity_values(self):
        """Test ErrorSeverity enum values"""
        assert ErrorSeverity.LOW == "low"
        assert ErrorSeverity.MEDIUM == "medium"
        assert ErrorSeverity.HIGH == "high"
        assert ErrorSeverity.CRITICAL == "critical"
    
    def test_error_category_values(self):
        """Test ErrorCategory enum values"""
        assert ErrorCategory.AUTHENTICATION == "authentication"
        assert ErrorCategory.AUTHORIZATION == "authorization"
        assert ErrorCategory.VALIDATION == "validation"
        assert ErrorCategory.DATABASE == "database"
        assert ErrorCategory.BLOCKCHAIN == "blockchain"
        assert ErrorCategory.CRYPTOGRAPHY == "cryptography"
        assert ErrorCategory.BUSINESS_LOGIC == "business_logic"
        assert ErrorCategory.SYSTEM == "system"
        assert ErrorCategory.EXTERNAL_SERVICE == "external_service"


class TestErrorResponse:
    """Test ErrorResponse model"""
    
    def test_error_response_creation(self):
        """Test creating ErrorResponse instance"""
        response = ErrorResponse(
            error_id="ERR_TEST_001",
            error_code="TEST_ERROR",
            message="Test error message",
            details={"field": "test_field"},
            request_id="req_123"
        )
        
        assert response.error_id == "ERR_TEST_001"
        assert response.error_code == "TEST_ERROR"
        assert response.message == "Test error message"
        assert response.details == {"field": "test_field"}
        assert response.request_id == "req_123"
        assert response.timestamp is not None
    
    def test_error_response_dict_conversion(self):
        """Test converting ErrorResponse to dict"""
        response = ErrorResponse(
            error_id="ERR_TEST_001",
            error_code="TEST_ERROR",
            message="Test error message"
        )
        
        response_dict = response.dict()
        
        assert response_dict["error_id"] == "ERR_TEST_001"
        assert response_dict["error_code"] == "TEST_ERROR"
        assert response_dict["message"] == "Test error message"
        assert "timestamp" in response_dict


class TestMediVoteException:
    """Test base MediVoteException"""
    
    def test_base_exception_creation(self):
        """Test creating base MediVoteException"""
        exception = MediVoteException(
            message="Test error",
            error_code="TEST_ERROR",
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.HIGH,
            details={"key": "value"}
        )
        
        assert exception.message == "Test error"
        assert exception.error_code == "TEST_ERROR"
        assert exception.category == ErrorCategory.SYSTEM
        assert exception.severity == ErrorSeverity.HIGH
        assert exception.details == {"key": "value"}
        assert exception.error_id is not None
        assert exception.timestamp is not None
    
    def test_exception_error_id_generation(self):
        """Test unique error ID generation"""
        exception1 = MediVoteException(
            message="Test error 1",
            error_code="TEST_ERROR",
            category=ErrorCategory.SYSTEM
        )
        
        exception2 = MediVoteException(
            message="Test error 2",
            error_code="TEST_ERROR",
            category=ErrorCategory.SYSTEM
        )
        
        assert exception1.error_id != exception2.error_id
        assert "SYSTEM" in exception1.error_id
        assert "ERR_" in exception1.error_id
    
    def test_exception_to_dict(self):
        """Test converting exception to dictionary"""
        exception = MediVoteException(
            message="Test error",
            error_code="TEST_ERROR",
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            details={"field": "test"},
            cause=ValueError("Original error")
        )
        
        exception_dict = exception.to_dict()
        
        assert exception_dict["message"] == "Test error"
        assert exception_dict["error_code"] == "TEST_ERROR"
        assert exception_dict["category"] == "validation"
        assert exception_dict["severity"] == "medium"
        assert exception_dict["details"] == {"field": "test"}
        assert "Original error" in exception_dict["cause"]


class TestAuthenticationExceptions:
    """Test authentication-related exceptions"""
    
    def test_authentication_error(self):
        """Test AuthenticationError creation"""
        error = AuthenticationError(
            message="Authentication failed",
            details={"reason": "invalid_password"}
        )
        
        assert error.message == "Authentication failed"
        assert error.error_code == "AUTHENTICATION_FAILED"
        assert error.category == ErrorCategory.AUTHENTICATION
        assert error.severity == ErrorSeverity.HIGH
        assert error.details == {"reason": "invalid_password"}
    
    def test_invalid_credentials_error(self):
        """Test InvalidCredentialsError creation"""
        error = InvalidCredentialsError(credential_type="username")
        
        assert error.message == "Invalid credentials provided"
        assert error.error_code == "INVALID_CREDENTIALS"
        assert error.details == {"credential_type": "username"}
    
    def test_session_expired_error(self):
        """Test SessionExpiredError creation"""
        error = SessionExpiredError(session_id="session_123")
        
        assert "expired" in error.message.lower()
        assert error.error_code == "SESSION_EXPIRED"
        assert error.details == {"session_id": "session_123"}
    
    def test_mfa_required_error(self):
        """Test MFARequiredError creation"""
        error = MFARequiredError(mfa_methods=["totp", "sms"])
        
        assert "multi-factor" in error.message.lower()
        assert error.error_code == "MFA_REQUIRED"
        assert error.details == {"available_methods": ["totp", "sms"]}


class TestAuthorizationExceptions:
    """Test authorization-related exceptions"""
    
    def test_authorization_error(self):
        """Test AuthorizationError creation"""
        error = AuthorizationError(
            message="Access denied",
            required_permission="admin_read"
        )
        
        assert error.message == "Access denied"
        assert error.error_code == "AUTHORIZATION_FAILED"
        assert error.category == ErrorCategory.AUTHORIZATION
        assert error.severity == ErrorSeverity.HIGH
        assert error.details == {"required_permission": "admin_read"}


class TestValidationExceptions:
    """Test validation-related exceptions"""
    
    def test_validation_error(self):
        """Test ValidationError creation"""
        error = ValidationError(
            message="Validation failed",
            field="email",
            value="invalid-email",
            details={"pattern": "email_format"}
        )
        
        assert error.message == "Validation failed"
        assert error.error_code == "VALIDATION_FAILED"
        assert error.category == ErrorCategory.VALIDATION
        assert error.severity == ErrorSeverity.MEDIUM
        assert error.details["field"] == "email"
        assert "invalid-email" in error.details["invalid_value"]
    
    def test_input_sanitization_error(self):
        """Test InputSanitizationError creation"""
        error = InputSanitizationError(
            field="user_input",
            reason="Contains SQL injection attempt"
        )
        
        assert "Input validation failed" in error.message
        assert error.error_code == "INVALID_INPUT"
        assert error.details["field"] == "user_input"
        assert error.details["reason"] == "Contains SQL injection attempt"


class TestBusinessLogicExceptions:
    """Test business logic exceptions"""
    
    def test_business_logic_error(self):
        """Test BusinessLogicError creation"""
        error = BusinessLogicError(
            message="Business rule violated",
            rule="max_votes_per_user",
            details={"current_votes": 3, "max_allowed": 1}
        )
        
        assert error.message == "Business rule violated"
        assert error.error_code == "BUSINESS_RULE_VIOLATION"
        assert error.category == ErrorCategory.BUSINESS_LOGIC
        assert error.details["violated_rule"] == "max_votes_per_user"
    
    def test_voting_error(self):
        """Test VotingError creation"""
        error = VotingError(
            message="Voting operation failed",
            election_id="election_123",
            voter_id="voter_456"
        )
        
        assert error.message == "Voting operation failed"
        assert error.error_code == "VOTING_ERROR"
        assert error.details == {"election_id": "election_123", "voter_id": "voter_456"}
    
    def test_election_state_error(self):
        """Test ElectionStateError creation"""
        error = ElectionStateError(
            message="Invalid election state",
            current_state="draft",
            required_state="active"
        )
        
        assert error.message == "Invalid election state"
        assert error.error_code == "INVALID_ELECTION_STATE"
        assert error.details == {"current_state": "draft", "required_state": "active"}


class TestSystemExceptions:
    """Test system and infrastructure exceptions"""
    
    def test_database_error(self):
        """Test DatabaseError creation"""
        original_error = Exception("Connection timeout")
        error = DatabaseError(
            message="Database operation failed",
            operation="SELECT",
            table="users",
            cause=original_error
        )
        
        assert error.message == "Database operation failed"
        assert error.error_code == "DATABASE_ERROR"
        assert error.category == ErrorCategory.DATABASE
        assert error.severity == ErrorSeverity.HIGH
        assert error.details == {"operation": "SELECT", "table": "users"}
        assert error.cause == original_error
    
    def test_cryptography_error(self):
        """Test CryptographyError creation"""
        error = CryptographyError(
            message="Encryption failed",
            operation="AES_encrypt"
        )
        
        assert error.message == "Encryption failed"
        assert error.error_code == "CRYPTOGRAPHY_ERROR"
        assert error.category == ErrorCategory.CRYPTOGRAPHY
        assert error.severity == ErrorSeverity.CRITICAL
        assert error.details == {"operation": "AES_encrypt"}
    
    def test_blockchain_error(self):
        """Test BlockchainError creation"""
        error = BlockchainError(
            message="Block validation failed",
            operation="validate_block",
            block_hash="0x123456"
        )
        
        assert error.message == "Block validation failed"
        assert error.error_code == "BLOCKCHAIN_ERROR"
        assert error.category == ErrorCategory.BLOCKCHAIN
        assert error.details == {"operation": "validate_block", "block_hash": "0x123456"}
    
    def test_external_service_error(self):
        """Test ExternalServiceError creation"""
        error = ExternalServiceError(
            message="External API failed",
            service="identity_verification",
            status_code=503
        )
        
        assert error.message == "External API failed"
        assert error.error_code == "EXTERNAL_SERVICE_ERROR"
        assert error.category == ErrorCategory.EXTERNAL_SERVICE
        assert error.details == {"service": "identity_verification", "status_code": 503}
    
    def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError creation"""
        error = RateLimitExceededError(
            limit=100,
            window="1 hour",
            retry_after=3600
        )
        
        assert "Rate limit exceeded" in error.message
        assert error.error_code == "RATE_LIMIT_EXCEEDED"
        assert error.category == ErrorCategory.SYSTEM
        assert error.details == {"limit": 100, "window": "1 hour", "retry_after_seconds": 3600}


class TestErrorHandler:
    """Test ErrorHandler functionality"""
    
    @pytest.fixture
    def handler(self):
        """Create fresh ErrorHandler instance"""
        return ErrorHandler()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock FastAPI request"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.__str__ = Mock(return_value="https://api.example.com/test")
        request.headers = {"user-agent": "TestAgent/1.0", "x-request-id": "req_123"}
        request.client = Mock()
        request.client.host = "192.168.1.1"
        return request
    
    def test_log_error_medivote_exception(self, handler, mock_request):
        """Test logging MediVote custom exception"""
        error = AuthenticationError("Login failed", details={"reason": "invalid_password"})
        
        with patch('core.error_handler.logger') as mock_logger:
            handler.log_error(error, mock_request, user_id="user_123")
            
            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args
            
            # Check log message format
            assert "AUTHENTICATION" in call_args[0][0]
            assert "AUTHENTICATION_FAILED" in call_args[0][0]
            assert "Login failed" in call_args[0][0]
            
            # Check extra data
            extra_data = call_args[1]["extra"]
            assert extra_data["error_id"] == error.error_id
            assert extra_data["error_code"] == "AUTHENTICATION_FAILED"
            assert extra_data["category"] == "authentication"
            assert extra_data["severity"] == "high"
    
    def test_log_error_generic_exception(self, handler, mock_request):
        """Test logging generic exception"""
        error = ValueError("Generic error")
        
        with patch('core.error_handler.logger') as mock_logger:
            handler.log_error(error, mock_request)
            
            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args
            
            assert "Unhandled exception" in call_args[0][0]
            assert "ValueError" in call_args[0][0]
            assert "Generic error" in call_args[0][0]
    
    def test_create_error_response_medivote_exception(self, handler, mock_request):
        """Test creating error response for MediVote exception"""
        error = ValidationError("Invalid input", field="email")
        
        response = handler.create_error_response(error, mock_request, include_details=True)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Parse response content
        content = json.loads(response.body.decode())
        assert content["error_id"] == error.error_id
        assert content["error_code"] == "VALIDATION_FAILED"
        assert content["message"] == "Invalid input"
        assert content["details"]["field"] == "email"
        assert content["request_id"] == "req_123"
    
    def test_create_error_response_http_exception(self, handler, mock_request):
        """Test creating error response for HTTP exception"""
        error = HTTPException(status_code=404, detail="Not found")
        
        response = handler.create_error_response(error, mock_request)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        
        content = json.loads(response.body.decode())
        assert content["error_code"] == "HTTP_ERROR"
        assert content["message"] == "Not found"
    
    def test_create_error_response_validation_error(self, handler, mock_request):
        """Test creating error response for FastAPI validation error"""
        # Mock RequestValidationError
        validation_error = RequestValidationError([
            {
                "loc": ("body", "email"),
                "msg": "field required",
                "type": "value_error.missing"
            }
        ])
        
        response = handler.create_error_response(validation_error, mock_request, include_details=True)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        content = json.loads(response.body.decode())
        assert content["error_code"] == "VALIDATION_ERROR"
        assert content["message"] == "Request validation failed"
        assert "validation_errors" in content["details"]
    
    def test_create_error_response_generic_exception(self, handler, mock_request):
        """Test creating error response for generic exception"""
        error = RuntimeError("Unexpected error")
        
        response = handler.create_error_response(error, mock_request)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        content = json.loads(response.body.decode())
        assert content["error_code"] == "INTERNAL_SERVER_ERROR"
        assert content["message"] == "An internal server error occurred"
    
    def test_get_http_status_code_mapping(self, handler):
        """Test HTTP status code mapping for different exception types"""
        # Test various exception types and their expected status codes
        test_cases = [
            (AuthenticationError("test"), status.HTTP_401_UNAUTHORIZED),
            (AuthorizationError("test"), status.HTTP_403_FORBIDDEN),
            (ValidationError("test"), status.HTTP_422_UNPROCESSABLE_ENTITY),
            (BusinessLogicError("test"), status.HTTP_400_BAD_REQUEST),
            (DatabaseError("test"), status.HTTP_500_INTERNAL_SERVER_ERROR),
            (CryptographyError("test"), status.HTTP_500_INTERNAL_SERVER_ERROR),
            (BlockchainError("test"), status.HTTP_500_INTERNAL_SERVER_ERROR),
            (ExternalServiceError("test", "service"), status.HTTP_502_BAD_GATEWAY),
            (RateLimitExceededError(10, "minute"), status.HTTP_429_TOO_MANY_REQUESTS)
        ]
        
        for exception, expected_status in test_cases:
            actual_status = handler._get_http_status_code(exception)
            assert actual_status == expected_status, f"Failed for {type(exception).__name__}"
    
    def test_error_statistics_tracking(self, handler):
        """Test error statistics tracking"""
        # Generate some errors
        error1 = AuthenticationError("Login failed")
        error2 = ValidationError("Invalid input")
        error3 = AuthenticationError("Token expired")
        
        # Log errors to update statistics
        handler.log_error(error1)
        handler.log_error(error2)
        handler.log_error(error3)
        
        stats = handler.get_error_statistics()
        
        assert stats["total_errors"] == 3
        assert stats["error_breakdown"]["AUTHENTICATION_FAILED"] == 2
        assert stats["error_breakdown"]["VALIDATION_FAILED"] == 1
        assert "last_updated" in stats


class TestUtilityFunctions:
    """Test utility functions for error handling"""
    
    @pytest.mark.asyncio
    async def test_handle_database_operation_success(self):
        """Test successful database operation wrapper"""
        async def mock_db_operation(param1, param2):
            return {"result": f"success with {param1} and {param2}"}
        
        result = await handle_database_operation(
            mock_db_operation, 
            "test_operation",
            param1="value1",
            param2="value2"
        )
        
        assert result["result"] == "success with value1 and value2"
    
    @pytest.mark.asyncio
    async def test_handle_database_operation_failure(self):
        """Test database operation wrapper with failure"""
        async def mock_db_operation():
            raise Exception("Database connection failed")
        
        with pytest.raises(DatabaseError) as exc_info:
            await handle_database_operation(mock_db_operation, "test_operation")
        
        assert exc_info.value.message == "Database operation 'test_operation' failed"
        assert exc_info.value.details["operation"] == "test_operation"
        assert isinstance(exc_info.value.cause, Exception)
    
    @pytest.mark.asyncio
    async def test_handle_cryptographic_operation_success(self):
        """Test successful cryptographic operation wrapper"""
        async def mock_crypto_operation(data):
            return f"encrypted_{data}"
        
        result = await handle_cryptographic_operation(
            mock_crypto_operation,
            "encrypt",
            data="test_data"
        )
        
        assert result == "encrypted_test_data"
    
    @pytest.mark.asyncio
    async def test_handle_cryptographic_operation_failure(self):
        """Test cryptographic operation wrapper with failure"""
        async def mock_crypto_operation():
            raise Exception("Key not found")
        
        with pytest.raises(CryptographyError) as exc_info:
            await handle_cryptographic_operation(mock_crypto_operation, "decrypt")
        
        assert exc_info.value.message == "Cryptographic operation 'decrypt' failed"
        assert exc_info.value.details["operation"] == "decrypt"
        assert exc_info.value.severity == ErrorSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_handle_blockchain_operation_success(self):
        """Test successful blockchain operation wrapper"""
        async def mock_blockchain_operation(block_data):
            return {"block_hash": f"0x{hash(block_data)}"}
        
        result = await handle_blockchain_operation(
            mock_blockchain_operation,
            "add_block",
            block_data="test_block"
        )
        
        assert "block_hash" in result
    
    @pytest.mark.asyncio
    async def test_handle_blockchain_operation_failure(self):
        """Test blockchain operation wrapper with failure"""
        async def mock_blockchain_operation():
            raise Exception("Invalid block")
        
        with pytest.raises(BlockchainError) as exc_info:
            await handle_blockchain_operation(mock_blockchain_operation, "validate_block")
        
        assert exc_info.value.message == "Blockchain operation 'validate_block' failed"
        assert exc_info.value.details["operation"] == "validate_block"
    
    def test_validate_input_success(self):
        """Test successful input validation"""
        def is_email(value):
            return "@" in value and "." in value
        
        result = validate_input("test@example.com", "email", is_email)
        assert result == "test@example.com"
    
    def test_validate_input_failure(self):
        """Test input validation failure"""
        def is_email(value):
            return "@" in value and "." in value
        
        with pytest.raises(InputSanitizationError) as exc_info:
            validate_input("invalid-email", "email", is_email, "Must be valid email")
        
        assert exc_info.value.details["field"] == "email"
        assert exc_info.value.details["reason"] == "Must be valid email"
    
    def test_validate_input_exception_during_validation(self):
        """Test input validation when validation function raises exception"""
        def problematic_validator(value):
            raise ValueError("Validator failed")
        
        with pytest.raises(ValidationError) as exc_info:
            validate_input("test_value", "test_field", problematic_validator)
        
        assert exc_info.value.details["field"] == "test_field"
        assert exc_info.value.details["invalid_value"] == "test_value"
        assert isinstance(exc_info.value.cause, ValueError)


class TestGlobalErrorHandler:
    """Test global error handler instance"""
    
    def test_global_error_handler_exists(self):
        """Test that global error handler instance exists"""
        assert error_handler is not None
        assert isinstance(error_handler, ErrorHandler)
    
    def test_global_error_handler_functionality(self):
        """Test global error handler basic functionality"""
        initial_stats = error_handler.get_error_statistics()
        initial_count = initial_stats["total_errors"]
        
        # Log an error
        test_error = ValidationError("Test validation error")
        error_handler.log_error(test_error)
        
        # Check statistics updated
        updated_stats = error_handler.get_error_statistics()
        assert updated_stats["total_errors"] == initial_count + 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])