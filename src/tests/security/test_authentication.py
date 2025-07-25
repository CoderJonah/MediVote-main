"""
Authentication Security Tests for MediVote

Tests the authentication system, session management, and API security.
"""

import pytest
import asyncio
import requests
from typing import Dict, Any

# Import MediVote authentication components
from backend.core.auth_service import AuthenticationService
from backend.core.auth_models import AdminLoginRequest, Permission
from backend.core.database import Database


class TestAuthentication:
    """Test suite for authentication and session management"""
    
    @pytest.fixture
    async def auth_service(self):
        """Create authentication service for testing"""
        db = Database()
        await db.initialize()
        session = db.get_session()
        return AuthenticationService(session)
    
    @pytest.fixture
    def admin_login_data(self):
        """Sample admin login data for testing"""
        return {
            "username": "admin",
            "password": "TempAdmin123!@#",
            "device_fingerprint": {"browser": "test", "os": "test"}
        }
    
    @pytest.mark.asyncio
    async def test_admin_authentication(self, auth_service, admin_login_data):
        """Test admin user authentication"""
        login_request = AdminLoginRequest(**admin_login_data)
        
        user, session_token, refresh_token = await auth_service.authenticate_admin(
            login_request,
            "127.0.0.1",
            "Test User Agent"
        )
        
        assert user is not None
        assert session_token is not None
        assert refresh_token is not None
        assert user.username == "admin"
    
    @pytest.mark.asyncio
    async def test_session_verification(self, auth_service, admin_login_data):
        """Test session token verification"""
        # First authenticate to get a session token
        login_request = AdminLoginRequest(**admin_login_data)
        
        user, session_token, refresh_token = await auth_service.authenticate_admin(
            login_request,
            "127.0.0.1",
            "Test User Agent"
        )
        
        # Verify the session
        security_context = await auth_service.verify_session(session_token)
        
        assert security_context is not None
        assert security_context.username == "admin"
        assert security_context.user_id == user.id
    
    @pytest.mark.asyncio
    async def test_permission_checking(self, auth_service, admin_login_data):
        """Test permission-based access control"""
        # Authenticate and get security context
        login_request = AdminLoginRequest(**admin_login_data)
        
        user, session_token, refresh_token = await auth_service.authenticate_admin(
            login_request,
            "127.0.0.1",
            "Test User Agent"
        )
        
        security_context = await auth_service.verify_session(session_token)
        
        # Test permission checking
        has_manage_users = auth_service.has_permission(
            security_context, 
            Permission.MANAGE_USERS
        )
        
        has_view_audit = auth_service.has_permission(
            security_context,
            Permission.VIEW_AUDIT_LOGS
        )
        
        assert has_manage_users is True  # Admin should have all permissions
        assert has_view_audit is True
    
    @pytest.mark.asyncio
    async def test_logout_functionality(self, auth_service, admin_login_data):
        """Test user logout"""
        # Authenticate first
        login_request = AdminLoginRequest(**admin_login_data)
        
        user, session_token, refresh_token = await auth_service.authenticate_admin(
            login_request,
            "127.0.0.1",
            "Test User Agent"
        )
        
        # Logout
        logout_success = await auth_service.logout(session_token)
        assert logout_success is True
        
        # Verify session is invalid after logout
        with pytest.raises(Exception):  # Should raise exception for invalid session
            await auth_service.verify_session(session_token)
    
    @pytest.mark.asyncio
    async def test_invalid_credentials(self, auth_service):
        """Test authentication with invalid credentials"""
        invalid_login = AdminLoginRequest(
            username="invalid_user",
            password="wrong_password",
            device_fingerprint={"browser": "test", "os": "test"}
        )
        
        with pytest.raises(Exception):  # Should raise exception for invalid credentials
            await auth_service.authenticate_admin(
                invalid_login,
                "127.0.0.1",
                "Test User Agent"
            )


class TestAPISecurityIntegration:
    """Integration tests for API security with running backend"""
    
    @pytest.fixture
    def backend_url(self):
        """Backend URL for API testing"""
        return "http://localhost:8000"
    
    @pytest.fixture
    def admin_credentials(self):
        """Admin credentials for API testing"""
        return {
            "username": "admin",
            "password": "TempAdmin123!@#",
            "device_fingerprint": {"browser": "test", "os": "test"}
        }
    
    def test_unauthenticated_access_rejected(self, backend_url):
        """Test that unauthenticated API access is properly rejected"""
        try:
            response = requests.get(f"{backend_url}/api/admin/system/stats", timeout=5)
            assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        except requests.ConnectionError:
            pytest.skip("Backend not running - skipping API integration tests")
    
    def test_admin_login_via_api(self, backend_url, admin_credentials):
        """Test admin login through API endpoint"""
        try:
            response = requests.post(
                f"{backend_url}/api/admin/auth/login",
                json=admin_credentials,
                timeout=5
            )
            
            assert response.status_code == 200, f"Login failed with status {response.status_code}"
            
            session_data = response.json()
            assert "access_token" in session_data
            assert "refresh_token" in session_data
            assert session_data["access_token"] is not None
            
            return session_data["access_token"]
            
        except requests.ConnectionError:
            pytest.skip("Backend not running - skipping API integration tests")
    
    def test_authenticated_api_access(self, backend_url, admin_credentials):
        """Test authenticated API access with valid token"""
        try:
            # First login to get token
            response = requests.post(
                f"{backend_url}/api/admin/auth/login",
                json=admin_credentials,
                timeout=5
            )
            
            if response.status_code != 200:
                pytest.skip("Could not authenticate for API test")
            
            access_token = response.json()["access_token"]
            headers = {"Authorization": f"Bearer {access_token}"}
            
            # Test authenticated access
            response = requests.get(
                f"{backend_url}/api/admin/system/stats",
                headers=headers,
                timeout=5
            )
            
            assert response.status_code == 200, f"Authenticated access failed with status {response.status_code}"
            
        except requests.ConnectionError:
            pytest.skip("Backend not running - skipping API integration tests")
    
    def test_permission_based_api_access(self, backend_url, admin_credentials):
        """Test permission-based API access control"""
        try:
            # Login and get token
            response = requests.post(
                f"{backend_url}/api/admin/auth/login",
                json=admin_credentials,
                timeout=5
            )
            
            if response.status_code != 200:
                pytest.skip("Could not authenticate for API test")
            
            access_token = response.json()["access_token"]
            headers = {"Authorization": f"Bearer {access_token}"}
            
            # Test permission-based endpoint
            response = requests.get(
                f"{backend_url}/api/admin/system/audit-logs",
                headers=headers,
                timeout=5
            )
            
            assert response.status_code == 200, f"Permission-based access failed with status {response.status_code}"
            
        except requests.ConnectionError:
            pytest.skip("Backend not running - skipping API integration tests")


if __name__ == "__main__":
    # Run the tests if this file is executed directly
    pytest.main([__file__, "-v"]) 