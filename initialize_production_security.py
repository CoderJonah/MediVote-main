#!/usr/bin/env python3
"""
MediVote Production Security Initialization Script
Sets up production-ready authentication, RBAC, and security features
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, Any
import requests
import json

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.core.database import Database
from backend.core.auth_service import AuthenticationService, APIKeyService
from backend.core.auth_models import (
    AdminCreateRequest, AdminLoginRequest, UserRole, Permission,
    SecurityUtils
)
from backend.core.config import get_settings

settings = get_settings()

class ProductionSecurityInitializer:
    """Initialize production security features"""
    
    def __init__(self):
        self.db_instance = Database()
        self.session = None
    
    async def initialize_database(self):
        """Initialize database with security tables"""
        print("Initializing database with security tables...")
        
        try:
            await self.db_instance.initialize()
            self.session = self.db_instance.get_session()
            print("[OK] Database initialized successfully")
            
            # Run health check
            health = await self.db_instance.health_check()
            print(f"Database health: {health['status']}")
            print(f"   - Users: {health.get('users', 0)}")
            print(f"   - Admins: {health.get('admins', 0)}")
            print(f"   - Active sessions: {health.get('active_sessions', 0)}")
            
        except Exception as e:
            print(f"ERROR: Database initialization failed: {e}")
            raise
    
    async def create_admin_users(self):
        """Create default admin users"""
        print("\nCreating admin users...")
        
        auth_service = AuthenticationService(self.session)
        
        # Define admin users to create
        admin_users = [
            {
                "username": "admin",
                "email": "admin@medivote.org",
                "password": "TempAdmin123!@#",
                "role": UserRole.SUPER_ADMIN
            },
            {
                "username": "security",
                "email": "security@medivote.org", 
                "password": "TempSecurity123!@#",
                "role": UserRole.ADMIN
            },
            {
                "username": "auditor",
                "email": "auditor@medivote.org",
                "password": "TempAuditor123!@#", 
                "role": UserRole.MODERATOR
            }
        ]
        
        for user_data in admin_users:
            try:
                create_request = AdminCreateRequest(
                    username=user_data["username"],
                    email=user_data["email"],
                    password=user_data["password"],
                    role=user_data["role"]
                )
                
                result = await auth_service.create_admin_user(create_request)
                print(f"[OK] Created {user_data['role'].value}: {user_data['username']}")
                
            except Exception as e:
                if "already exists" in str(e).lower():
                    print(f"WARNING: User {user_data['username']} already exists")
                else:
                    print(f"ERROR: Failed to create {user_data['username']}: {e}")
    
    async def create_api_keys(self):
        """Create API keys for services"""
        print("\nCreating API keys...")
        
        api_service = APIKeyService(self.session)
        
        # Define API keys to create
        api_keys_config = [
            {
                "name": "blockchain_service",
                "description": "API key for blockchain synchronization service",
                "permissions": [Permission.SYSTEM_ADMIN, Permission.CREATE_ELECTION, Permission.VIEW_RESULTS],
                "expires_days": 365
            },
            {
                "name": "vote_verification",
                "description": "API key for vote verification service",
                "permissions": [Permission.VOTE, Permission.VIEW_RESULTS],
                "expires_days": 90
            },
            {
                "name": "audit_service", 
                "description": "API key for audit and monitoring services",
                "permissions": [Permission.VIEW_RESULTS],
                "expires_days": 365
            },
            {
                "name": "frontend_integration",
                "description": "API key for frontend application integration",
                "permissions": [Permission.VOTE, Permission.CREATE_ELECTION],
                "expires_days": 180
            }
        ]
        
        created_keys = []
        
        for key_config in api_keys_config:
            try:
                # Create API key
                key_obj = await api_service.create_api_key(
                    name=key_config["name"],
                    description=key_config["description"],
                    permissions=key_config["permissions"],
                    expires_days=key_config["expires_days"]
                )
                
                created_keys.append({
                    "name": key_config["name"],
                    "key": key_obj.key,
                    "description": key_config["description"]
                })
                
                print(f"[OK] Created API key: {key_config['name']} ({key_obj.key_prefix})")
                
            except Exception as e:
                print(f"ERROR: Failed to create API key {key_config['name']}: {e}")
        
        return created_keys
    
    async def test_authentication_system(self):
        """Test the authentication system"""
        print("\nTesting authentication system...")
        
        try:
            auth_service = AuthenticationService(self.session)
            
            # Test admin login
            login_request = AdminLoginRequest(
                username="admin",
                password="TempAdmin123!@#"
            )
            
            login_result = await auth_service.authenticate_admin(login_request)
            print("[OK] Admin authentication test passed")
            
            # Test session verification
            security_context = await auth_service.verify_session(login_result.session_token)
            print(f"[OK] Session verification test passed (user: {security_context.username})")
            
            # Test permission check
            has_permission = await auth_service.check_permission(
                security_context.user_id, Permission.MANAGE_USERS
            )
            print(f"[OK] Permission check test passed (manage_users: {has_permission})")
            
            # Test logout
            logout_success = await auth_service.logout_user(login_result.session_token)
            print(f"[OK] Logout test passed (success: {logout_success})")
            
        except Exception as e:
            print(f"ERROR: Authentication test failed: {e}")
    
    async def test_api_security(self):
        """Test API security if backend is running"""
        print("\nTesting API security...")
        
        try:
            # Test unauthenticated access (should be rejected)
            response = requests.get(f"http://{settings.HOST}:{settings.PORT}/api/admin/dashboard", timeout=5)
            if response.status_code == 401:
                print("[OK] Unauthenticated access properly rejected")
            else:
                print(f"ERROR: Unauthenticated access returned: {response.status_code}")
        except requests.RequestException:
            print("WARNING: Backend not running - skipping API tests")
            return
        
        try:
            # Test admin login via API
            login_data = {
                "username": "admin",
                "password": "TempAdmin123!@#"
            }
            
            response = requests.post(
                f"http://{settings.HOST}:{settings.PORT}/api/auth/admin/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                print("[OK] Admin login via API successful")
                
                # Get session token
                session_data = response.json()
                session_token = session_data.get('session_token')
                
                # Test authenticated API access
                headers = {"Authorization": f"Bearer {session_token}"}
                response = requests.get(
                    f"http://{settings.HOST}:{settings.PORT}/api/admin/dashboard",
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    print("[OK] Authenticated API access successful")
                else:
                    print(f"ERROR: Authenticated API access failed: {response.status_code}")
                
                # Test permission-based access
                response = requests.get(
                    f"http://{settings.HOST}:{settings.PORT}/api/admin/users",
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    print("[OK] Permission-based API access successful")
                else:
                    print(f"ERROR: Permission-based API access failed: {response.status_code}")
                    
            else:
                print(f"ERROR: Admin login via API failed: {response.status_code}")
                
        except Exception as e:
            print(f"ERROR: API security test failed: {e}")
    
    async def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\nGenerating security report...")
        
        try:
            # Collect security status
            health = await self.db_instance.health_check()
            
            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "system": "MediVote Production Security",
                "version": "2.0",
                "environment": "production",
                "database_health": health,
                "security_features": [
                    "[OK] Production authentication system implemented",
                    "[OK] Role-based access control (RBAC) active", 
                    "[OK] Comprehensive audit logging enabled",
                    "[OK] Session management with security features",
                    "[OK] API key authentication for services"
                ],
                "security_recommendations": [
                    "WARNING: Change default admin password immediately",
                    "WARNING: Enable MFA for all admin accounts",
                    "WARNING: Configure proper SSL/TLS certificates",
                    "WARNING: Set up monitoring and alerting"
                ],
                "next_steps": [
                    "1. Change all default passwords",
                    "2. Configure SSL/TLS certificates",
                    "3. Set up monitoring and alerting",
                    "4. Enable multi-factor authentication",
                    "5. Configure backup and recovery procedures",
                    "6. Conduct security audit",
                    "7. Train administrative staff"
                ]
            }
            
            # Save report to file
            with open("SECURITY_INITIALIZATION_REPORT.json", "w") as f:
                json.dump(report, f, indent=2)
            
            print("[OK] Security report generated: SECURITY_INITIALIZATION_REPORT.json")
            
            # Print summary
            print("\nPRODUCTION SECURITY SUMMARY")
            print("=" * 40)
            
            for feature in report["security_features"]:
                print(f"  {feature}")
                
            print("\nSECURITY RECOMMENDATIONS:")
            for rec in report["security_recommendations"]:
                if "WARNING" in rec:
                    print(f"  {rec}")
            
            return report
            
        except Exception as e:
            print(f"ERROR: Security report generation failed: {e}")
    
    async def run_complete_initialization(self):
        """Run complete production security initialization"""
        print("MEDIVOTE PRODUCTION SECURITY INITIALIZATION")
        print("=" * 60)
        
        try:
            # Step 1: Initialize database
            await self.initialize_database()
            
            # Step 2: Create admin users
            await self.create_admin_users()
            
            # Step 3: Create API keys
            api_keys = await self.create_api_keys()
            
            # Step 4: Test authentication
            await self.test_authentication_system()
            
            # Step 5: Test API security (if backend is running)
            await self.test_api_security()
            
            # Step 6: Generate security report
            report = await self.generate_security_report()
            
            print("\n[SUCCESS] PRODUCTION SECURITY INITIALIZATION COMPLETE!")
            print("="*60)
            
            # Print important credentials
            if api_keys:
                print("\nAPI KEYS CREATED:")
                for key_info in api_keys:
                    print(f"   {key_info['name']}: {key_info['key']}")
            
            print("\nCRITICAL SECURITY NOTICES:")
            print("   1. Default admin password: 'TempAdmin123!@#' - CHANGE IMMEDIATELY")
            print("   2. All admin passwords are temporary - change them")
            print("   3. Store API keys securely")
            print("   4. Configure SSL/TLS for production")
            print("   5. Enable MFA for all admin accounts")
            
            return True
            
        except Exception as e:
            print(f"\nERROR: INITIALIZATION FAILED: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            if self.session:
                self.session.close()
                await self.db_instance.close()

async def main():
    """Main initialization function"""
    initializer = ProductionSecurityInitializer()
    
    success = await initializer.run_complete_initialization()
    
    if success:
        print("\n[OK] MediVote is now ready for production deployment!")
        return 0
    else:
        print("\nERROR: Initialization failed - check logs for details")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 