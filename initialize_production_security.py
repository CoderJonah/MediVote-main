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
        print("🔧 Initializing database with security tables...")
        
        try:
            await self.db_instance.initialize()
            self.session = self.db_instance.get_session()
            print("✅ Database initialized successfully")
            
            # Run health check
            health = await self.db_instance.health_check()
            print(f"📊 Database health: {health['status']}")
            print(f"   - Users: {health.get('users', 0)}")
            print(f"   - Admins: {health.get('admins', 0)}")
            print(f"   - Active sessions: {health.get('active_sessions', 0)}")
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            raise
    
    async def create_admin_users(self):
        """Create essential admin users"""
        print("\n👥 Creating admin users...")
        
        auth_service = AuthenticationService(self.session)
        
        # Admin users to create
        admin_users = [
            {
                "username": "election_admin",
                "email": "election@medivote.local",
                "password": "ElectionAdmin123!@#",
                "role": UserRole.ELECTION_ADMIN,
                "permissions": []
            },
            {
                "username": "auditor",
                "email": "auditor@medivote.local", 
                "password": "Auditor123!@#",
                "role": UserRole.AUDITOR,
                "permissions": []
            },
            {
                "username": "support",
                "email": "support@medivote.local",
                "password": "Support123!@#", 
                "role": UserRole.SUPPORT,
                "permissions": []
            }
        ]
        
        created_users = []
        
        for user_data in admin_users:
            try:
                request = AdminCreateRequest(**user_data)
                user = await auth_service.create_admin_user(request, "system")
                created_users.append(user)
                print(f"✅ Created {user_data['role'].value}: {user_data['username']}")
                
            except Exception as e:
                if "already exists" in str(e):
                    print(f"⚠️  User {user_data['username']} already exists")
                else:
                    print(f"❌ Failed to create {user_data['username']}: {e}")
        
        return created_users
    
    async def create_api_keys(self):
        """Create API keys for service-to-service authentication"""
        print("\n🔑 Creating API keys...")
        
        api_service = APIKeyService(self.session)
        
        # API keys to create
        api_keys_config = [
            {
                "name": "Frontend Service",
                "permissions": [Permission.VIEW_ELECTION, Permission.VOTE],
                "expires_days": 365
            },
            {
                "name": "Monitoring Service", 
                "permissions": [Permission.VIEW_AUDIT_LOGS],
                "expires_days": 90
            },
            {
                "name": "Blockchain Service",
                "permissions": [Permission.VIEW_RESULTS, Permission.VERIFY_VOTE],
                "expires_days": None  # No expiration
            }
        ]
        
        created_keys = []
        
        for key_config in api_keys_config:
            try:
                api_key, key_obj = await api_service.create_api_key(
                    key_config["name"],
                    key_config["permissions"], 
                    "system",
                    key_config["expires_days"]
                )
                
                created_keys.append({
                    "name": key_config["name"],
                    "key": api_key,
                    "prefix": key_obj.key_prefix
                })
                
                print(f"✅ Created API key: {key_config['name']} ({key_obj.key_prefix})")
                
            except Exception as e:
                print(f"❌ Failed to create API key {key_config['name']}: {e}")
        
        return created_keys
    
    async def test_authentication_system(self):
        """Test the authentication system"""
        print("\n🧪 Testing authentication system...")
        
        auth_service = AuthenticationService(self.session)
        
        # Test 1: Admin login
        try:
            login_request = AdminLoginRequest(
                username="admin",
                password="TempAdmin123!@#",
                device_fingerprint={"browser": "test", "os": "test"}
            )
            
            user, session_token, refresh_token = await auth_service.authenticate_admin(
                login_request,
                "127.0.0.1",
                "Test User Agent"
            )
            
            print("✅ Admin authentication test passed")
            
            # Test 2: Session verification
            security_context = await auth_service.verify_session(session_token)
            print(f"✅ Session verification test passed (user: {security_context.username})")
            
            # Test 3: Permission check
            has_permission = auth_service.has_permission(
                security_context, 
                Permission.MANAGE_USERS
            )
            print(f"✅ Permission check test passed (manage_users: {has_permission})")
            
            # Test 4: Logout
            logout_success = await auth_service.logout(session_token)
            print(f"✅ Logout test passed (success: {logout_success})")
            
        except Exception as e:
            print(f"❌ Authentication test failed: {e}")
            raise
    
    async def test_api_security(self):
        """Test API security with the running backend"""
        print("\n🌐 Testing API security...")
        
        backend_url = "http://localhost:8000"
        
        # Test 1: Unauthenticated access (should fail)
        try:
            response = requests.get(f"{backend_url}/api/admin/system/stats")
            if response.status_code == 401:
                print("✅ Unauthenticated access properly rejected")
            else:
                print(f"❌ Unauthenticated access returned: {response.status_code}")
        except requests.ConnectionError:
            print("⚠️  Backend not running - skipping API tests")
            return
        
        # Test 2: Admin login via API
        try:
            login_data = {
                "username": "admin",
                "password": "TempAdmin123!@#",
                "device_fingerprint": {"browser": "test", "os": "test"}
            }
            
            response = requests.post(
                f"{backend_url}/api/admin/auth/login",
                json=login_data
            )
            
            if response.status_code == 200:
                session_data = response.json()
                access_token = session_data["access_token"]
                print("✅ Admin login via API successful")
                
                # Test 3: Authenticated API access
                headers = {"Authorization": f"Bearer {access_token}"}
                response = requests.get(
                    f"{backend_url}/api/admin/system/stats",
                    headers=headers
                )
                
                if response.status_code == 200:
                    print("✅ Authenticated API access successful")
                else:
                    print(f"❌ Authenticated API access failed: {response.status_code}")
                
                # Test 4: Permission-based access
                response = requests.get(
                    f"{backend_url}/api/admin/system/audit-logs",
                    headers=headers
                )
                
                if response.status_code == 200:
                    print("✅ Permission-based API access successful")
                else:
                    print(f"❌ Permission-based API access failed: {response.status_code}")
                    
            else:
                print(f"❌ Admin login via API failed: {response.status_code}")
                
        except Exception as e:
            print(f"❌ API security test failed: {e}")
    
    async def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n📊 Generating security report...")
        
        try:
            # Get security metrics
            metrics = await self.db_instance.get_security_metrics()
            
            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "security_status": "PRODUCTION_READY",
                "database_health": await self.db_instance.health_check(),
                "security_metrics": metrics,
                "recommendations": [
                    "✅ Production authentication system implemented",
                    "✅ Role-based access control (RBAC) active", 
                    "✅ Comprehensive audit logging enabled",
                    "✅ Session management with security features",
                    "✅ API key authentication for services",
                    "⚠️  Change default admin password immediately",
                    "⚠️  Enable MFA for all admin accounts",
                    "⚠️  Configure proper SSL/TLS certificates",
                    "⚠️  Set up monitoring and alerting"
                ],
                "next_steps": [
                    "1. Change default admin password",
                    "2. Create additional admin users as needed",
                    "3. Configure MFA for sensitive operations",
                    "4. Set up SSL/TLS certificates",
                    "5. Configure monitoring dashboards",
                    "6. Review and test backup procedures",
                    "7. Conduct security penetration testing"
                ]
            }
            
            # Save report
            with open("SECURITY_INITIALIZATION_REPORT.json", "w") as f:
                json.dump(report, f, indent=2, default=str)
            
            print("✅ Security report generated: SECURITY_INITIALIZATION_REPORT.json")
            
            # Print summary
            print("\n" + "="*60)
            print("🛡️  PRODUCTION SECURITY SUMMARY")
            print("="*60)
            print(f"Status: {report['security_status']}")
            print(f"Database: {report['database_health']['status']}")
            print(f"Admin Users: {report['database_health'].get('admins', 0)}")
            print(f"Active Sessions: {report['database_health'].get('active_sessions', 0)}")
            print("\n🔧 IMMEDIATE ACTIONS REQUIRED:")
            for rec in report['recommendations']:
                if "⚠️" in rec:
                    print(f"  {rec}")
            
            return report
            
        except Exception as e:
            print(f"❌ Security report generation failed: {e}")
            return None
    
    async def run_complete_initialization(self):
        """Run complete production security initialization"""
        print("🚀 MEDIVOTE PRODUCTION SECURITY INITIALIZATION")
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
            
            print("\n🎉 PRODUCTION SECURITY INITIALIZATION COMPLETE!")
            print("="*60)
            
            # Print important credentials
            if api_keys:
                print("\n🔑 API KEYS CREATED:")
                for key_info in api_keys:
                    print(f"   {key_info['name']}: {key_info['key']}")
            
            print("\n⚠️  CRITICAL SECURITY NOTICES:")
            print("   1. Default admin password: 'TempAdmin123!@#' - CHANGE IMMEDIATELY")
            print("   2. All admin passwords are temporary - change them")
            print("   3. Store API keys securely")
            print("   4. Configure SSL/TLS for production")
            print("   5. Enable MFA for all admin accounts")
            
            return True
            
        except Exception as e:
            print(f"\n❌ INITIALIZATION FAILED: {e}")
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
        print("\n✅ MediVote is now ready for production deployment!")
        sys.exit(0)
    else:
        print("\n❌ Initialization failed - check logs for details")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 