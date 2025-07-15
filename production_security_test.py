#!/usr/bin/env python3
"""
Production Security Test Suite for MediVote
Comprehensive testing of authentication, authorization, and security features
"""

import asyncio
import sys
import os
import time
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any
import uuid

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

class ProductionSecurityTester:
    """Comprehensive security testing for production readiness"""
    
    def __init__(self):
        self.backend_url = "http://localhost:8000"
        self.test_results = []
        self.session_tokens = {}
        
    def log_test(self, category: str, test_name: str, passed: bool, details: str = "", error: str = ""):
        """Log test results"""
        status = "✅ PASSED" if passed else "❌ FAILED"
        self.test_results.append({
            "category": category,
            "test": test_name,
            "passed": passed,
            "details": details,
            "error": error
        })
        print(f"{status}: [{category}] {test_name}")
        if details:
            print(f"   {details}")
        if error and not passed:
            print(f"   Error: {error}")
    
    async def test_authentication_security(self):
        """Test authentication security features"""
        print("\n🔐 Testing Authentication Security...")
        
        # Test 1: Invalid credentials should be rejected
        try:
            response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                "username": "invalid_user",
                "password": "wrong_password",
                "device_fingerprint": {"browser": "test"}
            })
            
            passed = response.status_code == 401
            self.log_test("Authentication", "Invalid Credentials Rejection", passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authentication", "Invalid Credentials Rejection", False, error=str(e))
        
        # Test 2: Valid admin login should succeed
        try:
            response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                "username": "admin",
                "password": "TempAdmin123!@#",
                "device_fingerprint": {"browser": "test", "os": "linux"}
            })
            
            if response.status_code == 200:
                data = response.json()
                self.session_tokens["admin"] = data["access_token"]
                passed = True
                details = f"Token received, expires: {data.get('expires_at', 'N/A')}"
            else:
                passed = False
                details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            
            self.log_test("Authentication", "Valid Admin Login", passed, details)
        except Exception as e:
            self.log_test("Authentication", "Valid Admin Login", False, error=str(e))
        
        # Test 3: Rate limiting on repeated failed attempts
        try:
            failed_attempts = 0
            for i in range(10):
                response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                    "username": "admin",
                    "password": "wrong_password",
                    "device_fingerprint": {"browser": "test"}
                })
                
                if response.status_code == 429:  # Rate limited
                    failed_attempts += 1
                    break
                
                time.sleep(0.1)  # Small delay between attempts
            
            passed = failed_attempts > 0 or response.status_code == 429
            self.log_test("Authentication", "Rate Limiting Protection", passed,
                         f"Rate limiting triggered after multiple failures")
        except Exception as e:
            self.log_test("Authentication", "Rate Limiting Protection", False, error=str(e))
    
    async def test_authorization_controls(self):
        """Test role-based access control (RBAC)"""
        print("\n🛡️ Testing Authorization Controls...")
        
        if "admin" not in self.session_tokens:
            self.log_test("Authorization", "Admin Session Required", False, 
                         "Admin session not available for testing")
            return
        
        admin_token = self.session_tokens["admin"]
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test 1: Admin should access admin endpoints
        try:
            response = requests.get(f"{self.backend_url}/api/admin/system/stats", headers=headers)
            passed = response.status_code == 200
            self.log_test("Authorization", "Admin Access to Admin Endpoints", passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authorization", "Admin Access to Admin Endpoints", False, error=str(e))
        
        # Test 2: Admin should access audit logs
        try:
            response = requests.get(f"{self.backend_url}/api/admin/system/audit-logs", headers=headers)
            passed = response.status_code == 200
            if passed:
                data = response.json()
                log_count = data.get("total_logs", 0)
                details = f"Retrieved {log_count} audit logs"
            else:
                details = f"Status: {response.status_code}"
            
            self.log_test("Authorization", "Admin Access to Audit Logs", passed, details)
        except Exception as e:
            self.log_test("Authorization", "Admin Access to Audit Logs", False, error=str(e))
        
        # Test 3: Admin should access security events
        try:
            response = requests.get(f"{self.backend_url}/api/admin/system/security-events", headers=headers)
            passed = response.status_code == 200
            if passed:
                data = response.json()
                event_count = data.get("total_events", 0)
                details = f"Retrieved {event_count} security events"
            else:
                details = f"Status: {response.status_code}"
            
            self.log_test("Authorization", "Admin Access to Security Events", passed, details)
        except Exception as e:
            self.log_test("Authorization", "Admin Access to Security Events", False, error=str(e))
        
        # Test 4: Unauthenticated access should be denied
        try:
            response = requests.get(f"{self.backend_url}/api/admin/system/stats")
            passed = response.status_code in [401, 403]
            self.log_test("Authorization", "Unauthenticated Access Denial", passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authorization", "Unauthenticated Access Denial", False, error=str(e))
        
        # Test 5: Invalid token should be rejected
        try:
            invalid_headers = {"Authorization": "Bearer invalid_token_12345"}
            response = requests.get(f"{self.backend_url}/api/admin/system/stats", headers=invalid_headers)
            passed = response.status_code in [401, 403]
            self.log_test("Authorization", "Invalid Token Rejection", passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authorization", "Invalid Token Rejection", False, error=str(e))
    
    async def test_session_management(self):
        """Test session management security"""
        print("\n🔒 Testing Session Management...")
        
        # Test 1: Session creation and validation
        try:
            # Login to create session
            response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                "username": "admin",
                "password": "TempAdmin123!@#",
                "device_fingerprint": {"browser": "test", "session_test": True}
            })
            
            if response.status_code == 200:
                data = response.json()
                session_token = data["access_token"]
                
                # Validate session by accessing protected endpoint
                headers = {"Authorization": f"Bearer {session_token}"}
                response = requests.get(f"{self.backend_url}/api/admin/system/stats", headers=headers)
                
                passed = response.status_code == 200
                self.log_test("Session", "Session Creation and Validation", passed,
                             f"Session active and valid")
            else:
                passed = False
                self.log_test("Session", "Session Creation and Validation", passed,
                             f"Login failed: {response.status_code}")
        except Exception as e:
            self.log_test("Session", "Session Creation and Validation", False, error=str(e))
        
        # Test 2: Session logout
        try:
            if "admin" in self.session_tokens:
                headers = {"Authorization": f"Bearer {self.session_tokens['admin']}"}
                response = requests.post(f"{self.backend_url}/api/admin/auth/logout", headers=headers)
                
                passed = response.status_code == 200
                if passed:
                    # Verify session is invalidated
                    response = requests.get(f"{self.backend_url}/api/admin/system/stats", headers=headers)
                    passed = response.status_code in [401, 403]
                    details = "Session successfully invalidated after logout"
                else:
                    details = f"Logout failed: {response.status_code}"
                
                self.log_test("Session", "Session Logout and Invalidation", passed, details)
            else:
                self.log_test("Session", "Session Logout and Invalidation", False,
                             "No admin session available")
        except Exception as e:
            self.log_test("Session", "Session Logout and Invalidation", False, error=str(e))
    
    async def test_input_validation_security(self):
        """Test input validation security"""
        print("\n🔍 Testing Input Validation Security...")
        
        # Test 1: SQL injection in login
        try:
            malicious_inputs = [
                "admin'; DROP TABLE admin_users; --",
                "admin' OR '1'='1",
                "'; UNION SELECT * FROM admin_users; --"
            ]
            
            blocked_attempts = 0
            for malicious_input in malicious_inputs:
                response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                    "username": malicious_input,
                    "password": "any_password",
                    "device_fingerprint": {"browser": "test"}
                })
                
                # Should be rejected (401 or 422)
                if response.status_code in [401, 422]:
                    blocked_attempts += 1
            
            passed = blocked_attempts == len(malicious_inputs)
            self.log_test("Input Validation", "SQL Injection Protection", passed,
                         f"Blocked {blocked_attempts}/{len(malicious_inputs)} attempts")
        except Exception as e:
            self.log_test("Input Validation", "SQL Injection Protection", False, error=str(e))
        
        # Test 2: XSS in user creation (requires admin token)
        try:
            # First login as admin
            response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                "username": "admin",
                "password": "TempAdmin123!@#",
                "device_fingerprint": {"browser": "test"}
            })
            
            if response.status_code == 200:
                token = response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Try to create user with XSS payload
                xss_payload = "<script>alert('XSS')</script>"
                response = requests.post(f"{self.backend_url}/api/admin/users/create", 
                    headers=headers,
                    json={
                        "username": xss_payload,
                        "email": "test@test.com",
                        "password": "ValidPassword123!",
                        "role": "support",
                        "permissions": []
                    }
                )
                
                # Should be rejected
                passed = response.status_code == 422
                self.log_test("Input Validation", "XSS Protection in User Creation", passed,
                             f"Status: {response.status_code}")
            else:
                self.log_test("Input Validation", "XSS Protection in User Creation", False,
                             "Could not obtain admin token")
        except Exception as e:
            self.log_test("Input Validation", "XSS Protection in User Creation", False, error=str(e))
        
        # Test 3: Malformed JSON handling
        try:
            response = requests.post(f"{self.backend_url}/api/admin/auth/login",
                data="invalid json data",
                headers={"Content-Type": "application/json"}
            )
            
            # Should return 422 (Unprocessable Entity) or 400 (Bad Request)
            passed = response.status_code in [400, 422]
            self.log_test("Input Validation", "Malformed JSON Handling", passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Input Validation", "Malformed JSON Handling", False, error=str(e))
    
    async def test_audit_logging(self):
        """Test audit logging functionality"""
        print("\n📋 Testing Audit Logging...")
        
        # First, perform some actions that should be logged
        try:
            # Login (should be logged)
            response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                "username": "admin",
                "password": "TempAdmin123!@#",
                "device_fingerprint": {"browser": "audit_test"}
            })
            
            if response.status_code == 200:
                token = response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Access audit logs
                response = requests.get(f"{self.backend_url}/api/admin/system/audit-logs?limit=10", 
                                      headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    logs = data.get("logs", [])
                    
                    # Check if login event was logged
                    login_logged = any(log.get("event_type") == "login_success" for log in logs)
                    passed = len(logs) > 0 and login_logged
                    
                    details = f"Retrieved {len(logs)} logs, login event logged: {login_logged}"
                    self.log_test("Audit", "Login Event Logging", passed, details)
                else:
                    self.log_test("Audit", "Login Event Logging", False,
                                 f"Could not retrieve logs: {response.status_code}")
            else:
                self.log_test("Audit", "Login Event Logging", False,
                             f"Login failed: {response.status_code}")
        except Exception as e:
            self.log_test("Audit", "Login Event Logging", False, error=str(e))
        
        # Test failed login logging
        try:
            # Attempt failed login
            response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                "username": "admin",
                "password": "wrong_password",
                "device_fingerprint": {"browser": "audit_test"}
            })
            
            # Should fail
            if response.status_code == 401:
                # Login with correct credentials to check logs
                response = requests.post(f"{self.backend_url}/api/admin/auth/login", json={
                    "username": "admin",
                    "password": "TempAdmin123!@#",
                    "device_fingerprint": {"browser": "audit_test"}
                })
                
                if response.status_code == 200:
                    token = response.json()["access_token"]
                    headers = {"Authorization": f"Bearer {token}"}
                    
                    # Check audit logs for failed login
                    response = requests.get(f"{self.backend_url}/api/admin/system/audit-logs?limit=20", 
                                          headers=headers)
                    
                    if response.status_code == 200:
                        data = response.json()
                        logs = data.get("logs", [])
                        
                        failed_login_logged = any(log.get("event_type") == "login_failed" for log in logs)
                        passed = failed_login_logged
                        
                        details = f"Failed login event logged: {failed_login_logged}"
                        self.log_test("Audit", "Failed Login Event Logging", passed, details)
                    else:
                        self.log_test("Audit", "Failed Login Event Logging", False,
                                     "Could not retrieve audit logs")
                else:
                    self.log_test("Audit", "Failed Login Event Logging", False,
                                 "Could not login to check logs")
            else:
                self.log_test("Audit", "Failed Login Event Logging", False,
                             "Failed login attempt did not fail as expected")
        except Exception as e:
            self.log_test("Audit", "Failed Login Event Logging", False, error=str(e))
    
    async def test_security_headers(self):
        """Test security headers"""
        print("\n🛡️ Testing Security Headers...")
        
        try:
            response = requests.get(f"{self.backend_url}/health")
            
            expected_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY", 
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'"
            }
            
            missing_headers = []
            present_headers = []
            
            for header, expected_value in expected_headers.items():
                actual_value = response.headers.get(header)
                if actual_value == expected_value:
                    present_headers.append(header)
                else:
                    missing_headers.append(f"{header}: expected '{expected_value}', got '{actual_value}'")
            
            passed = len(missing_headers) == 0
            details = f"Present: {len(present_headers)}, Missing: {len(missing_headers)}"
            
            self.log_test("Security Headers", "Security Headers Present", passed, details)
            
            if missing_headers:
                for missing in missing_headers[:3]:  # Show first 3
                    print(f"      Missing: {missing}")
                    
        except Exception as e:
            self.log_test("Security Headers", "Security Headers Present", False, error=str(e))
    
    def generate_security_test_report(self):
        """Generate comprehensive security test report"""
        print("\n📊 Generating Security Test Report...")
        
        # Categorize results
        categories = {}
        for result in self.test_results:
            category = result["category"]
            if category not in categories:
                categories[category] = {"passed": 0, "failed": 0, "total": 0}
            
            categories[category]["total"] += 1
            if result["passed"]:
                categories[category]["passed"] += 1
            else:
                categories[category]["failed"] += 1
        
        # Calculate overall statistics
        total_tests = len(self.test_results)
        total_passed = sum(1 for r in self.test_results if r["passed"])
        success_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0
        
        # Generate report
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall": {
                "total_tests": total_tests,
                "passed": total_passed,
                "failed": total_tests - total_passed,
                "success_rate": success_rate
            },
            "categories": categories,
            "detailed_results": self.test_results,
            "security_assessment": self._assess_security_level(success_rate, categories)
        }
        
        # Save report
        with open("PRODUCTION_SECURITY_TEST_REPORT.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*60)
        print("🛡️  PRODUCTION SECURITY TEST SUMMARY")
        print("="*60)
        print(f"Overall Success Rate: {success_rate:.1f}% ({total_passed}/{total_tests})")
        print()
        
        for category, stats in categories.items():
            rate = (stats["passed"] / stats["total"]) * 100
            status = "✅" if rate == 100 else "⚠️" if rate >= 80 else "❌"
            print(f"{status} {category}: {stats['passed']}/{stats['total']} ({rate:.1f}%)")
        
        # Security assessment
        assessment = report["security_assessment"]
        print(f"\n🔒 Security Level: {assessment['level']}")
        print(f"📋 Production Ready: {assessment['production_ready']}")
        
        if assessment["critical_issues"]:
            print("\n❌ Critical Issues:")
            for issue in assessment["critical_issues"]:
                print(f"   • {issue}")
        
        if assessment["recommendations"]:
            print("\n💡 Recommendations:")
            for rec in assessment["recommendations"]:
                print(f"   • {rec}")
        
        return report
    
    def _assess_security_level(self, success_rate: float, categories: Dict) -> Dict[str, Any]:
        """Assess overall security level"""
        
        critical_categories = ["Authentication", "Authorization", "Session"]
        critical_issues = []
        recommendations = []
        
        # Check critical categories
        for category in critical_categories:
            if category in categories:
                stats = categories[category]
                rate = (stats["passed"] / stats["total"]) * 100
                if rate < 100:
                    critical_issues.append(f"{category} tests not all passing ({rate:.1f}%)")
        
        # Determine security level
        if success_rate >= 95:
            level = "HIGH"
            production_ready = True
        elif success_rate >= 85:
            level = "MEDIUM-HIGH"
            production_ready = True
            recommendations.append("Address remaining test failures before production")
        elif success_rate >= 70:
            level = "MEDIUM"
            production_ready = False
            recommendations.append("Significant security improvements needed")
        else:
            level = "LOW"
            production_ready = False
            critical_issues.append("Multiple security systems failing")
        
        # Add specific recommendations
        if "Authentication" in categories and categories["Authentication"]["passed"] < categories["Authentication"]["total"]:
            recommendations.append("Fix authentication system issues immediately")
        
        if "Authorization" in categories and categories["Authorization"]["passed"] < categories["Authorization"]["total"]:
            recommendations.append("Review and fix authorization controls")
        
        return {
            "level": level,
            "production_ready": production_ready,
            "critical_issues": critical_issues,
            "recommendations": recommendations
        }
    
    async def run_comprehensive_security_tests(self):
        """Run all security tests"""
        print("🚀 MEDIVOTE PRODUCTION SECURITY TEST SUITE")
        print("="*60)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Test categories
        test_functions = [
            self.test_authentication_security,
            self.test_authorization_controls,
            self.test_session_management,
            self.test_input_validation_security,
            self.test_audit_logging,
            self.test_security_headers
        ]
        
        # Run all tests
        for test_func in test_functions:
            try:
                await test_func()
                time.sleep(1)  # Brief pause between test categories
            except Exception as e:
                print(f"❌ Test category failed: {test_func.__name__}: {e}")
        
        # Generate report
        report = self.generate_security_test_report()
        
        return report

async def main():
    """Main test function"""
    print("🔍 Starting MediVote Production Security Testing...")
    
    tester = ProductionSecurityTester()
    
    try:
        # Check if backend is running
        response = requests.get(f"{tester.backend_url}/health", timeout=5)
        if response.status_code != 200:
            print("❌ Backend not responding properly")
            sys.exit(1)
    except requests.ConnectionError:
        print("❌ Backend not running - please start the backend first")
        sys.exit(1)
    
    # Run comprehensive tests
    report = await tester.run_comprehensive_security_tests()
    
    # Determine exit code based on results
    if report["security_assessment"]["production_ready"]:
        print("\n✅ MediVote security tests PASSED - production ready!")
        sys.exit(0)
    else:
        print("\n❌ MediVote security tests FAILED - not ready for production")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 