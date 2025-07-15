#!/usr/bin/env python3
"""
Comprehensive Test Suite for MediVote (After Critical Fixes)
Tests all major functionality with special focus on the validation fixes
"""

import requests
import json
import time
import sys
import os
import threading
import hashlib
import random
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

class MediVoteFixedTests:
    def __init__(self):
        self.backend_url = "http://localhost:8000"
        self.frontend_url = "http://localhost:3000"
        self.session = requests.Session()
        self.test_results = []
        self.errors = []
        
    def log_test(self, category, test_name, passed, details="", error=None):
        """Log test results with categorization"""
        status = "✅ PASSED" if passed else "❌ FAILED"
        self.test_results.append({
            "category": category,
            "test": test_name,
            "passed": passed,
            "details": details,
            "error": str(error) if error else None
        })
        print(f"{status}: [{category}] {test_name}")
        if details and not passed:
            print(f"   Details: {details}")
        if error:
            self.errors.append(f"[{category}] {test_name}: {error}")

    def test_input_validation_fixes(self):
        """Test the specific input validation fixes that were implemented"""
        print("\n🔧 Testing Input Validation Fixes...")
        
        # Test 1: Invalid email format (should now be REJECTED)
        try:
            invalid_email_data = {
                "full_name": "Test User",
                "email": "invalid-email",  # Invalid format
                "password": "StrongPass123!",
                "phone": "555-0123",
                "address": "123 Test Street",
                "date_of_birth": "1990-01-01",
                "identity_document": "ID123456",
                "id_number": "123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=invalid_email_data
            )
            passed = response.status_code == 422  # Should now reject invalid email
            self.log_test("Validation", "Invalid Email Rejection", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Invalid Email Rejection", False, error=e)
        
        # Test 2: Weak password (should now be REJECTED)
        try:
            weak_password_data = {
                "full_name": "Test User",
                "email": "test@valid.com",
                "password": "123",  # Weak password
                "phone": "555-0123",
                "address": "123 Test Street",
                "date_of_birth": "1990-01-01",
                "identity_document": "ID123456",
                "id_number": "123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=weak_password_data
            )
            passed = response.status_code == 422  # Should now reject weak password
            self.log_test("Validation", "Weak Password Rejection", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Weak Password Rejection", False, error=e)
        
        # Test 3: Empty required fields (should now be REJECTED)
        try:
            empty_fields_data = {
                "full_name": "",  # Empty required field
                "email": "test@valid.com",
                "password": "StrongPass123!",
                "phone": "555-0123",
                "address": "123 Test Street",
                "date_of_birth": "1990-01-01",
                "identity_document": "ID123456",
                "id_number": "123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=empty_fields_data
            )
            passed = response.status_code == 422  # Should now reject empty fields
            self.log_test("Validation", "Empty Fields Rejection", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Empty Fields Rejection", False, error=e)
        
        # Test 4: Invalid date format (should now be REJECTED)
        try:
            invalid_date_data = {
                "full_name": "Test User",
                "email": "test@valid.com",
                "password": "StrongPass123!",
                "phone": "555-0123",
                "address": "123 Test Street",
                "date_of_birth": "invalid-date",  # Invalid date format
                "identity_document": "ID123456",
                "id_number": "123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=invalid_date_data
            )
            passed = response.status_code == 422  # Should now reject invalid date
            self.log_test("Validation", "Invalid Date Rejection", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Invalid Date Rejection", False, error=e)
        
        # Test 5: Valid registration (should now PASS)
        try:
            valid_data = {
                "full_name": "Valid Test User",
                "email": "valid@test.com",
                "password": "StrongPass123!",
                "phone": "555-0123-456",
                "address": "123 Valid Test Street",
                "date_of_birth": "1990-01-01",
                "identity_document": "VALID_ID123456",
                "id_number": "VALID123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=valid_data
            )
            passed = response.status_code == 200  # Should accept valid data
            self.log_test("Validation", "Valid Registration Acceptance", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Valid Registration Acceptance", False, error=e)
    
    def test_additional_validation_edge_cases(self):
        """Test additional validation edge cases"""
        print("\n🔍 Testing Additional Validation Edge Cases...")
        
        # Test age validation (under 18)
        try:
            underage_data = {
                "full_name": "Young User",
                "email": "young@test.com",
                "password": "StrongPass123!",
                "phone": "555-0123",
                "address": "123 Test Street",
                "date_of_birth": "2010-01-01",  # Under 18
                "identity_document": "ID123456",
                "id_number": "123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=underage_data
            )
            passed = response.status_code == 422  # Should reject underage
            self.log_test("Validation", "Underage Rejection", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Underage Rejection", False, error=e)
        
        # Test future date rejection
        try:
            future_date_data = {
                "full_name": "Future User",
                "email": "future@test.com",
                "password": "StrongPass123!",
                "phone": "555-0123",
                "address": "123 Test Street",
                "date_of_birth": "2030-01-01",  # Future date
                "identity_document": "ID123456",
                "id_number": "123456789"
            }
            response = self.session.post(
                f"{self.backend_url}/api/auth/register",
                json=future_date_data
            )
            passed = response.status_code == 422  # Should reject future date
            self.log_test("Validation", "Future Date Rejection", passed, 
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Validation", "Future Date Rejection", False, error=e)
        
        # Test password complexity requirements
        try:
            weak_complexity_passwords = [
                "password",      # No uppercase, no digits, no special chars
                "PASSWORD",      # No lowercase, no digits, no special chars  
                "Password",      # No digits, no special chars
                "Password1",     # No special chars
            ]
            
            passed_tests = 0
            for i, weak_pass in enumerate(weak_complexity_passwords):
                test_data = {
                    "full_name": f"Test User {i}",
                    "email": f"test{i}@complexity.com",
                    "password": weak_pass,
                    "phone": "555-0123",
                    "address": "123 Test Street",
                    "date_of_birth": "1990-01-01",
                    "identity_document": "ID123456",
                    "id_number": "123456789"
                }
                response = self.session.post(
                    f"{self.backend_url}/api/auth/register",
                    json=test_data
                )
                if response.status_code == 422:  # Should reject weak passwords
                    passed_tests += 1
            
            passed = passed_tests == len(weak_complexity_passwords)
            self.log_test("Validation", "Password Complexity Requirements", passed, 
                         f"Rejected {passed_tests}/{len(weak_complexity_passwords)} weak passwords")
        except Exception as e:
            self.log_test("Validation", "Password Complexity Requirements", False, error=e)
    
    def test_system_functionality(self):
        """Test that the system still works correctly after validation fixes"""
        print("\n⚙️ Testing System Functionality...")
        
        # Test system health
        try:
            response = self.session.get(f"{self.backend_url}/health")
            passed = response.status_code == 200
            self.log_test("System", "Health Check", passed, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("System", "Health Check", False, error=e)
        
        # Test system status
        try:
            response = self.session.get(f"{self.backend_url}/api/status")
            passed = response.status_code == 200
            if passed:
                data = response.json()
                status = data.get("status", "unknown")
                self.log_test("System", "Status Endpoint", True, f"Status: {status}")
            else:
                self.log_test("System", "Status Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("System", "Status Endpoint", False, error=e)
        
        # Test ballots endpoint
        try:
            response = self.session.get(f"{self.backend_url}/api/voting/ballots")
            passed = response.status_code == 200
            if passed:
                data = response.json()
                ballots = data.get("ballots", [])
                self.log_test("System", "Ballots Endpoint", True, f"Found {len(ballots)} ballots")
            else:
                self.log_test("System", "Ballots Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("System", "Ballots Endpoint", False, error=e)
    
    def test_frontend_functionality(self):
        """Test frontend functionality after fixes"""
        print("\n🌐 Testing Frontend Functionality...")
        
        # Test main pages
        pages = [
            ("", "Main Page"),
            ("register.html", "Registration Page"),
            ("vote.html", "Voting Page"),
            ("verify.html", "Verification Page"),
            ("results.html", "Results Page"),
            ("admin.html", "Admin Page")
        ]
        
        for page, name in pages:
            try:
                url = f"{self.frontend_url}/{page}" if page else self.frontend_url
                response = self.session.get(url)
                passed = response.status_code == 200 and "MediVote" in response.text
                self.log_test("Frontend", f"{name} Accessibility", passed, 
                             f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Frontend", f"{name} Accessibility", False, error=e)
    
    def test_security_features(self):
        """Test security features are still active"""
        print("\n🛡️ Testing Security Features...")
        
        try:
            response = self.session.get(f"{self.backend_url}/api/status")
            if response.status_code == 200:
                data = response.json()
                security_features = data.get("security_features", {})
                
                expected_features = [
                    "ssi_verification",
                    "zero_knowledge_proofs", 
                    "homomorphic_encryption",
                    "blind_signatures",
                    "blockchain_storage",
                    "end_to_end_verification"
                ]
                
                active_features = 0
                for feature in expected_features:
                    if security_features.get(feature) == "active":
                        active_features += 1
                
                passed = active_features == len(expected_features)
                self.log_test("Security", "All Security Features Active", passed, 
                             f"Active: {active_features}/{len(expected_features)}")
            else:
                self.log_test("Security", "Security Features Check", False, 
                             f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Security", "Security Features Check", False, error=e)
    
    def run_comprehensive_tests(self):
        """Run all comprehensive tests after fixes"""
        print("🎯 MediVote Comprehensive Test Suite (After Critical Fixes)")
        print("=" * 80)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Run all test categories
        test_categories = [
            ("Input Validation Fixes", self.test_input_validation_fixes),
            ("Additional Validation Edge Cases", self.test_additional_validation_edge_cases),
            ("System Functionality", self.test_system_functionality),
            ("Frontend Functionality", self.test_frontend_functionality),
            ("Security Features", self.test_security_features)
        ]
        
        for category_name, test_func in test_categories:
            print(f"\n{'='*20} {category_name} {'='*20}")
            try:
                test_func()
            except Exception as e:
                print(f"❌ Category {category_name} failed with error: {e}")
                traceback.print_exc()
            time.sleep(1)
        
        # Summary
        self.print_test_summary()
        
        return self.calculate_success_rate()
    
    def print_test_summary(self):
        """Print detailed test summary"""
        print("\n" + "=" * 80)
        print("🎯 COMPREHENSIVE TEST SUMMARY (AFTER FIXES)")
        print("=" * 80)
        
        # Group results by category
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
        
        # Print category summaries
        total_passed = 0
        total_tests = 0
        
        for category, stats in categories.items():
            passed = stats["passed"]
            total = stats["total"]
            rate = (passed / total) * 100 if total > 0 else 0
            status = "✅" if rate == 100 else "⚠️" if rate >= 80 else "❌"
            
            print(f"{status} {category}: {passed}/{total} ({rate:.1f}%)")
            total_passed += passed
            total_tests += total
        
        overall_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0
        print(f"\n🎯 OVERALL: {total_passed}/{total_tests} ({overall_rate:.1f}%)")
        
        # Print improvement analysis
        print(f"\n📈 IMPROVEMENT ANALYSIS:")
        validation_results = [r for r in self.test_results if r["category"] == "Validation"]
        if validation_results:
            validation_passed = sum(1 for r in validation_results if r["passed"])
            validation_total = len(validation_results)
            validation_rate = (validation_passed / validation_total) * 100
            
            print(f"   Input Validation: {validation_passed}/{validation_total} ({validation_rate:.1f}%)")
            if validation_rate >= 80:
                print("   ✅ SIGNIFICANT IMPROVEMENT in input validation!")
            else:
                print("   ⚠️ Input validation still needs work")
        
        # Final assessment
        if overall_rate >= 95:
            print("\n🎉 OUTSTANDING: All critical issues have been resolved!")
        elif overall_rate >= 90:
            print("\n🎉 EXCELLENT: System is now production ready!")
        elif overall_rate >= 85:
            print("\n✅ VERY GOOD: Major improvements achieved!")
        elif overall_rate >= 80:
            print("\n✅ GOOD: Significant progress made!")
        else:
            print("\n⚠️ More work needed to reach production readiness")
    
    def calculate_success_rate(self):
        """Calculate overall success rate"""
        if not self.test_results:
            return 0
        passed = sum(1 for result in self.test_results if result["passed"])
        return (passed / len(self.test_results)) * 100

if __name__ == "__main__":
    print("🚀 Starting MediVote Comprehensive Testing (After Critical Fixes)...")
    
    tester = MediVoteFixedTests()
    success_rate = tester.run_comprehensive_tests()
    
    print(f"\n🏁 Testing completed with {success_rate:.1f}% success rate")
    
    if success_rate >= 95:
        print("🎉 OUTSTANDING performance - all critical issues resolved!")
        sys.exit(0)
    elif success_rate >= 90:
        print("🎉 EXCELLENT performance - system ready for production!")
        sys.exit(0)
    elif success_rate >= 85:
        print("✅ VERY GOOD performance - major improvements achieved!")
        sys.exit(0)
    else:
        print("⚠️ Additional work needed")
        sys.exit(1) 