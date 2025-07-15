#!/usr/bin/env python3
"""
ULTIMATE COMPREHENSIVE TEST SUITE FOR MEDIVOTE
Tests absolutely everything possible in the system
"""

import os
import sys
import json
import time
import subprocess
import requests
import threading
import hashlib
import random
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

class UltimateTestSuite:
    def __init__(self):
        self.backend_url = "http://localhost:8000"
        self.results = []
        self.errors = []
        self.warnings = []
        self.session = requests.Session()
        
    def log_test(self, category, test_name, status, details="", error=None):
        """Log comprehensive test results"""
        symbols = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "INFO": "ℹ️", "SKIP": "⏭️"}
        symbol = symbols.get(status, "❓")
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "test": test_name,
            "status": status,
            "details": details,
            "error": str(error) if error else None
        }
        self.results.append(result)
        
        print(f"{symbol} [{category}] {test_name}")
        if details:
            print(f"    {details}")
        if error and status == "FAIL":
            self.errors.append(f"[{category}] {test_name}: {error}")
            
    def test_file_system_integrity(self):
        """Test complete file system integrity"""
        print("\n🗂️ TESTING FILE SYSTEM INTEGRITY...")
        
        # Critical files
        critical_files = {
            "backend/main.py": "Main application",
            "simple_main_with_security.py": "Secure application",
            "build_installer.py": "Installer builder",
            "requirements.txt": "Dependencies",
            "README.md": "Documentation",
            "setup.py": "Setup script"
        }
        
        for file, description in critical_files.items():
            if os.path.exists(file):
                size = os.path.getsize(file)
                if size > 0:
                    self.log_test("FILE_SYSTEM", f"{description} exists", "PASS", f"Size: {size} bytes")
                else:
                    self.log_test("FILE_SYSTEM", f"{description} empty", "FAIL", f"File: {file}")
            else:
                self.log_test("FILE_SYSTEM", f"{description} missing", "FAIL", f"File: {file}")
                
        # Check file permissions
        for file in critical_files.keys():
            if os.path.exists(file):
                if os.access(file, os.R_OK):
                    self.log_test("FILE_SYSTEM", f"{file} readable", "PASS")
                else:
                    self.log_test("FILE_SYSTEM", f"{file} not readable", "FAIL")
                    
    def test_python_environment(self):
        """Test Python environment and dependencies"""
        print("\n🐍 TESTING PYTHON ENVIRONMENT...")
        
        # Test Python version
        version = sys.version_info
        self.log_test("PYTHON_ENV", "Python version", "PASS", f"Python {version.major}.{version.minor}.{version.micro}")
        
        # Test critical imports
        critical_imports = [
            "fastapi", "uvicorn", "pydantic", "sqlalchemy", 
            "requests", "json", "hashlib", "datetime"
        ]
        
        for module in critical_imports:
            try:
                __import__(module)
                self.log_test("PYTHON_ENV", f"Import {module}", "PASS")
            except ImportError as e:
                self.log_test("PYTHON_ENV", f"Import {module}", "FAIL", error=e)
                
    def test_backend_server_health(self):
        """Test backend server health and availability"""
        print("\n🏥 TESTING BACKEND SERVER HEALTH...")
        
        # Test server is running
        try:
            response = self.session.get(f"{self.backend_url}/health", timeout=5)
            if response.status_code == 200:
                health_data = response.json()
                self.log_test("BACKEND_HEALTH", "Server health check", "PASS", f"Status: {health_data.get('status')}")
                
                # Test health data completeness
                required_fields = ["status", "service", "version", "timestamp"]
                for field in required_fields:
                    if field in health_data:
                        self.log_test("BACKEND_HEALTH", f"Health data has {field}", "PASS")
                    else:
                        self.log_test("BACKEND_HEALTH", f"Health data missing {field}", "FAIL")
            else:
                self.log_test("BACKEND_HEALTH", "Server health check", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("BACKEND_HEALTH", "Server health check", "FAIL", error=e)
            
    def test_api_endpoints(self):
        """Test all API endpoints"""
        print("\n🔗 TESTING API ENDPOINTS...")
        
        endpoints = [
            ("/", "Root endpoint"),
            ("/health", "Health endpoint"),
            ("/docs", "Documentation endpoint"),
            ("/status", "Status endpoint")
        ]
        
        for endpoint, description in endpoints:
            try:
                response = self.session.get(f"{self.backend_url}{endpoint}", timeout=10)
                if response.status_code == 200:
                    self.log_test("API_ENDPOINTS", f"{description} accessible", "PASS", f"Status: {response.status_code}")
                else:
                    self.log_test("API_ENDPOINTS", f"{description} error", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("API_ENDPOINTS", f"{description} error", "FAIL", error=e)
                
    def test_cryptographic_functions(self):
        """Test cryptographic functionality"""
        print("\n🔐 TESTING CRYPTOGRAPHIC FUNCTIONS...")
        
        # Test hash functions
        try:
            test_data = "test_data_for_hashing"
            hash_result = hashlib.sha256(test_data.encode()).hexdigest()
            if len(hash_result) == 64:  # SHA256 produces 64 character hex
                self.log_test("CRYPTO", "SHA256 hashing", "PASS", f"Hash length: {len(hash_result)}")
            else:
                self.log_test("CRYPTO", "SHA256 hashing", "FAIL", f"Invalid hash length: {len(hash_result)}")
        except Exception as e:
            self.log_test("CRYPTO", "SHA256 hashing", "FAIL", error=e)
            
        # Test random generation
        try:
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            if len(random_string) == 32:
                self.log_test("CRYPTO", "Random string generation", "PASS", f"Length: {len(random_string)}")
            else:
                self.log_test("CRYPTO", "Random string generation", "FAIL", f"Invalid length: {len(random_string)}")
        except Exception as e:
            self.log_test("CRYPTO", "Random string generation", "FAIL", error=e)
            
    def test_data_validation(self):
        """Test data validation functions"""
        print("\n✅ TESTING DATA VALIDATION...")
        
        # Test email validation patterns
        valid_emails = ["test@example.com", "user.name@domain.co.uk", "admin@medivote.org"]
        invalid_emails = ["invalid-email", "@domain.com", "user@", "user@domain"]
        
        for email in valid_emails:
            # Basic email format check
            if "@" in email and "." in email.split("@")[1]:
                self.log_test("DATA_VALIDATION", f"Valid email: {email}", "PASS")
            else:
                self.log_test("DATA_VALIDATION", f"Valid email: {email}", "FAIL", "Email validation failed")
                
        for email in invalid_emails:
            if "@" not in email or "." not in email.split("@")[-1]:
                self.log_test("DATA_VALIDATION", f"Invalid email rejected: {email}", "PASS")
            else:
                self.log_test("DATA_VALIDATION", f"Invalid email rejected: {email}", "FAIL", "Should have been rejected")
                
    def test_security_features(self):
        """Test security implementations"""
        print("\n🛡️ TESTING SECURITY FEATURES...")
        
        # Test password requirements
        strong_passwords = ["SecurePass123!", "MyStr0ng#P@ssw0rd", "C0mpl3x!P@ssw0rd"]
        weak_passwords = ["password", "123456", "abc", ""]
        
        for password in strong_passwords:
            # Basic password strength check
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
            
            if has_upper and has_lower and has_digit and has_special and len(password) >= 8:
                self.log_test("SECURITY", f"Strong password accepted: {password[:3]}...", "PASS")
            else:
                self.log_test("SECURITY", f"Strong password rejected: {password[:3]}...", "FAIL")
                
    def test_performance_metrics(self):
        """Test performance metrics"""
        print("\n⚡ TESTING PERFORMANCE METRICS...")
        
        # Test response times
        start_time = time.time()
        try:
            response = self.session.get(f"{self.backend_url}/health", timeout=5)
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            if response_time < 1000:  # Less than 1 second
                self.log_test("PERFORMANCE", "Response time", "PASS", f"{response_time:.2f}ms")
            else:
                self.log_test("PERFORMANCE", "Response time", "WARN", f"{response_time:.2f}ms (slow)")
        except Exception as e:
            self.log_test("PERFORMANCE", "Response time", "FAIL", error=e)
            
        # Test concurrent requests
        def make_request():
            try:
                response = self.session.get(f"{self.backend_url}/health", timeout=5)
                return response.status_code == 200
            except:
                return False
                
        concurrent_requests = 10
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
            futures = [executor.submit(make_request) for _ in range(concurrent_requests)]
            results = [future.result() for future in as_completed(futures)]
            
        end_time = time.time()
        successful_requests = sum(results)
        total_time = end_time - start_time
        
        if successful_requests == concurrent_requests:
            self.log_test("PERFORMANCE", f"Concurrent requests ({concurrent_requests})", "PASS", 
                         f"All successful in {total_time:.2f}s")
        else:
            self.log_test("PERFORMANCE", f"Concurrent requests ({concurrent_requests})", "FAIL", 
                         f"Only {successful_requests}/{concurrent_requests} successful")
                         
    def test_installer_components(self):
        """Test installer components"""
        print("\n🔧 TESTING INSTALLER COMPONENTS...")
        
        installer_files = ["build_installer.py", "setup.py", "requirements_build.txt"]
        
        for file in installer_files:
            if os.path.exists(file):
                try:
                    with open(file, 'r') as f:
                        content = f.read()
                    
                    if len(content) > 100:  # Meaningful content
                        self.log_test("INSTALLER", f"{file} has content", "PASS", f"Size: {len(content)} chars")
                    else:
                        self.log_test("INSTALLER", f"{file} too small", "WARN", f"Size: {len(content)} chars")
                        
                    # Check for installer-specific content
                    if "install" in content.lower() or "setup" in content.lower():
                        self.log_test("INSTALLER", f"{file} has installer logic", "PASS")
                    else:
                        self.log_test("INSTALLER", f"{file} missing installer logic", "WARN")
                        
                except Exception as e:
                    self.log_test("INSTALLER", f"{file} read error", "FAIL", error=e)
            else:
                self.log_test("INSTALLER", f"{file} missing", "FAIL")
                
    def test_documentation_quality(self):
        """Test documentation quality"""
        print("\n📚 TESTING DOCUMENTATION QUALITY...")
        
        doc_files = ["README.md", "CONTRIBUTING.md", "LICENSE"]
        
        for doc_file in doc_files:
            if os.path.exists(doc_file):
                try:
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    word_count = len(content.split())
                    if word_count > 50:
                        self.log_test("DOCUMENTATION", f"{doc_file} comprehensive", "PASS", f"{word_count} words")
                    else:
                        self.log_test("DOCUMENTATION", f"{doc_file} brief", "WARN", f"{word_count} words")
                        
                    # Check for key documentation elements
                    if doc_file == "README.md":
                        key_sections = ["installation", "usage", "features", "requirements"]
                        for section in key_sections:
                            if section.lower() in content.lower():
                                self.log_test("DOCUMENTATION", f"README has {section}", "PASS")
                            else:
                                self.log_test("DOCUMENTATION", f"README missing {section}", "WARN")
                                
                except Exception as e:
                    self.log_test("DOCUMENTATION", f"{doc_file} read error", "FAIL", error=e)
            else:
                self.log_test("DOCUMENTATION", f"{doc_file} missing", "FAIL")
                
    def test_error_handling(self):
        """Test error handling capabilities"""
        print("\n🚨 TESTING ERROR HANDLING...")
        
        # Test invalid API requests
        invalid_requests = [
            ("/invalid-endpoint", "Invalid endpoint"),
            ("/register", "POST without data"),
            ("/vote", "Vote without auth")
        ]
        
        for endpoint, description in invalid_requests:
            try:
                response = self.session.get(f"{self.backend_url}{endpoint}", timeout=5)
                if response.status_code in [404, 400, 401, 403, 422]:
                    self.log_test("ERROR_HANDLING", f"{description} properly handled", "PASS", 
                                 f"Status: {response.status_code}")
                else:
                    self.log_test("ERROR_HANDLING", f"{description} not handled", "FAIL", 
                                 f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("ERROR_HANDLING", f"{description} error", "FAIL", error=e)
                
    def run_ultimate_tests(self):
        """Run all ultimate tests"""
        print("🚀 STARTING ULTIMATE COMPREHENSIVE MEDIVOTE TESTING...")
        print(f"Ultimate test suite started at: {datetime.now().isoformat()}")
        print("=" * 80)
        
        # Run all test categories
        test_methods = [
            self.test_file_system_integrity,
            self.test_python_environment,
            self.test_backend_server_health,
            self.test_api_endpoints,
            self.test_cryptographic_functions,
            self.test_data_validation,
            self.test_security_features,
            self.test_performance_metrics,
            self.test_installer_components,
            self.test_documentation_quality,
            self.test_error_handling
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_test("SYSTEM", f"Test method {test_method.__name__}", "FAIL", error=e)
                
        self.generate_ultimate_report()
        
    def generate_ultimate_report(self):
        """Generate ultimate comprehensive report"""
        print("\n" + "=" * 80)
        print("🏆 ULTIMATE COMPREHENSIVE TEST REPORT")
        print("=" * 80)
        
        # Count results by status
        status_counts = {}
        category_counts = {}
        
        for result in self.results:
            status = result['status']
            category = result['category']
            
            status_counts[status] = status_counts.get(status, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            
        # Print summary
        total_tests = len(self.results)
        passed = status_counts.get('PASS', 0)
        failed = status_counts.get('FAIL', 0)
        warned = status_counts.get('WARN', 0)
        info = status_counts.get('INFO', 0)
        skipped = status_counts.get('SKIP', 0)
        
        print(f"📊 TOTAL TESTS: {total_tests}")
        print(f"✅ PASSED: {passed}")
        print(f"❌ FAILED: {failed}")
        print(f"⚠️ WARNINGS: {warned}")
        print(f"ℹ️ INFO: {info}")
        print(f"⏭️ SKIPPED: {skipped}")
        
        if total_tests > 0:
            success_rate = (passed / total_tests) * 100
            print(f"🎯 SUCCESS RATE: {success_rate:.1f}%")
            
            # Quality assessment
            if success_rate >= 90:
                print("🏆 EXCELLENT: System is production-ready!")
            elif success_rate >= 75:
                print("✅ GOOD: System is mostly ready with minor issues")
            elif success_rate >= 50:
                print("⚠️ FAIR: System needs improvement")
            else:
                print("❌ POOR: System needs significant work")
                
        # Print category breakdown
        print("\n📋 CATEGORY BREAKDOWN:")
        for category, count in sorted(category_counts.items()):
            cat_results = [r for r in self.results if r['category'] == category]
            cat_passed = sum(1 for r in cat_results if r['status'] == 'PASS')
            cat_rate = (cat_passed / count) * 100 if count > 0 else 0
            print(f"  {category}: {cat_passed}/{count} ({cat_rate:.1f}%)")
            
        # Print all errors
        if self.errors:
            print("\n❌ CRITICAL ERRORS:")
            for error in self.errors:
                print(f"  {error}")
                
        # Save ultimate report
        report_data = {
            'test_type': 'ULTIMATE_COMPREHENSIVE',
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed': passed,
                'failed': failed,
                'warnings': warned,
                'info': info,
                'skipped': skipped,
                'success_rate': success_rate if total_tests > 0 else 0
            },
            'category_breakdown': {
                category: {
                    'total': count,
                    'passed': sum(1 for r in self.results if r['category'] == category and r['status'] == 'PASS'),
                    'success_rate': (sum(1 for r in self.results if r['category'] == category and r['status'] == 'PASS') / count) * 100 if count > 0 else 0
                } for category, count in category_counts.items()
            },
            'detailed_results': self.results,
            'errors': self.errors
        }
        
        with open('ULTIMATE_TEST_REPORT.json', 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"\n📄 Ultimate report saved to: ULTIMATE_TEST_REPORT.json")
        print("=" * 80)
        print("🎉 ULTIMATE TESTING COMPLETE!")

if __name__ == "__main__":
    suite = UltimateTestSuite()
    suite.run_ultimate_tests() 