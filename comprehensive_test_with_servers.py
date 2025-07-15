#!/usr/bin/env python3
"""
Comprehensive test suite that ensures both backend and frontend servers are running
"""

import subprocess
import time
import requests
import sys
import os
from pathlib import Path

class ComprehensiveTestWithServers:
    def __init__(self):
        self.backend_url = "http://localhost:8000"
        self.frontend_url = "http://localhost:3000"
        self.backend_process = None
        self.frontend_process = None
        self.results = []
        
    def log_test(self, category, test_name, passed, details=""):
        """Log test results"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.results.append({
            "category": category,
            "test": test_name,
            "passed": passed,
            "details": details
        })
        print(f"{status} [{category}] {test_name}")
        if details:
            print(f"    {details}")
            
    def start_servers(self):
        """Start both backend and frontend servers"""
        print("🚀 Starting MediVote servers...")
        
        # Start backend
        try:
            backend_dir = Path(__file__).parent / "backend"
            self.backend_process = subprocess.Popen(
                [sys.executable, "main.py"],
                cwd=backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print("✅ Backend server started")
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return False
            
        # Start frontend
        try:
            frontend_dir = Path(__file__).parent / "frontend"
            self.frontend_process = subprocess.Popen(
                [sys.executable, "serve.py"],
                cwd=frontend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print("✅ Frontend server started")
        except Exception as e:
            print(f"❌ Failed to start frontend: {e}")
            return False
            
        # Wait for servers to be ready
        print("⏳ Waiting for servers to be ready...")
        time.sleep(8)
        
        return True
        
    def stop_servers(self):
        """Stop both servers"""
        print("🛑 Stopping servers...")
        
        if self.backend_process:
            self.backend_process.terminate()
            self.backend_process.wait()
            
        if self.frontend_process:
            self.frontend_process.terminate()
            self.frontend_process.wait()
            
    def test_backend_health(self):
        """Test backend server health"""
        print("\n🏥 Testing Backend Health...")
        
        try:
            response = requests.get(f"{self.backend_url}/health", timeout=10)
            passed = response.status_code == 200
            details = f"Status: {response.status_code}"
            if passed:
                health_data = response.json()
                details += f", Service: {health_data.get('service', 'unknown')}"
            self.log_test("Backend", "Health Check", passed, details)
        except Exception as e:
            self.log_test("Backend", "Health Check", False, f"Error: {e}")
            
    def test_backend_endpoints(self):
        """Test backend API endpoints"""
        print("\n🔗 Testing Backend Endpoints...")
        
        endpoints = [
            ("/", "Root endpoint"),
            ("/api/status", "Status endpoint"),
            ("/api/voting/ballots", "Ballots endpoint")
        ]
        
        for endpoint, name in endpoints:
            try:
                response = requests.get(f"{self.backend_url}{endpoint}", timeout=10)
                passed = response.status_code == 200
                self.log_test("Backend", name, passed, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Backend", name, False, f"Error: {e}")
                
    def test_frontend_pages(self):
        """Test frontend page accessibility"""
        print("\n🌐 Testing Frontend Pages...")
        
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
                response = requests.get(url, timeout=10)
                has_medivote = "MediVote" in response.text
                passed = response.status_code == 200 and has_medivote
                details = f"Status: {response.status_code}, Has MediVote: {has_medivote}"
                self.log_test("Frontend", f"{name} Accessibility", passed, details)
            except Exception as e:
                self.log_test("Frontend", f"{name} Accessibility", False, f"Error: {e}")
                
    def test_api_integration(self):
        """Test API integration"""
        print("\n🔄 Testing API Integration...")
        
        # Test voter registration
        try:
            registration_data = {
                "full_name": "Test User",
                "email": "test@example.com", 
                "password": "SecurePass123!"
            }
            response = requests.post(
                f"{self.backend_url}/api/auth/register",
                json=registration_data,
                timeout=10
            )
            passed = response.status_code in [200, 201]
            self.log_test("Integration", "Voter Registration", passed, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Integration", "Voter Registration", False, f"Error: {e}")
            
    def run_all_tests(self):
        """Run all comprehensive tests"""
        print("🧪 COMPREHENSIVE TEST SUITE WITH SERVERS")
        print("=" * 60)
        
        # Start servers
        if not self.start_servers():
            print("❌ Failed to start servers - aborting tests")
            return False
            
        try:
            # Run tests
            self.test_backend_health()
            self.test_backend_endpoints()
            self.test_frontend_pages()
            self.test_api_integration()
            
            # Generate report
            self.generate_report()
            
        finally:
            # Always stop servers
            self.stop_servers()
            
        return True
        
    def generate_report(self):
        """Generate test report"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("=" * 60)
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        failed = total - passed
        
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        
        if total > 0:
            success_rate = (passed / total) * 100
            print(f"🎯 Success Rate: {success_rate:.1f}%")
            
            if success_rate >= 90:
                print("🏆 EXCELLENT: System is production-ready!")
            elif success_rate >= 75:
                print("✅ GOOD: System is mostly ready")
            elif success_rate >= 50:
                print("⚠️ FAIR: System needs improvement")
            else:
                print("❌ POOR: System needs significant work")
                
        # Category breakdown
        categories = {}
        for result in self.results:
            cat = result['category']
            if cat not in categories:
                categories[cat] = {'total': 0, 'passed': 0}
            categories[cat]['total'] += 1
            if result['passed']:
                categories[cat]['passed'] += 1
                
        print("\n📋 Category Breakdown:")
        for cat, stats in categories.items():
            rate = (stats['passed'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  {cat}: {stats['passed']}/{stats['total']} ({rate:.1f}%)")

if __name__ == "__main__":
    tester = ComprehensiveTestWithServers()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1) 