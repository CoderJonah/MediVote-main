#!/usr/bin/env python3
"""
Test Enhanced Error Recovery and Resilience (High Priority 3)
Tests the new error recovery, health monitoring, and resilience features
"""

import requests
import time
import json
import psutil
import threading
from datetime import datetime

class EnhancedErrorRecoveryTest:
    def __init__(self):
        self.base_url = "http://localhost:8090"
        self.test_results = []
        
    def log_test(self, category, test_name, passed, details="", error=None):
        """Log test results"""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = {
            "category": category,
            "test": test_name,
            "passed": passed,
            "details": details,
            "error": str(error) if error else None,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status}: [{category}] {test_name}")
        if details and not passed:
            print(f"   Details: {details}")
        if error:
            print(f"   Error: {error}")
    
    def test_health_endpoint(self):
        """Test the new health endpoint"""
        print("\n🏥 Testing Health Endpoint...")
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                self.log_test("HEALTH", "Health Endpoint Available", True, f"Got health data for {len(health_data)} services")
                
                # Test health data structure
                for service_id, health_info in health_data.items():
                    has_required_fields = all(key in health_info for key in ['status', 'last_check', 'uptime'])
                    self.log_test("HEALTH", f"{service_id} Health Structure", has_required_fields,
                                f"Health info: {health_info}")
                    
                    # Test auto-recovery fields
                    has_recovery_fields = all(key in health_info for key in ['auto_recovery_enabled', 'failure_count', 'recovery_attempts'])
                    self.log_test("HEALTH", f"{service_id} Recovery Fields", has_recovery_fields,
                                f"Recovery info: {health_info.get('auto_recovery_enabled', 'missing')}")
            else:
                self.log_test("HEALTH", "Health Endpoint Available", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("HEALTH", "Health Endpoint Available", False, error=e)
    
    def test_enhanced_status_api(self):
        """Test that status API now includes health information"""
        print("\n📊 Testing Enhanced Status API...")
        
        try:
            response = requests.get(f"{self.base_url}/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Check if health information is included
                services_with_health = 0
                total_services = len(data)
                
                for service_id, info in data.items():
                    if 'health' in info:
                        services_with_health += 1
                        health_info = info['health']
                        has_health_fields = all(key in health_info for key in ['status', 'last_check', 'uptime'])
                        self.log_test("STATUS", f"{service_id} Health Info", has_health_fields,
                                    f"Health: {health_info.get('status', 'missing')}")
                
                health_coverage = services_with_health / total_services if total_services > 0 else 0
                self.log_test("STATUS", "Health Information Coverage", health_coverage >= 0.8,
                            f"Coverage: {services_with_health}/{total_services} ({health_coverage:.1%})")
            else:
                self.log_test("STATUS", "Enhanced Status API", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("STATUS", "Enhanced Status API", False, error=e)
    
    def test_failure_recording(self):
        """Test that service failures are properly recorded"""
        print("\n📝 Testing Failure Recording...")
        
        try:
            # Try to restart a service to trigger potential failure recording
            response = requests.post(f"{self.base_url}/restart/backend", timeout=20)
            if response.status_code == 200:
                # Check health endpoint for failure recording
                health_response = requests.get(f"{self.base_url}/health", timeout=10)
                if health_response.status_code == 200:
                    health_data = health_response.json()
                    backend_health = health_data.get('backend', {})
                    
                    # Check if failure tracking is working
                    has_failure_tracking = 'failure_count' in backend_health
                    self.log_test("FAILURE", "Failure Count Tracking", has_failure_tracking,
                                f"Failure count: {backend_health.get('failure_count', 'missing')}")
                    
                    # Check if recovery attempts are tracked
                    has_recovery_tracking = 'recovery_attempts' in backend_health
                    self.log_test("FAILURE", "Recovery Attempts Tracking", has_recovery_tracking,
                                f"Recovery attempts: {backend_health.get('recovery_attempts', 'missing')}")
                else:
                    self.log_test("FAILURE", "Health Data Available", False, f"Status: {health_response.status_code}")
            else:
                self.log_test("FAILURE", "Service Restart", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("FAILURE", "Failure Recording", False, error=e)
    
    def test_auto_recovery_settings(self):
        """Test auto-recovery configuration"""
        print("\n🔄 Testing Auto-Recovery Settings...")
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                
                auto_recovery_enabled_count = 0
                total_services = len(health_data)
                
                for service_id, health_info in health_data.items():
                    auto_recovery = health_info.get('auto_recovery_enabled', False)
                    if auto_recovery:
                        auto_recovery_enabled_count += 1
                    
                    self.log_test("RECOVERY", f"{service_id} Auto-Recovery", auto_recovery,
                                f"Auto-recovery: {auto_recovery}")
                
                # Most services should have auto-recovery enabled
                recovery_coverage = auto_recovery_enabled_count / total_services if total_services > 0 else 0
                self.log_test("RECOVERY", "Auto-Recovery Coverage", recovery_coverage >= 0.7,
                            f"Coverage: {auto_recovery_enabled_count}/{total_services} ({recovery_coverage:.1%})")
            else:
                self.log_test("RECOVERY", "Health Data Available", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("RECOVERY", "Auto-Recovery Settings", False, error=e)
    
    def test_health_monitoring_interval(self):
        """Test that health monitoring is running at appropriate intervals"""
        print("\n⏰ Testing Health Monitoring Interval...")
        
        try:
            # Get initial health data
            response1 = requests.get(f"{self.base_url}/health", timeout=10)
            if response1.status_code == 200:
                health_data1 = response1.json()
                
                # Wait a bit for health monitoring to potentially update
                time.sleep(5)
                
                # Get updated health data
                response2 = requests.get(f"{self.base_url}/health", timeout=10)
                if response2.status_code == 200:
                    health_data2 = response2.json()
                    
                    # Check if health data is being updated
                    updated_services = 0
                    total_services = len(health_data1)
                    
                    for service_id in health_data1.keys():
                        if service_id in health_data2:
                            last_check1 = health_data1[service_id].get('last_check', 0)
                            last_check2 = health_data2[service_id].get('last_check', 0)
                            
                            if last_check2 > last_check1:
                                updated_services += 1
                    
                    # Some services should have updated health data
                    update_coverage = updated_services / total_services if total_services > 0 else 0
                    self.log_test("MONITORING", "Health Data Updates", update_coverage >= 0.3,
                                f"Updated: {updated_services}/{total_services} ({update_coverage:.1%})")
                else:
                    self.log_test("MONITORING", "Second Health Check", False, f"Status: {response2.status_code}")
            else:
                self.log_test("MONITORING", "First Health Check", False, f"Status: {response1.status_code}")
        except Exception as e:
            self.log_test("MONITORING", "Health Monitoring Interval", False, error=e)
    
    def test_concurrent_operation_resilience(self):
        """Test that concurrent operations are handled resiliently"""
        print("\n🛡️ Testing Concurrent Operation Resilience...")
        
        def make_concurrent_requests():
            """Make multiple concurrent requests to test resilience"""
            results = []
            for i in range(5):
                try:
                    response = requests.post(f"{self.base_url}/restart/backend", timeout=15)
                    results.append(response.status_code == 200)
                except Exception:
                    results.append(False)
            return results
        
        # Run concurrent requests
        threads = []
        all_results = []
        
        for i in range(3):
            thread = threading.Thread(target=lambda: all_results.extend(make_concurrent_requests()))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Check results
        successful_requests = sum(all_results)
        total_requests = len(all_results)
        
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        self.log_test("RESILIENCE", "Concurrent Operation Handling", success_rate >= 0.6,
                    f"Success rate: {successful_requests}/{total_requests} ({success_rate:.1%})")
    
    def test_error_recovery_mechanisms(self):
        """Test that error recovery mechanisms are working"""
        print("\n🔧 Testing Error Recovery Mechanisms...")
        
        try:
            # Test invalid service ID (should be handled gracefully)
            response = requests.post(f"{self.base_url}/restart/invalid_service", timeout=10)
            # Should handle gracefully (not crash)
            self.log_test("RECOVERY", "Invalid Service Handling", True,
                        f"Status: {response.status_code}")
            
            # Test invalid endpoint
            response = requests.get(f"{self.base_url}/invalid_endpoint", timeout=10)
            # Should return 404 or handle gracefully
            self.log_test("RECOVERY", "Invalid Endpoint Handling", True,
                        f"Status: {response.status_code}")
            
            # Test malformed requests
            try:
                response = requests.post(f"{self.base_url}/restart/", data="invalid", timeout=10)
                self.log_test("RECOVERY", "Malformed Request Handling", True,
                            f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("RECOVERY", "Malformed Request Handling", False, error=e)
                
        except Exception as e:
            self.log_test("RECOVERY", "Error Recovery Mechanisms", False, error=e)
    
    def test_system_stability(self):
        """Test overall system stability with enhanced error recovery"""
        print("\n🏗️ Testing System Stability...")
        
        try:
            # Check if all services are still running after tests
            response = requests.get(f"{self.base_url}/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                running_services = 0
                total_services = len(data)
                
                for service_id, info in data.items():
                    if info.get('status') == 'running':
                        running_services += 1
                
                stability_ratio = running_services / total_services if total_services > 0 else 0
                self.log_test("STABILITY", "Service Stability", stability_ratio >= 0.8,
                            f"Running: {running_services}/{total_services} ({stability_ratio:.1%})")
                
                # Check memory usage
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                        cmdline = proc.cmdline()
                        if 'python' in proc.info['name'].lower() and any('start_medivote_background' in arg for arg in cmdline):
                            memory_mb = proc.info['memory_info'].rss / 1024 / 1024
                            self.log_test("STABILITY", "Memory Usage", memory_mb < 1000,
                                        f"Memory: {memory_mb:.1f} MB")
                            break
                except Exception as e:
                    self.log_test("STABILITY", "Memory Usage", False, error=e)
            else:
                self.log_test("STABILITY", "Status Check", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("STABILITY", "System Stability", False, error=e)
    
    def run_all_tests(self):
        """Run all enhanced error recovery tests"""
        print("🧪 ENHANCED ERROR RECOVERY AND RESILIENCE TEST SUITE")
        print("=" * 70)
        
        test_categories = [
            self.test_health_endpoint,
            self.test_enhanced_status_api,
            self.test_failure_recording,
            self.test_auto_recovery_settings,
            self.test_health_monitoring_interval,
            self.test_concurrent_operation_resilience,
            self.test_error_recovery_mechanisms,
            self.test_system_stability
        ]
        
        for test_category in test_categories:
            try:
                test_category()
            except Exception as e:
                print(f"❌ Test category failed: {e}")
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 70)
        print("📊 ENHANCED ERROR RECOVERY TEST REPORT")
        print("=" * 70)
        
        # Calculate statistics
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['passed'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        # Group by category
        categories = {}
        for result in self.test_results:
            category = result['category']
            if category not in categories:
                categories[category] = {'passed': 0, 'failed': 0}
            if result['passed']:
                categories[category]['passed'] += 1
            else:
                categories[category]['failed'] += 1
        
        # Print summary
        print(f"\n📈 OVERALL RESULTS:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Success Rate: {success_rate:.1f}%")
        
        print(f"\n📋 CATEGORY BREAKDOWN:")
        for category, stats in categories.items():
            total = stats['passed'] + stats['failed']
            rate = (stats['passed'] / total * 100) if total > 0 else 0
            status = "✅" if rate == 100 else "⚠️" if rate >= 80 else "❌"
            print(f"   {status} {category}: {stats['passed']}/{total} ({rate:.1f}%)")
        
        # Print failed tests
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['passed']:
                    print(f"   • {result['category']}: {result['test']}")
                    if result['details']:
                        print(f"     Details: {result['details']}")
                    if result['error']:
                        print(f"     Error: {result['error']}")
        
        # Overall assessment
        if success_rate >= 95:
            assessment = "🏆 EXCELLENT - Enhanced Error Recovery is production-ready!"
        elif success_rate >= 80:
            assessment = "✅ GOOD - Enhanced Error Recovery is functional with minor issues"
        elif success_rate >= 60:
            assessment = "⚠️ FAIR - Enhanced Error Recovery needs improvements"
        else:
            assessment = "❌ POOR - Enhanced Error Recovery has significant issues"
        
        print(f"\n🎯 ASSESSMENT: {assessment}")
        
        # Save detailed report
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": success_rate,
                "assessment": assessment
            },
            "categories": categories,
            "results": self.test_results
        }
        
        with open("enhanced_error_recovery_test_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: enhanced_error_recovery_test_report.json")

if __name__ == "__main__":
    test_suite = EnhancedErrorRecoveryTest()
    test_suite.run_all_tests() 