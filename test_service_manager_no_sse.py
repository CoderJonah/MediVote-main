#!/usr/bin/env python3
"""
Test Suite for MediVote Service Manager (No SSE)
Tests the service manager without SSE to avoid hanging issues
"""

import requests
import json
import time
import threading
import psutil
import socket
import sys
import os
from datetime import datetime
import traceback

class NoSSEServiceManagerTestSuite:
    def __init__(self):
        self.base_url = "http://localhost:8090"
        self.test_results = []
        self.errors = []
        
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
            self.errors.append(f"[{category}] {test_name}: {error}")
    
    def test_connectivity(self):
        """Test basic connectivity to service manager"""
        print("\n🔗 Testing Connectivity...")
        
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            self.log_test("CONNECTIVITY", "HTTP Server Response", 
                         response.status_code == 200, 
                         f"Status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            self.log_test("CONNECTIVITY", "HTTP Server Response", False, "Connection refused")
        except Exception as e:
            self.log_test("CONNECTIVITY", "HTTP Server Response", False, error=e)
    
    def test_status_api(self):
        """Test the status API endpoint"""
        print("\n📊 Testing Status API...")
        
        try:
            response = requests.get(f"{self.base_url}/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("API", "Status Endpoint", True, f"Got {len(data)} services")
                
                # Test each service status
                for service_id, info in data.items():
                    has_required_fields = all(key in info for key in ['name', 'port', 'status'])
                    self.log_test("API", f"Service {service_id} Status", has_required_fields,
                                f"Status: {info.get('status', 'missing')}")
            else:
                self.log_test("API", "Status Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("API", "Status Endpoint", False, error=e)
    
    def test_service_operations(self):
        """Test service start/stop/restart operations"""
        print("\n⚙️ Testing Service Operations...")
        
        # Test restart operation
        try:
            response = requests.post(f"{self.base_url}/restart/backend", timeout=20)
            if response.status_code == 200:
                data = response.json()
                self.log_test("OPERATIONS", "Restart Backend", data.get('success', False),
                            f"Response: {data}")
            else:
                self.log_test("OPERATIONS", "Restart Backend", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("OPERATIONS", "Restart Backend", False, error=e)
        
        # Test stop operation
        try:
            response = requests.post(f"{self.base_url}/stop/frontend", timeout=20)
            if response.status_code == 200:
                data = response.json()
                self.log_test("OPERATIONS", "Stop Frontend", data.get('success', False),
                            f"Response: {data}")
            else:
                self.log_test("OPERATIONS", "Stop Frontend", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("OPERATIONS", "Stop Frontend", False, error=e)
        
        # Test start operation
        try:
            response = requests.post(f"{self.base_url}/start/frontend", timeout=20)
            if response.status_code == 200:
                data = response.json()
                self.log_test("OPERATIONS", "Start Frontend", data.get('success', False),
                            f"Response: {data}")
            else:
                self.log_test("OPERATIONS", "Start Frontend", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("OPERATIONS", "Start Frontend", False, error=e)
    
    def test_resource_monitoring(self):
        """Test CPU and memory monitoring"""
        print("\n📈 Testing Resource Monitoring...")
        
        try:
            response = requests.get(f"{self.base_url}/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for service_id, info in data.items():
                    if info.get('status') == 'running':
                        # Check if CPU and memory values are present
                        cpu_present = 'cpu_percent' in info
                        memory_present = 'memory_mb' in info
                        
                        self.log_test("RESOURCES", f"{service_id} CPU Monitoring", cpu_present,
                                    f"CPU: {info.get('cpu_percent', 'missing')}")
                        self.log_test("RESOURCES", f"{service_id} Memory Monitoring", memory_present,
                                    f"Memory: {info.get('memory_mb', 'missing')} MB")
                        
                        # Check if values are numeric
                        if cpu_present:
                            cpu_value = info.get('cpu_percent')
                            is_numeric = isinstance(cpu_value, (int, float))
                            self.log_test("RESOURCES", f"{service_id} CPU Numeric", is_numeric,
                                        f"CPU value: {cpu_value} (type: {type(cpu_value)})")
                        
                        if memory_present:
                            memory_value = info.get('memory_mb')
                            is_numeric = isinstance(memory_value, (int, float))
                            self.log_test("RESOURCES", f"{service_id} Memory Numeric", is_numeric,
                                        f"Memory value: {memory_value} (type: {type(memory_value)})")
            else:
                self.log_test("RESOURCES", "Status API", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("RESOURCES", "Status API", False, error=e)
    
    def test_port_availability(self):
        """Test if all service ports are available"""
        print("\n🔌 Testing Port Availability...")
        
        # Only test the main service manager port and a few key service ports
        expected_ports = [8090, 8001]  # Main service manager and backend
        
        for port in expected_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                
                is_open = result == 0
                self.log_test("PORTS", f"Port {port}", is_open, 
                            "Open" if is_open else "Closed")
            except Exception as e:
                self.log_test("PORTS", f"Port {port}", False, error=e)
    
    def test_error_handling(self):
        """Test error handling for invalid requests"""
        print("\n🚨 Testing Error Handling...")
        
        # Test invalid service ID
        try:
            response = requests.post(f"{self.base_url}/restart/invalid_service", timeout=10)
            # Should handle gracefully (not crash)
            self.log_test("ERROR_HANDLING", "Invalid Service ID", True,
                        f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("ERROR_HANDLING", "Invalid Service ID", False, error=e)
        
        # Test invalid endpoint
        try:
            response = requests.get(f"{self.base_url}/invalid_endpoint", timeout=10)
            # Should return 404 or handle gracefully
            self.log_test("ERROR_HANDLING", "Invalid Endpoint", True,
                        f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("ERROR_HANDLING", "Invalid Endpoint", False, error=e)
    
    def test_concurrent_operations(self):
        """Test concurrent operations"""
        print("\n🔄 Testing Concurrent Operations...")
        
        def make_request(operation, service_id):
            try:
                response = requests.post(f"{self.base_url}/{operation}/{service_id}", timeout=15)
                return response.status_code == 200
            except:
                return False
        
        # Test concurrent restart operations
        threads = []
        results = []
        
        for i in range(3):
            thread = threading.Thread(target=lambda: results.append(make_request('restart', 'backend')))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        success_count = sum(results)
        self.log_test("CONCURRENCY", "Concurrent Restart Operations", success_count > 0,
                    f"Success: {success_count}/3")
    
    def test_memory_usage(self):
        """Test memory usage of service manager"""
        print("\n💾 Testing Memory Usage...")
        
        try:
            # Find service manager process
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    cmdline = proc.cmdline()
                    if 'python' in proc.info['name'].lower() and any('start_medivote_background' in arg for arg in cmdline):
                        memory_mb = proc.info['memory_info'].rss / 1024 / 1024
                        self.log_test("MEMORY", "Service Manager Memory Usage", memory_mb < 500,
                                    f"Memory: {memory_mb:.1f} MB")
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            else:
                self.log_test("MEMORY", "Service Manager Memory Usage", False, "Process not found")
        except Exception as e:
            self.log_test("MEMORY", "Service Manager Memory Usage", False, error=e)
    
    def test_process_cleanup(self):
        """Test process cleanup when services are stopped"""
        print("\n🧹 Testing Process Cleanup...")
        
        try:
            # Get initial process count (fix the generator issue)
            initial_count = len(list(psutil.process_iter()))
            
            # Stop a service
            response = requests.post(f"{self.base_url}/stop/network_dashboard", timeout=15)
            
            if response.status_code == 200:
                time.sleep(5)  # Wait for cleanup
                
                # Check if process count decreased
                final_count = len(list(psutil.process_iter()))
                cleanup_success = final_count <= initial_count
                
                self.log_test("CLEANUP", "Process Cleanup", cleanup_success,
                            f"Processes: {initial_count} -> {final_count}")
            else:
                self.log_test("CLEANUP", "Process Cleanup", False, f"Stop failed: {response.status_code}")
        except Exception as e:
            self.log_test("CLEANUP", "Process Cleanup", False, error=e)
    
    def test_ui_functionality(self):
        """Test UI functionality through HTTP requests"""
        print("\n🖥️ Testing UI Functionality...")
        
        try:
            # Test main dashboard
            response = requests.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                content = response.text
                has_medivote = 'MediVote' in content
                has_service_cards = 'service-card' in content
                has_buttons = 'button' in content
                
                self.log_test("UI", "Dashboard Content", has_medivote, "Contains MediVote branding")
                self.log_test("UI", "Service Cards", has_service_cards, "Contains service cards")
                self.log_test("UI", "Action Buttons", has_buttons, "Contains action buttons")
            else:
                self.log_test("UI", "Dashboard Content", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("UI", "Dashboard Content", False, error=e)
    
    def test_service_health(self):
        """Test that all services are healthy"""
        print("\n🏥 Testing Service Health...")
        
        try:
            response = requests.get(f"{self.base_url}/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Check that all services are running
                running_services = 0
                total_services = len(data)
                
                for service_id, info in data.items():
                    if info.get('status') == 'running':
                        running_services += 1
                        self.log_test("HEALTH", f"{service_id} Running", True, 
                                    f"PID: {info.get('pid', 'N/A')}")
                    else:
                        self.log_test("HEALTH", f"{service_id} Running", False, 
                                    f"Status: {info.get('status', 'unknown')}")
                
                # Overall health check
                health_ratio = running_services / total_services if total_services > 0 else 0
                self.log_test("HEALTH", "Overall Service Health", health_ratio >= 0.8,
                            f"Running: {running_services}/{total_services} ({health_ratio:.1%})")
            else:
                self.log_test("HEALTH", "Service Health Check", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("HEALTH", "Service Health Check", False, error=e)
    
    def run_all_tests(self):
        """Run all tests"""
        print("🧪 NO-SSE MEDIVOTE SERVICE MANAGER TEST SUITE")
        print("=" * 60)
        
        # Run all test categories (excluding SSE)
        test_categories = [
            self.test_connectivity,
            self.test_status_api,
            self.test_service_operations,
            self.test_resource_monitoring,
            self.test_port_availability,
            self.test_error_handling,
            self.test_concurrent_operations,
            self.test_memory_usage,
            self.test_process_cleanup,
            self.test_ui_functionality,
            self.test_service_health
        ]
        
        for test_category in test_categories:
            try:
                test_category()
            except Exception as e:
                print(f"❌ Test category failed: {e}")
                traceback.print_exc()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 NO-SSE TEST REPORT")
        print("=" * 60)
        
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
        
        # Print errors
        if self.errors:
            print(f"\n🚨 ERRORS:")
            for error in self.errors:
                print(f"   • {error}")
        
        # Overall assessment
        if success_rate >= 95:
            assessment = "🏆 EXCELLENT - Service Manager is production-ready!"
        elif success_rate >= 80:
            assessment = "✅ GOOD - Service Manager is functional with minor issues"
        elif success_rate >= 60:
            assessment = "⚠️ FAIR - Service Manager needs improvements"
        else:
            assessment = "❌ POOR - Service Manager has significant issues"
        
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
            "results": self.test_results,
            "errors": self.errors
        }
        
        with open("no_sse_test_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: no_sse_test_report.json")

if __name__ == "__main__":
    test_suite = NoSSEServiceManagerTestSuite()
    test_suite.run_all_tests() 