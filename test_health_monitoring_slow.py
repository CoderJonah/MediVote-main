#!/usr/bin/env python3
"""
Slow Health Monitoring Test
Tests the health monitoring system with longer intervals and detailed verification
"""

import requests
import time
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SlowHealthMonitoringTest:
    def __init__(self):
        self.base_url = "http://localhost:8090"
        self.test_results = []
        
    def log_test(self, category, test_name, passed, details=None, error=None):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        message = f"{status}: [{category}] {test_name}"
        if details:
            message += f" - {details}"
        if error:
            message += f" - Error: {error}"
        
        print(message)
        logger.info(message)
        
        self.test_results.append({
            'category': category,
            'test_name': test_name,
            'passed': passed,
            'details': details,
            'error': str(error) if error else None
        })
    
    def test_health_endpoint_availability(self):
        """Test if health endpoint is available"""
        print("\n🏥 Testing Health Endpoint Availability...")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                self.log_test("HEALTH", "Endpoint Available", True, f"Status: {response.status_code}")
                return True
            else:
                self.log_test("HEALTH", "Endpoint Available", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("HEALTH", "Endpoint Available", False, error=e)
            return False
    
    def test_health_data_structure(self):
        """Test health data structure"""
        print("\n📊 Testing Health Data Structure...")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                
                # Check if we have data for all expected services
                expected_services = ['backend', 'blockchain_node',
                                   'incentive_system', 'network_coordinator',
                                   'network_dashboard', 'frontend']
                
                missing_services = [service for service in expected_services if service not in health_data]
                if missing_services:
                    self.log_test("STRUCTURE", "All Services Present", False, f"Missing: {missing_services}")
                    return False
                
                self.log_test("STRUCTURE", "All Services Present", True, f"Found {len(health_data)} services")
                
                # Check structure of each service
                for service_id, health_info in health_data.items():
                    required_fields = ['status', 'last_check', 'uptime', 'restart_count', 
                                     'failure_count', 'last_failure', 'recovery_attempts']
                    
                    missing_fields = [field for field in required_fields if field not in health_info]
                    if missing_fields:
                        self.log_test("STRUCTURE", f"{service_id} Health Fields", False, f"Missing: {missing_fields}")
                        return False
                
                self.log_test("STRUCTURE", "Health Fields Complete", True, "All required fields present")
                return True
            else:
                self.log_test("STRUCTURE", "Health Data Structure", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("STRUCTURE", "Health Data Structure", False, error=e)
            return False
    
    def test_health_monitoring_updates(self):
        """Test if health monitoring actually updates over time"""
        print("\n⏰ Testing Health Monitoring Updates (15 second test)...")
        
        try:
            # Get initial health data
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code != 200:
                self.log_test("MONITORING", "Initial Health Data", False, f"Status: {response.status_code}")
                return False
            
            initial_data = response.json()
            initial_times = {}
            
            # Record initial check times
            for service_id, health_info in initial_data.items():
                initial_times[service_id] = health_info.get('last_check', 0)
            
            print(f"📅 Initial check times recorded for {len(initial_times)} services")
            
            # Wait 15 seconds for health monitoring to update
            print("⏳ Waiting 15 seconds for health monitoring updates...")
            time.sleep(15)
            
            # Get updated health data
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code != 200:
                self.log_test("MONITORING", "Updated Health Data", False, f"Status: {response.status_code}")
                return False
            
            updated_data = response.json()
            updated_count = 0
            
            # Check which services were updated
            for service_id, health_info in updated_data.items():
                if service_id in initial_times:
                    current_time = health_info.get('last_check', 0)
                    initial_time = initial_times[service_id]
                    
                    if current_time > initial_time:
                        updated_count += 1
                        print(f"✅ {service_id}: {initial_time:.2f} -> {current_time:.2f}")
                    else:
                        print(f"❌ {service_id}: No update ({initial_time:.2f} -> {current_time:.2f})")
            
            # Calculate update percentage
            total_services = len(initial_times)
            update_percentage = (updated_count / total_services) * 100 if total_services > 0 else 0
            
            print(f"📊 Update Summary: {updated_count}/{total_services} services updated ({update_percentage:.1f}%)")
            
            if updated_count > 0:
                self.log_test("MONITORING", "Health Data Updates", True, 
                            f"Updated: {updated_count}/{total_services} ({update_percentage:.1f}%)")
                return True
            else:
                self.log_test("MONITORING", "Health Data Updates", False, 
                            f"Updated: {updated_count}/{total_services} ({update_percentage:.1f}%)")
                return False
                
        except Exception as e:
            self.log_test("MONITORING", "Health Monitoring Updates", False, error=e)
            return False
    
    def test_health_monitoring_interval(self):
        """Test health monitoring interval timing"""
        print("\n⏱️ Testing Health Monitoring Interval (25 second test)...")
        
        try:
            # Get initial health data
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code != 200:
                self.log_test("INTERVAL", "Initial Health Data", False, f"Status: {response.status_code}")
                return False
            
            initial_data = response.json()
            initial_times = {}
            
            # Record initial check times
            for service_id, health_info in initial_data.items():
                initial_times[service_id] = health_info.get('last_check', 0)
            
            print(f"📅 Initial check times recorded for {len(initial_times)} services")
            
            # Wait 25 seconds (should trigger 2-3 health check cycles with 10s interval)
            print("⏳ Waiting 25 seconds for multiple health check cycles...")
            time.sleep(25)
            
            # Get updated health data
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code != 200:
                self.log_test("INTERVAL", "Updated Health Data", False, f"Status: {response.status_code}")
                return False
            
            updated_data = response.json()
            update_intervals = []
            
            # Calculate time intervals between updates
            for service_id, health_info in updated_data.items():
                if service_id in initial_times:
                    current_time = health_info.get('last_check', 0)
                    initial_time = initial_times[service_id]
                    
                    if current_time > initial_time:
                        interval = current_time - initial_time
                        update_intervals.append(interval)
                        print(f"⏱️ {service_id}: {interval:.1f}s interval")
            
            if update_intervals:
                avg_interval = sum(update_intervals) / len(update_intervals)
                min_interval = min(update_intervals)
                max_interval = max(update_intervals)
                
                print(f"📊 Interval Analysis:")
                print(f"   Average: {avg_interval:.1f}s")
                print(f"   Range: {min_interval:.1f}s - {max_interval:.1f}s")
                print(f"   Expected: ~10s (configured interval)")
                
                # Check if intervals are reasonable (between 15-40 seconds for production systems)
                reasonable_intervals = [interval for interval in update_intervals if 15 <= interval <= 40]
                reasonable_percentage = (len(reasonable_intervals) / len(update_intervals)) * 100 if update_intervals else 0
                
                if reasonable_percentage >= 80:
                    self.log_test("INTERVAL", "Health Check Timing", True, 
                                f"Average: {avg_interval:.1f}s, {reasonable_percentage:.1f}% reasonable")
                    return True
                else:
                    self.log_test("INTERVAL", "Health Check Timing", False, 
                                f"Average: {avg_interval:.1f}s, {reasonable_percentage:.1f}% reasonable")
                    return False
            else:
                self.log_test("INTERVAL", "Health Check Timing", False, "No updates detected")
                return False
                
        except Exception as e:
            self.log_test("INTERVAL", "Health Monitoring Interval", False, error=e)
            return False
    
    def test_health_status_consistency(self):
        """Test consistency between health and status endpoints"""
        print("\n🔄 Testing Health-Status Consistency...")
        
        try:
            # Get health data
            health_response = requests.get(f"{self.base_url}/health", timeout=10)
            if health_response.status_code != 200:
                self.log_test("CONSISTENCY", "Health Endpoint", False, f"Status: {health_response.status_code}")
                return False
            
            # Get status data
            status_response = requests.get(f"{self.base_url}/status", timeout=10)
            if status_response.status_code != 200:
                self.log_test("CONSISTENCY", "Status Endpoint", False, f"Status: {status_response.status_code}")
                return False
            
            health_data = health_response.json()
            status_data = status_response.json()
            
            # Check if services present in both endpoints
            health_services = set(health_data.keys())
            status_services = set(status_data.keys())
            
            if health_services == status_services:
                self.log_test("CONSISTENCY", "Service Coverage", True, f"Both endpoints have {len(health_services)} services")
            else:
                missing_in_status = health_services - status_services
                missing_in_health = status_services - health_services
                self.log_test("CONSISTENCY", "Service Coverage", False, 
                            f"Missing in status: {missing_in_status}, Missing in health: {missing_in_health}")
                return False
            
            # Check if status endpoint includes health information
            services_with_health = 0
            for service_id, status_info in status_data.items():
                if 'health' in status_info:
                    services_with_health += 1
            
            health_coverage = (services_with_health / len(status_data)) * 100 if status_data else 0
            
            if health_coverage >= 80:
                self.log_test("CONSISTENCY", "Health Integration", True, f"{health_coverage:.1f}% of services have health info")
                return True
            else:
                self.log_test("CONSISTENCY", "Health Integration", False, f"{health_coverage:.1f}% of services have health info")
                return False
                
        except Exception as e:
            self.log_test("CONSISTENCY", "Health-Status Consistency", False, error=e)
            return False
    
    def run_all_tests(self):
        """Run all health monitoring tests"""
        print("🧪 SLOW HEALTH MONITORING TEST SUITE")
        print("=" * 60)
        print("Testing health monitoring with longer intervals and detailed verification")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run tests
        tests = [
            self.test_health_endpoint_availability,
            self.test_health_data_structure,
            self.test_health_monitoring_updates,
            self.test_health_monitoring_interval,
            self.test_health_status_consistency
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                logger.error(f"Test {test.__name__} failed with exception: {e}")
        
        # Calculate results
        success_rate = (passed / total) * 100 if total > 0 else 0
        duration = time.time() - start_time
        
        print("\n" + "=" * 60)
        print("📊 SLOW HEALTH MONITORING TEST RESULTS")
        print("=" * 60)
        print(f"⏱️  Test Duration: {duration:.1f} seconds")
        print(f"📈 Success Rate: {success_rate:.1f}% ({passed}/{total})")
        
        if success_rate >= 80:
            print("🎯 ASSESSMENT: ✅ EXCELLENT - Health monitoring is working correctly!")
        elif success_rate >= 60:
            print("🎯 ASSESSMENT: ⚠️ GOOD - Health monitoring is mostly working")
        else:
            print("🎯 ASSESSMENT: ❌ NEEDS IMPROVEMENT - Health monitoring has issues")
        
        # Save detailed report
        report = {
            'test_suite': 'Slow Health Monitoring Test',
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': duration,
            'total_tests': total,
            'passed_tests': passed,
            'success_rate': success_rate,
            'results': self.test_results
        }
        
        with open('slow_health_monitoring_test_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: slow_health_monitoring_test_report.json")
        
        return success_rate >= 80

if __name__ == "__main__":
    test = SlowHealthMonitoringTest()
    success = test.run_all_tests()
    exit(0 if success else 1) 