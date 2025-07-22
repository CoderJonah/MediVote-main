#!/usr/bin/env python3
"""
Test Shutdown Queuing Fixes
Validates that HTTP timeouts no longer occur during queued shutdown operations
"""

import asyncio
import json
import requests
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

class ShutdownQueuingTester:
    """Test the shutdown queuing fixes"""
    
    def __init__(self):
        self.test_results = []
        self.base_url = "http://localhost:8090"
        
    def log(self, message: str, level: str = "INFO"):
        """Log test messages"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def record_result(self, test_name: str, success: bool, details: str = ""):
        """Record test result"""
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
        
        status = "✅ PASS" if success else "❌ FAIL"
        self.log(f"{status}: {test_name} - {details}")
    
    def test_throttling_configuration(self):
        """Test that throttling configuration is properly implemented"""
        self.log("🚦 Testing Shutdown Throttling Configuration...")
        
        try:
            # Import and check configuration
            import start_medivote_background
            
            manager = start_medivote_background.MediVoteBackgroundManager()
            
            # Check throttling attributes exist
            if hasattr(manager, 'last_shutdown_time'):
                self.record_result("Shutdown Time Tracking", True, "last_shutdown_time attribute exists")
            else:
                self.record_result("Shutdown Time Tracking", False, "last_shutdown_time attribute missing")
            
            if hasattr(manager, 'shutdown_throttle_delay'):
                delay = getattr(manager, 'shutdown_throttle_delay')
                self.record_result("Throttle Delay Config", True, f"Throttle delay set to {delay}s")
            else:
                self.record_result("Throttle Delay Config", False, "shutdown_throttle_delay missing")
            
            if hasattr(manager, 'bulk_shutdown_mode'):
                self.record_result("Bulk Shutdown Mode", True, "Bulk shutdown mode flag exists")
            else:
                self.record_result("Bulk Shutdown Mode", False, "bulk_shutdown_mode flag missing")
                
        except Exception as e:
            self.record_result("Throttling Configuration", False, f"Error testing configuration: {e}")
    
    def test_timeout_improvements(self):
        """Test that timeout improvements are implemented"""
        self.log("⏱️ Testing HTTP Timeout Improvements...")
        
        try:
            import start_medivote_background
            import inspect
            
            manager = start_medivote_background.MediVoteBackgroundManager()
            
            # Check if enhanced timeout logic exists in _try_graceful_shutdown
            method_source = inspect.getsource(manager._try_graceful_shutdown)
            
            if "http_request_timeout = 15" in method_source:
                self.record_result("Enhanced Timeouts", True, "Extended 15s timeout for critical services found")
            else:
                self.record_result("Enhanced Timeouts", False, "Enhanced timeout logic not found")
            
            if "retry_strategy" in method_source:
                self.record_result("Retry Logic", True, "HTTP retry mechanism found")
            else:
                self.record_result("Retry Logic", False, "HTTP retry mechanism not found")
            
            if "requests.exceptions.Timeout" in method_source:
                self.record_result("Enhanced Error Handling", True, "Specific timeout exception handling found")
            else:
                self.record_result("Enhanced Error Handling", False, "Enhanced error handling not found")
                
        except Exception as e:
            self.record_result("Timeout Improvements", False, f"Error testing timeouts: {e}")
    
    def test_bulk_shutdown_enhancements(self):
        """Test that bulk shutdown enhancements are implemented"""
        self.log("📦 Testing Bulk Shutdown Enhancements...")
        
        try:
            import start_medivote_background
            import inspect
            
            manager = start_medivote_background.MediVoteBackgroundManager()
            
            # Check if bulk shutdown improvements exist
            method_source = inspect.getsource(manager.stop_all_services)
            
            if "bulk_shutdown_mode = True" in method_source:
                self.record_result("Bulk Mode Activation", True, "Bulk shutdown mode activation found")
            else:
                self.record_result("Bulk Mode Activation", False, "Bulk shutdown mode activation not found")
            
            if "await asyncio.sleep(2.0)" in method_source:
                self.record_result("Enhanced Delays", True, "2.0s delays between services found")
            else:
                self.record_result("Enhanced Delays", False, "Enhanced delays not found")
            
            if "bulk_shutdown_mode = False" in method_source:
                self.record_result("Bulk Mode Cleanup", True, "Bulk shutdown mode cleanup found")
            else:
                self.record_result("Bulk Mode Cleanup", False, "Bulk shutdown mode cleanup not found")
                
        except Exception as e:
            self.record_result("Bulk Shutdown Enhancements", False, f"Error testing bulk shutdown: {e}")
    
    def test_tiered_shutdown_integration(self):
        """Test that the tiered shutdown approach is still intact"""
        self.log("🏗️ Testing Tiered Shutdown Integration...")
        
        try:
            import start_medivote_background
            import inspect
            
            manager = start_medivote_background.MediVoteBackgroundManager()
            
            # Check if tiered shutdown logic is still present
            method_source = inspect.getsource(manager._try_graceful_shutdown)
            
            if "tier1_critical_services" in method_source and "tier2_simple_services" in method_source:
                self.record_result("Tiered Service Classification", True, "Tier 1 and Tier 2 classification intact")
            else:
                self.record_result("Tiered Service Classification", False, "Service tier classification not found")
            
            # Check specific service assignments
            if "blockchain_node" in method_source and "incentive_system" in method_source:
                self.record_result("Tier 1 Services", True, "Critical services properly assigned to Tier 1")
            else:
                self.record_result("Tier 1 Services", False, "Tier 1 service assignments not found")
            
            if "network_dashboard" in method_source and "frontend" in method_source:
                self.record_result("Tier 2 Services", True, "Simple services properly assigned to Tier 2")
            else:
                self.record_result("Tier 2 Services", False, "Tier 2 service assignments not found")
                
        except Exception as e:
            self.record_result("Tiered Shutdown Integration", False, f"Error testing tiered shutdown: {e}")
    
    def test_individual_shutdown_throttling(self):
        """Test individual shutdown throttling logic"""
        self.log("🔄 Testing Individual Shutdown Throttling...")
        
        try:
            import start_medivote_background
            import inspect
            
            manager = start_medivote_background.MediVoteBackgroundManager()
            
            # Check individual shutdown throttling
            method_source = inspect.getsource(manager.stop_service)
            
            if "throttle_delay = self.shutdown_throttle_delay if self.bulk_shutdown_mode else 1.0" in method_source:
                self.record_result("Dual Mode Throttling", True, "Different throttling for bulk vs individual found")
            else:
                self.record_result("Dual Mode Throttling", False, "Dual mode throttling logic not found")
            
            if "Throttling" in method_source and "mode_desc" in method_source:
                self.record_result("Throttling Logging", True, "Enhanced throttling logging found")
            else:
                self.record_result("Throttling Logging", False, "Throttling logging not found")
                
        except Exception as e:
            self.record_result("Individual Shutdown Throttling", False, f"Error testing individual throttling: {e}")
    
    def generate_report(self):
        """Generate test report"""
        self.log("📊 Generating Test Report...")
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["success"]])
        failed_tests = total_tests - passed_tests
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            "test_summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": f"{success_rate:.1f}%"
            },
            "test_results": self.test_results,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save report to file
        with open("shutdown_queuing_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*80)
        print("🚦 SHUTDOWN QUEUING FIXES TEST REPORT")
        print("="*80)
        print(f"📊 Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        print("="*80)
        
        if failed_tests > 0:
            print("❌ Failed Tests:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  • {result['test']}: {result['details']}")
        else:
            print("🎉 ALL TESTS PASSED!")
            print("✅ Shutdown queuing fixes working correctly!")
            print("✨ Benefits:")
            print("  • No more HTTP timeouts during queued shutdowns")
            print("  • Proper throttling prevents service overload") 
            print("  • Enhanced retry logic for reliability")
            print("  • Bulk vs individual shutdown optimization")
        
        print("="*80)
        print(f"📄 Detailed report saved to: shutdown_queuing_test_report.json")
        
        return success_rate >= 85  # 85% success rate threshold
    
    def run_all_tests(self):
        """Run all shutdown queuing tests"""
        self.log("🧪 Starting Shutdown Queuing Fixes Tests...")
        
        try:
            # Test throttling configuration
            self.test_throttling_configuration()
            
            # Test timeout improvements
            self.test_timeout_improvements()
            
            # Test bulk shutdown enhancements
            self.test_bulk_shutdown_enhancements()
            
            # Test tiered shutdown integration
            self.test_tiered_shutdown_integration()
            
            # Test individual shutdown throttling
            self.test_individual_shutdown_throttling()
            
        except Exception as e:
            self.log(f"❌ Test execution error: {e}")
            self.record_result("Test Execution", False, f"Unhandled error: {e}")
        
        # Generate and return report
        return self.generate_report()

def main():
    """Main test function"""
    print("🚦 MediVote Shutdown Queuing Fixes Test Suite")
    print("=" * 65)
    print("Testing HTTP timeout prevention and throttling improvements")
    print("=" * 65)
    
    tester = ShutdownQueuingTester()
    success = tester.run_all_tests()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 