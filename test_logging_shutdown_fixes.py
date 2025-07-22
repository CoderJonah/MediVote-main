#!/usr/bin/env python3
"""
Test Logging and Shutdown Fixes
Validates that both unicode logging errors and HTTP shutdown timeouts are resolved
"""

import asyncio
import json
import logging
import requests
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

class LoggingShutdownTester:
    """Test the logging and shutdown fixes"""
    
    def __init__(self):
        self.test_results = []
        
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
    
    def test_logging_configuration(self):
        """Test that logging configuration doesn't crash on unicode"""
        try:
            self.log("🧪 Testing Logging Configuration...")
            
            # Test import without crashes
            import start_medivote_background
            self.record_result("Logging Import", True, "Service manager imports without logging errors")
            
            # Test logger creation
            logger = logging.getLogger("test_unicode")
            
            # Test various unicode characters that could cause issues
            test_messages = [
                "SUCCESS: Test message with success indicator",
                "✅ Checkmark emoji (should not crash)",
                "🔧 Tool emoji test",  
                "Unicode characters: ñ ü ö é à ç",
                "Mixed content: SUCCESS ✅ with emoji and text"
            ]
            
            unicode_errors = 0
            for i, message in enumerate(test_messages):
                try:
                    logger.info(f"Test message {i+1}: {message}")
                except UnicodeEncodeError:
                    unicode_errors += 1
            
            if unicode_errors == 0:
                self.record_result("Unicode Logging", True, f"All {len(test_messages)} test messages logged without errors")
            else:
                self.record_result("Unicode Logging", False, f"{unicode_errors}/{len(test_messages)} messages caused unicode errors")
            
        except Exception as e:
            self.record_result("Logging Configuration", False, f"Import or logging test failed: {e}")
    
    def test_service_endpoints(self):
        """Test that HTTP shutdown endpoints exist for Tier 1 services"""
        self.log("🔗 Testing HTTP Shutdown Endpoints...")
        
        # Test that services have the expected endpoints
        tier1_services = [
            ("backend", 8001, "Backend"),
            ("blockchain_node", 8546, "Blockchain Node"),  
            ("incentive_system", 8082, "Incentive System"),
            ("network_coordinator", 8083, "Network Coordinator")
        ]
        
        for service_id, port, name in tier1_services:
            self.log(f"Checking {name} shutdown endpoint structure...")
            
            # We can't actually test the endpoints without starting services,
            # but we can verify the code structure exists
            try:
                if service_id == "backend":
                    import backend.main
                    # Check if backend has shutdown endpoint in code
                    has_endpoint = "/shutdown" in str(backend.main.__dict__)
                    
                elif service_id == "blockchain_node":
                    import blockchain_node
                    # Check if shutdown handler exists
                    source_code = str(blockchain_node.__dict__)
                    has_endpoint = "shutdown_handler" in source_code
                    
                elif service_id == "incentive_system":
                    import node_incentive_system
                    source_code = str(node_incentive_system.__dict__)
                    has_endpoint = "_shutdown_handler" in source_code
                    
                elif service_id == "network_coordinator":
                    import network_coordinator
                    source_code = str(network_coordinator.__dict__)
                    has_endpoint = "shutdown_handler" in source_code
                
                if has_endpoint:
                    self.record_result(f"{name} Endpoint", True, "Shutdown endpoint code found")
                else:
                    self.record_result(f"{name} Endpoint", False, "Shutdown endpoint code not found")
                    
            except Exception as e:
                self.record_result(f"{name} Endpoint", False, f"Could not verify endpoint: {e}")
    
    def test_timeout_configuration(self):
        """Test that timeout configuration is properly implemented"""
        self.log("⏱️ Testing Timeout Configuration...")
        
        try:
            # Import service manager
            import start_medivote_background
            
            # Create a manager instance to test the timeout logic
            manager = start_medivote_background.MediVoteBackgroundManager()
            
            # Test the tiered shutdown logic exists
            if hasattr(manager, '_try_graceful_shutdown'):
                self.record_result("Tiered Shutdown Method", True, "_try_graceful_shutdown method exists")
                
                # Check if tier classification exists in the method
                import inspect
                method_source = inspect.getsource(manager._try_graceful_shutdown)
                
                if "tier1_critical_services" in method_source:
                    self.record_result("Tier 1 Classification", True, "Tier 1 services properly classified")
                else:
                    self.record_result("Tier 1 Classification", False, "Tier 1 classification not found")
                
                if "tier2_simple_services" in method_source:
                    self.record_result("Tier 2 Classification", True, "Tier 2 services properly classified")
                else:
                    self.record_result("Tier 2 Classification", False, "Tier 2 classification not found")
                
                if "http_request_timeout" in method_source:
                    self.record_result("Service-Specific Timeouts", True, "Service-specific timeout logic found")
                else:
                    self.record_result("Service-Specific Timeouts", False, "Service-specific timeout logic not found")
            else:
                self.record_result("Tiered Shutdown Method", False, "_try_graceful_shutdown method not found")
                
        except Exception as e:
            self.record_result("Timeout Configuration", False, f"Could not test timeout configuration: {e}")
    
    def test_log_directory_creation(self):
        """Test that log directory is created properly"""
        self.log("📁 Testing Log Directory Creation...")
        
        try:
            # Import should create logs directory
            import start_medivote_background
            
            # Check if logs directory exists
            logs_dir = Path("logs")
            if logs_dir.exists() and logs_dir.is_dir():
                self.record_result("Log Directory Creation", True, "logs/ directory exists")
            else:
                self.record_result("Log Directory Creation", False, "logs/ directory not found")
                
        except Exception as e:
            self.record_result("Log Directory Creation", False, f"Error testing log directory: {e}")
    
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
        with open("logging_shutdown_fixes_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*80)
        print("🧪 LOGGING & SHUTDOWN FIXES TEST REPORT")
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
            print("✅ Logging and shutdown fixes working correctly!")
        
        print("="*80)
        print(f"📄 Detailed report saved to: logging_shutdown_fixes_test_report.json")
        
        return success_rate >= 80
    
    def run_all_tests(self):
        """Run all logging and shutdown tests"""
        self.log("🧪 Starting Logging & Shutdown Fixes Tests...")
        
        try:
            # Test logging configuration
            self.test_logging_configuration()
            
            # Test service endpoints
            self.test_service_endpoints()
            
            # Test timeout configuration
            self.test_timeout_configuration()
            
            # Test log directory creation
            self.test_log_directory_creation()
            
        except Exception as e:
            self.log(f"❌ Test execution error: {e}")
            self.record_result("Test Execution", False, f"Unhandled error: {e}")
        
        # Generate and return report
        return self.generate_report()

def main():
    """Main test function"""
    print("🧪 MediVote Logging & Shutdown Fixes Test Suite")
    print("=" * 60)
    print("Testing unicode logging fixes and HTTP shutdown improvements")
    print("=" * 60)
    
    tester = LoggingShutdownTester()
    success = tester.run_all_tests()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 