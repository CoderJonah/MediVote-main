#!/usr/bin/env python3
"""
Test Tiered Shutdown Implementation
Validates that the tiered shutdown approach works correctly for all service types
"""

import asyncio
import json
import requests
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

class TieredShutdownTester:
    """Test the tiered shutdown implementation"""
    
    def __init__(self):
        self.test_results = []
        self.service_manager_process = None
        self.base_management_url = "http://localhost:8090"
        
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
        
    async def start_service_manager(self):
        """Start the service manager for testing"""
        try:
            self.log("🚀 Starting MediVote Service Manager...")
            self.service_manager_process = subprocess.Popen([
                sys.executable, "start_medivote_background.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for service manager to start
            await asyncio.sleep(10)
            
            # Verify service manager is running
            try:
                response = requests.get(f"{self.base_management_url}/status", timeout=5)
                if response.status_code == 200:
                    self.record_result("Service Manager Startup", True, "Service manager started successfully")
                    return True
                else:
                    self.record_result("Service Manager Startup", False, f"Status check returned {response.status_code}")
                    return False
            except Exception as e:
                self.record_result("Service Manager Startup", False, f"Could not connect to service manager: {e}")
                return False
                
        except Exception as e:
            self.record_result("Service Manager Startup", False, f"Failed to start service manager: {e}")
            return False
    
    async def stop_service_manager(self):
        """Stop the service manager"""
        if self.service_manager_process:
            try:
                self.log("🛑 Stopping service manager...")
                self.service_manager_process.terminate()
                self.service_manager_process.wait(timeout=30)
                self.record_result("Service Manager Shutdown", True, "Service manager stopped cleanly")
            except Exception as e:
                self.record_result("Service Manager Shutdown", False, f"Error stopping service manager: {e}")
                try:
                    self.service_manager_process.kill()
                except:
                    pass
    
    async def test_tier1_services(self):
        """Test Tier 1 services (HTTP + SIGTERM fallback)"""
        self.log("🏗️ Testing Tier 1 Services (Critical Services)")
        
        tier1_services = [
            ("backend", 8001),
            ("blockchain_node", 8546),
            ("incentive_system", 8082),
            ("network_coordinator", 8083)
        ]
        
        for service_id, port in tier1_services:
            await self._test_tier1_service(service_id, port)
    
    async def _test_tier1_service(self, service_id: str, port: int):
        """Test a specific Tier 1 service"""
        try:
            # Start the service
            self.log(f"Starting {service_id}...")
            start_response = requests.post(f"{self.base_management_url}/start/{service_id}", timeout=30)
            
            if start_response.status_code != 200:
                self.record_result(f"Tier 1 - {service_id} Start", False, f"Start request failed: {start_response.status_code}")
                return
            
            # Wait for service to be running
            await asyncio.sleep(8)
            
            # Verify service is running
            status_response = requests.get(f"{self.base_management_url}/status", timeout=5)
            status_data = status_response.json()
            
            if service_id not in status_data or status_data[service_id]["status"] != "running":
                self.record_result(f"Tier 1 - {service_id} Running Check", False, "Service not running after start")
                return
            
            self.record_result(f"Tier 1 - {service_id} Start", True, "Service started and running")
            
            # Test HTTP shutdown endpoint directly
            try:
                shutdown_response = requests.post(f"http://localhost:{port}/shutdown", timeout=10)
                if shutdown_response.status_code == 200:
                    self.record_result(f"Tier 1 - {service_id} HTTP Shutdown", True, "HTTP shutdown endpoint responded")
                    
                    # Wait a bit and check if service stopped
                    await asyncio.sleep(5)
                    
                    # Verify service stopped
                    status_response = requests.get(f"{self.base_management_url}/status", timeout=5)
                    status_data = status_response.json()
                    
                    if service_id in status_data and status_data[service_id]["status"] == "stopped":
                        self.record_result(f"Tier 1 - {service_id} HTTP Shutdown Effect", True, "Service stopped after HTTP shutdown")
                    else:
                        self.record_result(f"Tier 1 - {service_id} HTTP Shutdown Effect", False, "Service still running after HTTP shutdown")
                        
                else:
                    self.record_result(f"Tier 1 - {service_id} HTTP Shutdown", False, f"HTTP shutdown returned {shutdown_response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.record_result(f"Tier 1 - {service_id} HTTP Shutdown", False, f"HTTP shutdown request failed: {e}")
            
        except Exception as e:
            self.record_result(f"Tier 1 - {service_id} Test", False, f"Test error: {e}")
    
    async def test_tier2_services(self):
        """Test Tier 2 services (SIGTERM only)"""
        self.log("🔧 Testing Tier 2 Services (Simple Services)")
        
        tier2_services = [
            ("network_dashboard", 8084),
            ("frontend", 8080)
        ]
        
        for service_id, port in tier2_services:
            await self._test_tier2_service(service_id, port)
    
    async def _test_tier2_service(self, service_id: str, port: int):
        """Test a specific Tier 2 service"""
        try:
            # Start the service
            self.log(f"Starting {service_id}...")
            start_response = requests.post(f"{self.base_management_url}/start/{service_id}", timeout=30)
            
            if start_response.status_code != 200:
                self.record_result(f"Tier 2 - {service_id} Start", False, f"Start request failed: {start_response.status_code}")
                return
            
            # Wait for service to be running
            await asyncio.sleep(8)
            
            # Verify service is running
            status_response = requests.get(f"{self.base_management_url}/status", timeout=5)
            status_data = status_response.json()
            
            if service_id not in status_data or status_data[service_id]["status"] != "running":
                self.record_result(f"Tier 2 - {service_id} Running Check", False, "Service not running after start")
                return
            
            self.record_result(f"Tier 2 - {service_id} Start", True, "Service started and running")
            
            # Verify NO shutdown endpoint exists (should get 404/405)
            try:
                shutdown_response = requests.post(f"http://localhost:{port}/shutdown", timeout=5)
                if shutdown_response.status_code in [404, 405, 501]:
                    self.record_result(f"Tier 2 - {service_id} No HTTP Shutdown", True, f"Correctly no shutdown endpoint (HTTP {shutdown_response.status_code})")
                else:
                    self.record_result(f"Tier 2 - {service_id} No HTTP Shutdown", False, f"Unexpected response: {shutdown_response.status_code}")
                    
            except requests.exceptions.RequestException:
                # This is expected for Tier 2 services
                self.record_result(f"Tier 2 - {service_id} No HTTP Shutdown", True, "Correctly no shutdown endpoint (connection failed)")
            
            # Test service manager stop (should use SIGTERM directly)
            stop_response = requests.post(f"{self.base_management_url}/stop/{service_id}", timeout=15)
            if stop_response.status_code == 200:
                self.record_result(f"Tier 2 - {service_id} Manager Stop", True, "Service manager stop request succeeded")
                
                # Wait and verify service stopped
                await asyncio.sleep(5)
                
                status_response = requests.get(f"{self.base_management_url}/status", timeout=5)
                status_data = status_response.json()
                
                if service_id in status_data and status_data[service_id]["status"] == "stopped":
                    self.record_result(f"Tier 2 - {service_id} SIGTERM Effect", True, "Service stopped after SIGTERM")
                else:
                    self.record_result(f"Tier 2 - {service_id} SIGTERM Effect", False, "Service still running after SIGTERM")
            else:
                self.record_result(f"Tier 2 - {service_id} Manager Stop", False, f"Stop request failed: {stop_response.status_code}")
                
        except Exception as e:
            self.record_result(f"Tier 2 - {service_id} Test", False, f"Test error: {e}")
    
    async def test_shutdown_logs(self):
        """Test that shutdown logs no longer show 404/501 errors"""
        self.log("📋 Testing Shutdown Log Quality...")
        
        try:
            # Start all services
            self.log("Starting all services for log test...")
            for service_id in ["backend", "blockchain_node", "incentive_system", "network_coordinator", "network_dashboard", "frontend"]:
                requests.post(f"{self.base_management_url}/start/{service_id}", timeout=30)
            
            await asyncio.sleep(15)  # Wait for all to start
            
            # Stop all services and capture behavior
            self.log("Stopping all services to test logs...")
            for service_id in ["frontend", "network_dashboard", "network_coordinator", "incentive_system", "blockchain_node", "backend"]:
                requests.post(f"{self.base_management_url}/stop/{service_id}", timeout=30)
                await asyncio.sleep(2)  # Brief delay between stops
            
            # Check if we can read logs to verify no errors
            log_file = Path("logs/medivote_background.log")
            if log_file.exists():
                # Read last 50 lines of log
                with open(log_file, 'r') as f:
                    lines = f.readlines()[-50:]  # Last 50 lines
                
                # Look for HTTP error codes
                error_codes = ["404", "501", "500"]
                shutdown_errors = []
                
                for line in lines:
                    if "shutdown" in line.lower():
                        for error_code in error_codes:
                            if error_code in line:
                                shutdown_errors.append(line.strip())
                
                if shutdown_errors:
                    self.record_result("Shutdown Log Quality", False, f"Found {len(shutdown_errors)} shutdown errors in logs")
                    for error in shutdown_errors[:3]:  # Show first 3 errors
                        self.log(f"  Error: {error}")
                else:
                    self.record_result("Shutdown Log Quality", True, "No HTTP errors found in shutdown logs")
            else:
                self.record_result("Shutdown Log Quality", False, "Could not find log file to check")
                
        except Exception as e:
            self.record_result("Shutdown Log Quality", False, f"Log test error: {e}")
    
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
        with open("tiered_shutdown_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*80)
        print("🧪 TIERED SHUTDOWN TEST REPORT")
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
            print("✅ Tiered shutdown implementation working correctly!")
        
        print("="*80)
        print(f"📄 Detailed report saved to: tiered_shutdown_test_report.json")
        
        return success_rate >= 80  # 80% success rate threshold
    
    async def run_all_tests(self):
        """Run all tiered shutdown tests"""
        self.log("🧪 Starting Tiered Shutdown Tests...")
        
        try:
            # Start service manager
            if not await self.start_service_manager():
                self.log("❌ Failed to start service manager, aborting tests")
                return False
            
            # Test Tier 1 services
            await self.test_tier1_services()
            
            # Test Tier 2 services  
            await self.test_tier2_services()
            
            # Test log quality
            await self.test_shutdown_logs()
            
        except Exception as e:
            self.log(f"❌ Test execution error: {e}")
            self.record_result("Test Execution", False, f"Unhandled error: {e}")
        
        finally:
            # Stop service manager
            await self.stop_service_manager()
        
        # Generate and return report
        return self.generate_report()

async def main():
    """Main test function"""
    print("🧪 MediVote Tiered Shutdown Test Suite")
    print("=" * 50)
    print("Testing the tiered shutdown implementation")
    print("=" * 50)
    
    tester = TieredShutdownTester()
    success = await tester.run_all_tests()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 