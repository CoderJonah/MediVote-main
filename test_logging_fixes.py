#!/usr/bin/env python3
"""
Test Logging Fixes
Validates that all logging issues have been resolved
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

class LoggingFixesTester:
    """Test that all logging fixes work correctly"""
    
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
    
    def test_backend_logging_config(self):
        """Test that backend has proper logging configuration"""
        self.log("🔍 Testing Backend Logging Configuration...")
        
        try:
            with open("backend/main.py", 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for logging setup
            has_logging_import = "import logging" in content
            has_basicConfig = "logging.basicConfig" in content
            has_file_handler = "FileHandler('../logs/backend.log'" in content
            has_logger = "logger = logging.getLogger" in content
            has_logger_calls = "logger.info" in content or "logger.error" in content
            
            if has_logging_import and has_basicConfig and has_file_handler and has_logger and has_logger_calls:
                self.record_result("Backend Logging Configuration", True, "All logging components found")
            else:
                missing = []
                if not has_logging_import: missing.append("logging import")
                if not has_basicConfig: missing.append("basicConfig")
                if not has_file_handler: missing.append("FileHandler")
                if not has_logger: missing.append("logger creation")
                if not has_logger_calls: missing.append("logger calls")
                self.record_result("Backend Logging Configuration", False, f"Missing: {', '.join(missing)}")
                
        except Exception as e:
            self.record_result("Backend Logging Configuration", False, f"Error reading backend: {e}")
    
    def test_frontend_logging_config(self):
        """Test that frontend has proper logging configuration"""
        self.log("🔍 Testing Frontend Logging Configuration...")
        
        try:
            with open("frontend/serve.py", 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for logging setup
            has_logging_import = "import logging" in content
            has_basicConfig = "logging.basicConfig" in content
            has_file_handler = "FileHandler('../logs/frontend.log'" in content
            has_logger = "logger = logging.getLogger" in content
            has_logger_calls = "logger.info" in content or "logger.error" in content
            
            if has_logging_import and has_basicConfig and has_file_handler and has_logger and has_logger_calls:
                self.record_result("Frontend Logging Configuration", True, "All logging components found")
            else:
                missing = []
                if not has_logging_import: missing.append("logging import")
                if not has_basicConfig: missing.append("basicConfig")
                if not has_file_handler: missing.append("FileHandler")
                if not has_logger: missing.append("logger creation")
                if not has_logger_calls: missing.append("logger calls")
                self.record_result("Frontend Logging Configuration", False, f"Missing: {', '.join(missing)}")
                
        except Exception as e:
            self.record_result("Frontend Logging Configuration", False, f"Error reading frontend: {e}")
    
    def test_service_manager_subprocess_fix(self):
        """Test that service manager subprocess redirection is fixed"""
        self.log("🔄 Testing Service Manager Subprocess Logging Fix...")
        
        try:
            with open("start_medivote_background.py", 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for subprocess fixes
            has_log_handle_open = "log_handle = open(log_file, 'a'" in content
            has_stdout_redirect = "stdout=log_handle" in content
            has_stderr_redirect = "stderr=log_handle" in content
            has_log_handles_storage = "self.log_handles[service_id] = log_handle" in content
            has_cleanup = "log_handles[service_id].close()" in content
            
            if has_log_handle_open and has_stdout_redirect and has_stderr_redirect and has_log_handles_storage and has_cleanup:
                self.record_result("Subprocess Logging Fix", True, "Proper subprocess redirection implemented")
            else:
                missing = []
                if not has_log_handle_open: missing.append("log handle opening")
                if not has_stdout_redirect: missing.append("stdout redirection")  
                if not has_stderr_redirect: missing.append("stderr redirection")
                if not has_log_handles_storage: missing.append("handle storage")
                if not has_cleanup: missing.append("handle cleanup")
                self.record_result("Subprocess Logging Fix", False, f"Missing: {', '.join(missing)}")
                
        except Exception as e:
            self.record_result("Subprocess Logging Fix", False, f"Error checking service manager: {e}")
    
    def test_log_file_structure(self):
        """Test current log file structure"""
        self.log("📊 Testing Log File Structure...")
        
        log_dir = Path("logs")
        if not log_dir.exists():
            self.record_result("Log Directory", False, "Logs directory doesn't exist")
            return
        
        expected_logs = [
            "medivote_background.log",
            "backend.log",
            "frontend.log",
            "blockchain_node.log",
            "incentive_system.log",
            "network_coordinator.log",
            "network_dashboard.log"
        ]
        
        missing_logs = []
        working_logs = 0
        
        for log_name in expected_logs:
            log_path = log_dir / log_name
            if log_path.exists():
                size = log_path.stat().st_size
                if size > 100:  # More than just placeholder text
                    working_logs += 1
                    self.log(f"  ✅ {log_name}: {size} bytes")
                else:
                    self.log(f"  ⚠️ {log_name}: {size} bytes (placeholder only)")
            else:
                missing_logs.append(log_name)
                self.log(f"  ❌ {log_name}: Missing")
        
        if missing_logs:
            self.record_result("Log Files Exist", False, f"Missing: {', '.join(missing_logs)}")
        else:
            self.record_result("Log Files Exist", True, f"All {len(expected_logs)} log files present")
        
        self.record_result("Active Logging", working_logs >= 2, f"{working_logs}/{len(expected_logs)} logs have active content")
    
    def test_service_startup_logging(self):
        """Test that services can start and log properly (quick test)"""
        self.log("🚀 Testing Quick Service Startup Logging...")
        
        # Test backend logging by importing and checking
        try:
            # Change to the appropriate directory for testing
            original_cwd = os.getcwd()
            
            # Test backend
            self.log("  Testing backend logging...")
            backend_result = subprocess.run(
                [sys.executable, "-c", "import sys; sys.path.append('backend'); import main; print('Backend logging test complete')"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=original_cwd
            )
            
            if backend_result.returncode == 0:
                self.record_result("Backend Startup Test", True, "Backend imports and runs without errors")
            else:
                self.record_result("Backend Startup Test", False, f"Backend failed: {backend_result.stderr}")
            
            # Test frontend
            self.log("  Testing frontend logging...")
            frontend_result = subprocess.run(
                [sys.executable, "-c", "import sys; sys.path.append('frontend'); import serve; print('Frontend logging test complete')"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=original_cwd
            )
            
            if frontend_result.returncode == 0:
                self.record_result("Frontend Startup Test", True, "Frontend imports and runs without errors")
            else:
                self.record_result("Frontend Startup Test", False, f"Frontend failed: {frontend_result.stderr}")
                
        except Exception as e:
            self.record_result("Service Startup Test", False, f"Test execution failed: {e}")
    
    def test_unicode_logging_fix(self):
        """Test that unicode logging fix is working"""
        self.log("✨ Testing Unicode Logging Fix...")
        
        try:
            # Import service manager and test unicode logging
            import start_medivote_background
            
            # This should not crash with unicode errors
            logger = start_medivote_background.logger
            test_messages = [
                "Unicode test: ✅ 🔧 🚦",
                "SUCCESS: This message should log without errors",
                "Emojis: 🎉 ❌ ⚠️",
                "Special chars: ñ ü ö é à ç"
            ]
            
            unicode_errors = 0
            for message in test_messages:
                try:
                    logger.info(message)
                except UnicodeEncodeError:
                    unicode_errors += 1
            
            if unicode_errors == 0:
                self.record_result("Unicode Logging Fix", True, f"All {len(test_messages)} unicode messages logged successfully")
            else:
                self.record_result("Unicode Logging Fix", False, f"{unicode_errors}/{len(test_messages)} messages caused unicode errors")
                
        except Exception as e:
            self.record_result("Unicode Logging Fix", False, f"Unicode test failed: {e}")
    
    def generate_report(self):
        """Generate comprehensive test report"""
        self.log("📊 Generating Logging Fixes Test Report...")
        
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
            "fixes_applied": [
                "Added logging configuration to backend/main.py",
                "Added logging configuration to frontend/serve.py", 
                "Fixed subprocess stdout/stderr redirection in service manager",
                "Added proper log file handle management",
                "Maintained unicode logging fix from previous work"
            ],
            "test_results": self.test_results,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save report to file
        with open("logging_fixes_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*80)
        print("🔧 LOGGING FIXES TEST REPORT")
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
            print("✅ All logging fixes working correctly!")
            print("")
            print("🔧 Fixes Applied Successfully:")
            for fix in report["fixes_applied"]:
                print(f"  ✅ {fix}")
        
        print("="*80)
        print(f"📄 Detailed report: logging_fixes_test_report.json")
        
        return success_rate >= 85
    
    def run_all_tests(self):
        """Run all logging fix tests"""
        self.log("🧪 Starting Logging Fixes Tests...")
        
        try:
            # Test individual service configurations
            self.test_backend_logging_config()
            self.test_frontend_logging_config()
            
            # Test service manager subprocess fix
            self.test_service_manager_subprocess_fix()
            
            # Test log file structure
            self.test_log_file_structure()
            
            # Test service startup
            self.test_service_startup_logging()
            
            # Test unicode fix
            self.test_unicode_logging_fix()
            
        except Exception as e:
            self.log(f"❌ Test execution error: {e}")
            self.record_result("Test Execution", False, f"Unhandled error: {e}")
        
        # Generate and return report
        return self.generate_report()

def main():
    """Main test function"""
    print("🔧 MediVote Logging Fixes Test Suite")
    print("=" * 60)
    print("Testing all applied logging fixes and improvements")
    print("=" * 60)
    
    tester = LoggingFixesTester()
    success = tester.run_all_tests()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 