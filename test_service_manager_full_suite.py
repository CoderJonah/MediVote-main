#!/usr/bin/env python3
"""
Comprehensive Test Suite for MediVote Service Manager
Tests all major functionality of start_medivote_background.py
"""

import asyncio
import json
import os
import psutil
import requests
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock, create_autospec

# Import the service manager
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import start_medivote_background


# Set Windows event loop policy for asyncio
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class TestServiceManager(unittest.TestCase):
    """Base test class for MediVote Service Manager"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests"""
        # Create test directories
        cls.test_dir = tempfile.mkdtemp(prefix="medivote_test_")
        cls.logs_dir = os.path.join(cls.test_dir, "logs")
        os.makedirs(cls.logs_dir, exist_ok=True)
        
        # Save original directory
        cls.original_dir = os.getcwd()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests"""
        # Restore original directory
        os.chdir(cls.original_dir)
        
        # Clean up test directory
        import shutil
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Set up for each test"""
        self.manager = start_medivote_background.MediVoteBackgroundManager()
        
        # Mock subprocess to prevent actual service starts
        self.popen_patcher = patch('subprocess.Popen')
        self.mock_popen = self.popen_patcher.start()
        
        # Create mock process
        self.mock_process = Mock()
        self.mock_process.poll.return_value = None  # Process running
        self.mock_process.pid = 12345
        self.mock_process.wait.return_value = 0
        self.mock_process.terminate = Mock()
        self.mock_process.kill = Mock()
        
        self.mock_popen.return_value = self.mock_process
        
        # Mock webbrowser to prevent opening browsers
        self.browser_patcher = patch('webbrowser.open')
        self.mock_browser = self.browser_patcher.start()
        
        # Don't mock socket globally - it interferes with asyncio
        # Instead, we'll mock specific manager methods when needed
        
        # Mock open for log files
        self.open_patcher = patch('builtins.open', create=True)
        self.mock_open = self.open_patcher.start()
        self.mock_log_handle = Mock()
        self.mock_open.return_value = self.mock_log_handle
        
    def tearDown(self):
        """Clean up after each test"""
        self.popen_patcher.stop()
        self.browser_patcher.stop()
        self.open_patcher.stop()
        
        # Stop any running services
        if hasattr(self.manager, 'is_running'):
            self.manager.is_running = False


class TestServiceStartup(TestServiceManager):
    """Test service startup functionality"""
    
    async def test_start_single_service(self):
        """Test starting a single service"""
        # Start backend service
        result = await self.manager.start_service("backend")
        
        # Verify service started
        self.assertTrue(result)
        self.assertIn("backend", self.manager.processes)
        self.assertEqual(self.manager.processes["backend"].pid, 12345)
        
        # Verify subprocess was called correctly
        self.mock_popen.assert_called()
        call_args = self.mock_popen.call_args[0][0]
        self.assertIn("python", call_args[0])
        self.assertIn("backend/main.py", call_args[1])
    
    async def test_start_all_services(self):
        """Test starting all services"""
        # Mock the node config creation to avoid file I/O
        with patch.object(self.manager, '_create_node_configs', return_value=None):
            # Mock dashboard server creation and other methods
            with patch('socketserver.TCPServer'):
                with patch('threading.Thread'):
                    with patch.object(self.manager, 'start_dashboard_servers', return_value=None):
                        with patch.object(self.manager, 'open_management_dashboard', return_value=None):
                            with patch('asyncio.create_task'):  # Mock health monitoring task
                                result = await self.manager.start_all_services()
        
        # Verify all services started
        self.assertTrue(result)
        
        # Check that start was called for each service
        expected_services = ["backend", "blockchain_node", "incentive_system", 
                           "network_coordinator", "network_dashboard", "frontend"]
        
        # Verify each service has a process
        for service in expected_services:
            self.assertIn(service, self.manager.processes)
    
    async def test_service_already_running(self):
        """Test starting a service that's already running"""
        # Start service first time
        await self.manager.start_service("backend")
        
        # Reset mock
        self.mock_popen.reset_mock()
        
        # Try to start again
        result = await self.manager.start_service("backend")
        
        # Should return True but not start new process
        self.assertTrue(result)
        self.mock_popen.assert_not_called()
    
    async def test_port_already_in_use(self):
        """Test handling port already in use"""
        # Mock the port check to indicate port is in use
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0  # Port in use
            mock_socket.close = Mock()
            mock_socket.settimeout = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Try to start service
            result = await self.manager.start_service("backend")
        
        # Should still return True (service running externally)
        self.assertTrue(result)
        self.assertIn("backend", self.manager.processes)
    
    async def test_invalid_service(self):
        """Test starting invalid service"""
        result = await self.manager.start_service("invalid_service")
        self.assertFalse(result)


class TestServiceStop(TestServiceManager):
    """Test service stop functionality"""
    
    async def test_stop_single_service(self):
        """Test stopping a single service"""
        # Start service first
        await self.manager.start_service("backend")
        
        # Stop service
        result = await self.manager.stop_service("backend")
        
        # Verify stopped
        self.assertTrue(result)
        self.assertNotIn("backend", self.manager.processes)
        self.mock_process.terminate.assert_called()
    
    async def test_stop_all_services(self):
        """Test stopping all services"""
        # Start some services
        await self.manager.start_service("backend")
        await self.manager.start_service("frontend")
        
        # Mock the _try_graceful_shutdown method to avoid importing requests
        async def mock_graceful_shutdown(service_id, config, process):
            return False  # Simulate HTTP not available, will use SIGTERM
        
        with patch.object(self.manager, '_try_graceful_shutdown', side_effect=mock_graceful_shutdown):
            # Stop all
            await self.manager.stop_all_services()
        
        # Verify all stopped
        self.assertEqual(len(self.manager.processes), 0)
    
    async def test_graceful_shutdown(self):
        """Test graceful shutdown via HTTP"""
        # Start service first
        await self.manager.start_service("backend")
        
        # Mock the _try_graceful_shutdown method to simulate successful HTTP shutdown
        async def mock_graceful_shutdown(service_id, config, process):
            return True  # Simulate successful graceful shutdown
        
        with patch.object(self.manager, '_try_graceful_shutdown', side_effect=mock_graceful_shutdown):
            # Stop with graceful shutdown
            result = await self.manager.stop_service("backend", force=False)
            
            # Verify HTTP shutdown was attempted
            self.assertTrue(result)
            self.assertNotIn("backend", self.manager.processes)
    
    async def test_force_stop(self):
        """Test force stopping a service"""
        # Start service
        await self.manager.start_service("backend")
        
        # Force stop
        result = await self.manager.stop_service("backend", force=True)
        
        # Verify terminated
        self.assertTrue(result)
        self.mock_process.terminate.assert_called()
    
    async def test_stop_non_running_service(self):
        """Test stopping a service that's not running"""
        result = await self.manager.stop_service("backend")
        
        # Should still return True
        self.assertTrue(result)


class TestServiceRestart(TestServiceManager):
    """Test service restart functionality"""
    
    async def test_restart_running_service(self):
        """Test restarting a running service"""
        # Start service
        await self.manager.start_service("backend")
        
        # Reset mock to track restart
        self.mock_popen.reset_mock()
        
        # Restart service
        result = await self.manager.restart_service("backend")
        
        # Verify restarted
        self.assertTrue(result)
        self.mock_popen.assert_called()  # New process started
    
    async def test_restart_stopped_service(self):
        """Test restarting a stopped service (acts as start)"""
        # Don't start service first
        result = await self.manager.restart_service("backend")
        
        # Should start the service
        self.assertTrue(result)
        self.assertIn("backend", self.manager.processes)


class TestAutoRecovery(TestServiceManager):
    """Test auto-recovery functionality"""
    
    def test_auto_recovery_enabled_by_default(self):
        """Test that auto-recovery is enabled by default"""
        for service_id in self.manager.service_configs:
            self.assertTrue(self.manager.auto_recovery_enabled[service_id])
    
    def test_enable_disable_auto_recovery(self):
        """Test enabling/disabling auto-recovery"""
        # Disable
        result = self.manager.disable_auto_recovery("backend")
        self.assertTrue(result)
        self.assertFalse(self.manager.auto_recovery_enabled["backend"])
        
        # Enable
        result = self.manager.enable_auto_recovery("backend")
        self.assertTrue(result)
        self.assertTrue(self.manager.auto_recovery_enabled["backend"])
    
    async def test_auto_recovery_on_crash(self):
        """Test auto-recovery when service crashes"""
        # Start service
        await self.manager.start_service("backend")
        
        # Simulate crash
        self.mock_process.poll.return_value = 1  # Process exited
        
        # Record failure
        self.manager._record_service_failure("backend", "Test crash")
        
        # Attempt recovery
        with patch.object(self.manager, 'start_service', return_value=True) as mock_start:
            result = await self.manager._auto_recover_service("backend")
        
        # Verify recovery attempted
        self.assertTrue(result)
        mock_start.assert_called_with("backend")
    
    def test_max_failures_disable(self):
        """Test auto-recovery disabled after max failures"""
        # Record multiple failures
        for i in range(self.manager.max_failures_before_disable):
            self.manager._record_service_failure("backend", f"Failure {i}")
        
        # Check auto-recovery disabled
        self.assertFalse(self.manager.auto_recovery_enabled["backend"])


class TestHealthMonitoring(TestServiceManager):
    """Test health monitoring functionality"""
    
    async def test_health_check_process(self):
        """Test health check via process status"""
        # Start service
        await self.manager.start_service("backend")
        
        # Check health
        is_healthy = await self.manager._check_service_health("backend")
        
        # Should be healthy (process running)
        self.assertTrue(is_healthy)
    
    async def test_health_check_port(self):
        """Test health check via port availability"""
        # Start service
        await self.manager.start_service("backend")
        
        # Mock port check
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0  # Port in use (service running)
            mock_socket.close = Mock()
            mock_socket.settimeout = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Check health
            is_healthy = await self.manager._check_service_health("backend")
        
        self.assertTrue(is_healthy)
    
    async def test_health_check_http(self):
        """Test health check via HTTP endpoint"""
        # Mock requests
        with patch('start_medivote_background.requests') as mock_requests:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_requests.get.return_value = mock_response
            
            # Start service
            await self.manager.start_service("backend")
            
            # Check health
            is_healthy = await self.manager._check_service_health("backend")
            
            self.assertTrue(is_healthy)
    
    def test_get_service_health_info(self):
        """Test getting health information for a service"""
        health_info = self.manager.get_service_health_info("backend")
        
        # Check required fields
        self.assertIn('status', health_info)
        self.assertIn('last_check', health_info)
        self.assertIn('uptime', health_info)
        self.assertIn('auto_recovery_enabled', health_info)


class TestConcurrentOperations(TestServiceManager):
    """Test concurrent operation handling"""
    
    def test_concurrent_start_prevented(self):
        """Test preventing concurrent start operations"""
        # Start first operation
        self.manager.active_operations["backend"] = "start"
        
        # Try concurrent start
        result = self.manager._handle_concurrent_operation(
            "backend", "start", Mock(), "backend"
        )
        
        # Should be rejected
        self.assertFalse(result)
    
    def test_restart_overrides_stop(self):
        """Test restart can override stop operation"""
        # Set stop operation active
        self.manager.active_operations["backend"] = "stop"
        
        # Try restart
        result = self.manager._handle_concurrent_operation(
            "backend", "restart", Mock(), "backend"
        )
        
        # Should be allowed
        self.assertNotEqual(result, False)


class TestPortManagement(TestServiceManager):
    """Test port management functionality"""
    
    def test_find_available_port(self):
        """Test finding available port"""
        # Mock all ports busy except one
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            
            def mock_connect(addr):
                port = addr[1]
                return 0 if port != 8095 else 1  # 8095 is free
            
            mock_socket.connect_ex.side_effect = mock_connect
            mock_socket.close = Mock()
            mock_socket.settimeout = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Find available port
            port = self.manager._find_available_port(8090)
        
        # Should find 8095
        self.assertEqual(port, 8095)
    
    def test_random_port_fallback(self):
        """Test falling back to random port"""
        # Mock all standard ports busy and random port selection
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            
            # Mock connect_ex to return busy for all ports except 9500
            def connect_mock(addr):
                if isinstance(addr, tuple) and len(addr) >= 2:
                    return 1 if addr[1] == 9500 else 0
                return 0
            
            mock_socket.connect_ex.side_effect = connect_mock
            mock_socket.close = Mock()
            mock_socket.settimeout = Mock()
            mock_socket_class.return_value = mock_socket
            
            with patch('random.randint') as mock_random:
                # Make random port available
                mock_random.return_value = 9500
                
                port = self.manager._find_available_port(8090)
            
            # Should use random port
            self.assertEqual(port, 9500)


class TestServiceStatus(TestServiceManager):
    """Test service status tracking"""
    
    async def test_get_service_status(self):
        """Test getting status of all services"""
        # Start a service
        await self.manager.start_service("backend")
        
        # Get status
        status = self.manager.get_service_status()
        
        # Check backend status
        self.assertIn("backend", status)
        backend_status = status["backend"]
        self.assertEqual(backend_status["status"], "running")
        self.assertEqual(backend_status["pid"], 12345)
        self.assertEqual(backend_status["port"], 8001)
    
    def test_cpu_memory_tracking(self):
        """Test CPU and memory usage tracking"""
        # Mock psutil process
        with patch('psutil.Process') as mock_process_class:
            mock_proc = Mock()
            mock_proc.cpu_percent.return_value = 25.5
            mock_proc.memory_info.return_value = Mock(rss=100 * 1024 * 1024)  # 100MB
            mock_process_class.return_value = mock_proc
            
            # Get resources
            cpu, memory = self.manager._get_process_resources(12345)
            
            # Verify
            self.assertEqual(cpu, 25.5)
            self.assertEqual(memory, 100.0)


class TestResourceCleanup(TestServiceManager):
    """Test resource cleanup functionality"""
    
    async def test_log_handle_cleanup(self):
        """Test log file handle cleanup"""
        # Create mock log handle
        self.manager.log_handles = {"backend": self.mock_log_handle}
        
        # Start and stop service
        await self.manager.start_service("backend")
        await self.manager.stop_service("backend")
        
        # Verify log handle closed
        self.mock_log_handle.close.assert_called()
    
    def test_process_cache_cleanup(self):
        """Test process cache cleanup"""
        # Add to caches
        pid = 12345
        self.manager.cpu_cache[pid] = 25.0
        self.manager.memory_cache[pid] = 100.0
        self.manager.last_update[pid] = time.time()
        
        # Cleanup
        self.manager._cleanup_process_cache(pid)
        
        # Verify cleaned
        self.assertNotIn(pid, self.manager.cpu_cache)
        self.assertNotIn(pid, self.manager.memory_cache)
        self.assertNotIn(pid, self.manager.last_update)


class TestErrorHandling(TestServiceManager):
    """Test error handling"""
    
    async def test_start_service_error(self):
        """Test handling errors during service start"""
        # Mock subprocess to raise error
        self.mock_popen.side_effect = FileNotFoundError("Command not found")
        
        # Try to start
        result = await self.manager.start_service("backend")
        
        # Should return False
        self.assertFalse(result)
    
    async def test_invalid_service_handling(self):
        """Test handling invalid service IDs"""
        # Test various invalid operations
        self.assertFalse(await self.manager.start_service("invalid"))
        self.assertFalse(await self.manager.stop_service("invalid"))
        self.assertFalse(await self.manager.restart_service("invalid"))
        self.assertFalse(self.manager.enable_auto_recovery("invalid"))


class TestDashboardAndAPI(TestServiceManager):
    """Test dashboard and API functionality"""
    
    def test_create_management_dashboard(self):
        """Test management dashboard HTML creation"""
        html = self.manager._create_management_dashboard()
        
        # Verify HTML structure
        self.assertIn("<title>MediVote Service Manager</title>", html)
        self.assertIn("backend", html)
        self.assertIn("frontend", html)
        self.assertIn("blockchain_node", html)
    
    def test_create_service_dashboard(self):
        """Test service-specific dashboard creation"""
        config = self.manager.service_configs["backend"]
        html = self.manager._create_service_dashboard("backend", config)
        
        # Verify service dashboard
        self.assertIn("MediVote Backend", html)
        self.assertIn("8001", html)  # Port
        self.assertIn("backend", html)  # Service ID


class TestSignalHandling(TestServiceManager):
    """Test signal handling and graceful shutdown"""
    
    async def test_graceful_shutdown_signal(self):
        """Test graceful shutdown on SIGINT"""
        # Start services
        await self.manager.start_service("backend")
        await self.manager.start_service("frontend")
        
        # Simulate SIGINT
        self.manager._shutdown_requested = True
        
        # Stop all services
        await self.manager.stop_all_services()
        
        # Check all services stopped
        self.assertEqual(len(self.manager.processes), 0)


class TestLogging(TestServiceManager):
    """Test logging functionality"""
    
    def test_log_file_creation(self):
        """Test log file creation"""
        # Check logs directory exists
        self.assertTrue(os.path.exists("logs"))
        
        # Check service manager log configured
        import logging
        logger = logging.getLogger("start_medivote_background")
        self.assertTrue(logger.hasHandlers())
    
    async def test_subprocess_log_redirection(self):
        """Test subprocess output redirection to log files"""
        # Start service
        await self.manager.start_service("backend")
        
        # Check open was called for log file
        self.mock_open.assert_called()
        
        # Check that log file was opened with correct parameters
        call_args = [call[0] for call in self.mock_open.call_args_list]
        # Should have opened a log file
        self.assertTrue(any('backend.log' in str(arg[0]) for arg in call_args if arg))
        
        # Check Popen was called with log file handle
        self.mock_popen.assert_called()
        call_kwargs = self.mock_popen.call_args[1] if self.mock_popen.call_args[1] else {}
        # Should have stdout and stderr set
        self.assertIn('stdout', call_kwargs)
        self.assertIn('stderr', call_kwargs)


class TestIntegration(TestServiceManager):
    """Integration tests for complete workflows"""
    
    async def test_full_service_lifecycle(self):
        """Test complete service lifecycle"""
        service_id = "backend"
        
        # 1. Start service
        self.assertTrue(await self.manager.start_service(service_id))
        self.assertIn(service_id, self.manager.processes)
        
        # 2. Check health
        self.assertTrue(await self.manager._check_service_health(service_id))
        
        # 3. Get status
        status = self.manager.get_service_status()
        self.assertEqual(status[service_id]["status"], "running")
        
        # 4. Restart
        self.assertTrue(await self.manager.restart_service(service_id))
        
        # 5. Stop
        self.assertTrue(await self.manager.stop_service(service_id))
        self.assertNotIn(service_id, self.manager.processes)
    
    async def test_failure_recovery_workflow(self):
        """Test service failure and recovery workflow"""
        # Enable auto-recovery
        self.manager.enable_auto_recovery("backend")
        
        # Start service
        await self.manager.start_service("backend")
        
        # Simulate failure
        self.mock_process.poll.return_value = 1
        self.manager._record_service_failure("backend", "Simulated crash")
        
        # Attempt recovery
        with patch.object(self.manager, 'start_service', return_value=True):
            result = await self.manager._auto_recover_service("backend")
        
        self.assertTrue(result)


def run_async_test(test_func):
    """Helper to run async tests"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(test_func())
    finally:
        # Ensure pending tasks are cancelled
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        # Run loop until tasks are cancelled
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


def create_test_suite():
    """Create complete test suite"""
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestServiceStartup,
        TestServiceStop,
        TestServiceRestart,
        TestAutoRecovery,
        TestHealthMonitoring,
        TestConcurrentOperations,
        TestPortManagement,
        TestServiceStatus,
        TestResourceCleanup,
        TestErrorHandling,
        TestDashboardAndAPI,
        TestSignalHandling,
        TestLogging,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_tests(verbose=True):
    """Run all tests and generate report"""
    print("MediVote Service Manager - Comprehensive Test Suite")
    print("=" * 60)
    
    # Create test suite
    suite = create_test_suite()
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)
    
    # Generate summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            error_msg = str(traceback).split('\n')[-2] if '\n' in str(traceback) else str(traceback)
            print(f"  - {test}: {error_msg}")
    
    # Generate JSON report
    report = {
        "test_suite": "MediVote Service Manager Comprehensive Tests",
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tests": result.testsRun,
            "passed": result.testsRun - len(result.failures) - len(result.errors),
            "failed": len(result.failures),
            "errors": len(result.errors),
            "success_rate": f"{((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%" if result.testsRun > 0 else "0.0%"
        },
        "test_categories": [
            "Service Startup",
            "Service Stop",
            "Service Restart",
            "Auto-Recovery",
            "Health Monitoring",
            "Concurrent Operations",
            "Port Management",
            "Service Status",
            "Resource Cleanup",
            "Error Handling",
            "Dashboard and API",
            "Signal Handling",
            "Logging",
            "Integration"
        ]
    }
    
    with open("service_manager_test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: service_manager_test_report.json")
    
    return result.wasSuccessful()


def main():
    """Main test runner"""
    # Handle async tests properly
    for test_class in [TestServiceStartup, TestServiceStop, TestServiceRestart, 
                      TestAutoRecovery, TestHealthMonitoring, TestConcurrentOperations,
                      TestServiceStatus, TestResourceCleanup, TestErrorHandling,
                      TestSignalHandling, TestLogging, TestIntegration]:
        for method_name in dir(test_class):
            method = getattr(test_class, method_name)
            if method_name.startswith('test_') and asyncio.iscoroutinefunction(method):
                # Wrap async test methods
                def create_sync_test(async_method):
                    def sync_test(self):
                        run_async_test(lambda: async_method(self))
                    return sync_test
                
                setattr(test_class, method_name, create_sync_test(method))
    
    # Run tests
    success = run_tests(verbose=True)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 