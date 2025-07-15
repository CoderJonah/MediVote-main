#!/usr/bin/env python3
"""
MediVote Corrected Startup Script
Properly handles different service types
"""

import os
import sys
import time
import subprocess
import requests
import psutil
from pathlib import Path

class MediVoteCorrectedRunner:
    def __init__(self):
        self.processes = {}
        
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
    def kill_existing_processes(self):
        """Kill existing python processes except self"""
        self.log("🛑 Stopping existing python.exe processes (except self)...")
        try:
            current_pid = os.getpid()
            killed_count = 0
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and 'python' in proc.info['name'].lower():
                        if proc.pid != current_pid:
                            proc.terminate()
                            killed_count += 1
                            self.log(f"Terminated python.exe with PID {proc.pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if killed_count > 0:
                time.sleep(3)
            else:
                self.log("No other Python processes found")
        except Exception as e:
            self.log(f"Error killing python processes: {e}")
            
    def start_service(self, name, command, has_web_server=True, test_url=None, test_timeout=30):
        """Service starter with proper handling"""
        self.log(f"🚀 Starting {name}...")
        
        try:
            # Start the process
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            
            self.processes[name] = process
            time.sleep(10)  # Give time to start
            
            # Check if process is still running
            if process.poll() is None:
                if has_web_server and test_url:
                    # Test web server if it has one
                    start_time = time.time()
                    attempts = 0
                    while time.time() - start_time < test_timeout:
                        attempts += 1
                        try:
                            response = requests.get(test_url, timeout=10)
                            if response.status_code == 200:
                                self.log(f"✅ {name} is running (web server responding)")
                                return True
                        except requests.exceptions.RequestException:
                            if attempts % 3 == 0:
                                self.log(f"  Testing {test_url}... (attempt {attempts})")
                            time.sleep(3)
                            continue
                    
                    self.log(f"⚠️ {name} started but web server not responding")
                    return True  # Return True since process is running
                else:
                    # For services without web servers, just check if process is running
                    self.log(f"✅ {name} started successfully")
                    return True
            else:
                self.log(f"❌ {name} failed to start")
                return False
                
        except Exception as e:
            self.log(f"❌ Error starting {name}: {e}")
            return False
            
    def start_all_services(self):
        """Start all services with proper configuration"""
        services = [
            # Services with web servers
            ("Backend", [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"], True, "http://localhost:8001/health"),
            ("Frontend", [sys.executable, "-m", "http.server", "8080", "--directory", "frontend"], True, "http://localhost:8080/"),
            ("Incentive System", [sys.executable, "node_incentive_system.py", "--port", "8082"], True, "http://localhost:8082/status"),
            ("Network Coordinator", [sys.executable, "network_coordinator.py", "--port", "8083"], True, "http://localhost:8083/status"),
            ("Network Dashboard", [sys.executable, "network_dashboard.py", "--port", "8084"], True, "http://localhost:8084/"),
            
            # Services without web servers (background processes)
            ("Blockchain Node", [sys.executable, "blockchain_node.py", "--port", "8081", "--data-dir", "blockchain_data"], False),
        ]
        
        results = {}
        for service_info in services:
            if len(service_info) == 4:
                name, command, has_web_server, test_url = service_info
                results[name] = self.start_service(name, command, has_web_server, test_url)
            else:
                name, command, has_web_server = service_info
                results[name] = self.start_service(name, command, has_web_server)
            
            time.sleep(5)  # Wait between services
            
        return results
        
    def print_system_info(self):
        """Print system information"""
        self.log("🎉 MediVote System is Running!")
        print("\n" + "=" * 70)
        print("🌐 System Components:")
        print("  • Frontend:        http://localhost:8080")
        print("  • Backend API:     http://localhost:8001")
        print("  • Blockchain:      Running in background (port 8545)")
        print("  • Incentive:       http://localhost:8082")
        print("  • Coordinator:     http://localhost:8083")
        print("  • Dashboard:       http://localhost:8084")
        print("=" * 70)
        print("📝 Quick Start Guide:")
        print("1. Open http://localhost:8080 in your browser")
        print("2. Register as a voter")
        print("3. Run a blockchain node to create ballots")
        print("4. Cast your vote securely")
        print("5. Monitor the network at http://localhost:8084")
        print("=" * 70)
        print("🔧 System Features:")
        print("  • Decentralized blockchain voting")
        print("  • Node incentive system")
        print("  • Real-time network monitoring")
        print("  • Advanced cryptographic security")
        print("  • End-to-end verifiability")
        print("=" * 70)
        print("💡 Press Ctrl+C to stop all services")
        print("=" * 70)
        
    def run(self):
        """Run the complete MediVote system"""
        try:
            self.log("🚀 Starting MediVote Complete System...")
            
            # Kill existing processes
            self.kill_existing_processes()
            
            # Start all services
            results = self.start_all_services()
            
            # Print results
            working = sum(1 for success in results.values() if success)
            self.log(f"📊 Started {working}/{len(results)} services successfully")
            
            if working > 0:
                self.print_system_info()
                
                # Keep running
                while True:
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            self.log("🛑 Shutting down complete system...")
            self.cleanup()
            
    def cleanup(self):
        """Clean up all processes"""
        for name, process in self.processes.items():
            try:
                process.terminate()
                self.log(f"✅ Stopped {name}")
            except:
                pass

if __name__ == "__main__":
    runner = MediVoteCorrectedRunner()
    runner.run() 