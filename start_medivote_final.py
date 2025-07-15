#!/usr/bin/env python3
"""
MediVote Final Startup Script
Complete working system startup
"""

import os
import sys
import time
import subprocess
import requests
import threading
from pathlib import Path
import psutil  # Add this import for process management

class MediVoteFinalRunner:
    def __init__(self):
        self.processes = {}
        self.ports = {
            'backend': 8001,
            'frontend': 8080,
            'blockchain': 8081,
            'incentive': 8082
        }
        
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
    def kill_existing_processes(self):
        self.log("🛑 Stopping existing python.exe processes (except self)...")
        try:
            import psutil
            current_pid = os.getpid()
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    if proc.info['name'] and 'python' in proc.info['name'].lower():
                        if proc.pid != current_pid:
                            proc.terminate()
                            self.log(f"Terminated python.exe with PID {proc.pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(2)
        except Exception as e:
            self.log(f"Error killing python processes: {e}")
            
    def start_backend(self):
        """Start the backend server"""
        self.log("🚀 Starting Backend Server...")
        
        try:
            # Start backend using uvicorn
            process = subprocess.Popen([
                sys.executable, "-m", "uvicorn", 
                "backend.main:app",
                "--host", "0.0.0.0",
                "--port", str(self.ports['backend']),
                "--reload", "false"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['backend'] = process
            time.sleep(5)  # Give it more time to start
            
            # Test if it's running
            try:
                response = requests.get(f"http://localhost:{self.ports['backend']}/health", timeout=10)
                if response.status_code == 200:
                    self.log("✅ Backend is running")
                    return True
            except:
                pass
                
            self.log("❌ Backend failed to start")
            return False
            
        except Exception as e:
            self.log(f"❌ Error starting backend: {e}")
            return False
            
    def start_frontend(self):
        """Start frontend server"""
        self.log("🚀 Starting Frontend Server...")
        
        try:
            frontend_dir = Path("frontend")
            if frontend_dir.exists():
                process = subprocess.Popen([
                    sys.executable, "-m", "http.server", 
                    str(self.ports['frontend']),
                    "--directory", str(frontend_dir)
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes['frontend'] = process
                time.sleep(3)
                
                # Test if it's running
                try:
                    response = requests.get(f"http://localhost:{self.ports['frontend']}/", timeout=10)
                    if response.status_code == 200:
                        self.log("✅ Frontend is running")
                        return True
                except:
                    pass
                    
                self.log("❌ Frontend failed to start")
                return False
            else:
                self.log("❌ Frontend directory not found")
                return False
                
        except Exception as e:
            self.log(f"❌ Error starting frontend: {e}")
            return False
            
    def start_blockchain_node(self):
        """Start blockchain node"""
        self.log("🚀 Starting Blockchain Node...")
        
        try:
            # Create blockchain data directory
            Path("blockchain_data").mkdir(exist_ok=True)
            
            process = subprocess.Popen([
                sys.executable, "blockchain_node.py",
                "--port", str(self.ports['blockchain']),
                "--data-dir", "blockchain_data"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['blockchain'] = process
            time.sleep(3)
            self.log("✅ Blockchain node started")
            return True
            
        except Exception as e:
            self.log(f"❌ Error starting blockchain: {e}")
            return False
            
    def start_incentive_system(self):
        """Start incentive system"""
        self.log("🚀 Starting Incentive System...")
        
        try:
            process = subprocess.Popen([
                sys.executable, "node_incentive_system.py",
                "--port", str(self.ports['incentive'])
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['incentive'] = process
            time.sleep(3)
            self.log("✅ Incentive system started")
            return True
            
        except Exception as e:
            self.log(f"❌ Error starting incentive system: {e}")
            return False
            
    def print_system_info(self):
        """Print system information"""
        self.log("🎉 MediVote System is Running!")
        print("\n" + "=" * 60)
        print("🌐 Access URLs:")
        print(f"  Frontend:        http://localhost:{self.ports['frontend']}")
        print(f"  Backend API:     http://localhost:{self.ports['backend']}")
        print(f"  Blockchain:      http://localhost:{self.ports['blockchain']}")
        print(f"  Incentive:       http://localhost:{self.ports['incentive']}")
        print("=" * 60)
        print("📝 Quick Start:")
        print("1. Open http://localhost:8080 in your browser")
        print("2. Register as a voter")
        print("3. Run a blockchain node to create ballots")
        print("4. Cast your vote securely")
        print("=" * 60)
        print("💡 Press Ctrl+C to stop all services")
        print("=" * 60)
        
    def test_system(self):
        """Test all components"""
        self.log("🧪 Testing system components...")
        
        tests = [
            ("Backend", f"http://localhost:{self.ports['backend']}/health"),
            ("Frontend", f"http://localhost:{self.ports['frontend']}/"),
        ]
        
        working = 0
        for name, url in tests:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    self.log(f"✅ {name} is working")
                    working += 1
                else:
                    self.log(f"❌ {name} returned status {response.status_code}")
            except Exception as e:
                self.log(f"❌ {name} error: {e}")
                
        return working >= 1  # At least backend should work
        
    def run(self):
        """Run the complete system"""
        try:
            self.log("🚀 Starting MediVote System...")
            
            # Kill existing processes
            self.kill_existing_processes()
            
            # Start components
            backend_ok = self.start_backend()
            frontend_ok = self.start_frontend()
            blockchain_ok = self.start_blockchain_node()
            incentive_ok = self.start_incentive_system()
            
            # Test system
            if self.test_system():
                self.print_system_info()
                
                # Keep running
                while True:
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            self.log("🛑 Shutting down...")
            self.cleanup()
            
    def cleanup(self):
        """Clean up processes"""
        for name, process in self.processes.items():
            try:
                process.terminate()
                self.log(f"✅ Stopped {name}")
            except:
                pass

if __name__ == "__main__":
    runner = MediVoteFinalRunner()
    runner.run() 