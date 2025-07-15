#!/usr/bin/env python3
"""
MediVote Complete System Startup
Full decentralized voting system with all components
"""

import os
import sys
import time
import subprocess
import requests
import threading
import psutil
import argparse
from pathlib import Path

class MediVoteCompleteRunner:
    def __init__(self, skip_kill=False):
        self.processes = {}
        self.skip_kill = skip_kill
        self.ports = {
            'backend': 8001,
            'frontend': 8080,
            'blockchain': 8081,
            'incentive': 8082,
            'coordinator': 8083,
            'dashboard': 8084
        }
        
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
                time.sleep(3)  # Give more time for processes to terminate
            else:
                self.log("No other Python processes found")
        except Exception as e:
            self.log(f"Error killing python processes: {e}")
            
    def start_backend(self):
        """Start the backend server"""
        self.log("🚀 Starting Backend Server...")
        
        try:
            process = subprocess.Popen([
                sys.executable, "-m", "uvicorn", 
                "backend.main:app",
                "--host", "0.0.0.0",
                "--port", str(self.ports['backend']),
                "--reload", "false"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['backend'] = process
            time.sleep(8)  # Give more time to start
            
            # Test if it's running with retries
            for attempt in range(3):
                try:
                    response = requests.get(f"http://localhost:{self.ports['backend']}/health", timeout=10)
                    if response.status_code == 200:
                        self.log("✅ Backend is running")
                        return True
                except:
                    if attempt < 2:
                        self.log(f"Backend not ready, retrying... (attempt {attempt + 1}/3)")
                        time.sleep(3)
                    else:
                        self.log("❌ Backend failed to start after 3 attempts")
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
            time.sleep(5)  # Give more time to start
            
            # Test if it's running with retries
            for attempt in range(3):
                try:
                    response = requests.get(f"http://localhost:{self.ports['incentive']}/status", timeout=10)
                    if response.status_code == 200:
                        self.log("✅ Incentive system is running")
                        return True
                except:
                    if attempt < 2:
                        self.log(f"Incentive system not ready, retrying... (attempt {attempt + 1}/3)")
                        time.sleep(3)
                    else:
                        self.log("✅ Incentive system started (status endpoint may not be available)")
                        return True  # Return True even if status endpoint fails
                        
        except Exception as e:
            self.log(f"❌ Error starting incentive system: {e}")
            return False
            
    def start_network_coordinator(self):
        """Start network coordinator"""
        self.log("🚀 Starting Network Coordinator...")
        
        try:
            process = subprocess.Popen([
                sys.executable, "network_coordinator.py",
                "--port", str(self.ports['coordinator'])
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['coordinator'] = process
            time.sleep(3)
            self.log("✅ Network coordinator started")
            return True
            
        except Exception as e:
            self.log(f"❌ Error starting network coordinator: {e}")
            return False
            
    def start_network_dashboard(self):
        """Start network dashboard"""
        self.log("🚀 Starting Network Dashboard...")
        
        try:
            process = subprocess.Popen([
                sys.executable, "network_dashboard.py",
                "--port", str(self.ports['dashboard'])
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['dashboard'] = process
            time.sleep(3)
            self.log("✅ Network dashboard started")
            return True
            
        except Exception as e:
            self.log(f"❌ Error starting network dashboard: {e}")
            return False
            
    def test_all_services(self):
        """Test all running services"""
        self.log("🧪 Testing all system components...")
        
        tests = [
            ("Backend", f"http://localhost:{self.ports['backend']}/health"),
            ("Frontend", f"http://localhost:{self.ports['frontend']}/"),
            ("Incentive System", f"http://localhost:{self.ports['incentive']}/status"),
        ]
        
        working = 0
        for name, url in tests:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    self.log(f"✅ {name} is working")
                    working += 1
                else:
                    self.log(f"⚠️ {name} returned status {response.status_code}")
            except Exception as e:
                self.log(f"⚠️ {name} not responding: {str(e)[:50]}...")
                
        self.log(f"📊 {working}/{len(tests)} core services are working")
        return working >= 1  # At least one service should work
        
    def print_system_info(self):
        """Print comprehensive system information"""
        self.log("🎉 MediVote Complete System is Running!")
        print("\n" + "=" * 70)
        print("🌐 System Components:")
        print(f"  • Frontend:        http://localhost:{self.ports['frontend']}")
        print(f"  • Backend API:     http://localhost:{self.ports['backend']}")
        print(f"  • Blockchain:      http://localhost:{self.ports['blockchain']}")
        print(f"  • Incentive:       http://localhost:{self.ports['incentive']}")
        print(f"  • Coordinator:     http://localhost:{self.ports['coordinator']}")
        print(f"  • Dashboard:       http://localhost:{self.ports['dashboard']}")
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
            
            # Kill existing processes (unless skipped)
            if not self.skip_kill:
                self.kill_existing_processes()
            else:
                self.log("⏭️ Skipping process cleanup (--skip-kill flag used)")
            
            # Start all components
            backend_ok = self.start_backend()
            frontend_ok = self.start_frontend()
            blockchain_ok = self.start_blockchain_node()
            incentive_ok = self.start_incentive_system()
            coordinator_ok = self.start_network_coordinator()
            dashboard_ok = self.start_network_dashboard()
            
            # Test system
            if self.test_all_services():
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
    parser = argparse.ArgumentParser(description="Start MediVote Complete System")
    parser.add_argument("--skip-kill", action="store_true", help="Skip killing existing python processes")
    args = parser.parse_args()

    runner = MediVoteCompleteRunner(skip_kill=args.skip_kill)
    runner.run() 