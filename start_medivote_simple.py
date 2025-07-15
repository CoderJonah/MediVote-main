#!/usr/bin/env python3
"""
MediVote Simple Startup Script
Simple and reliable startup without complex health checks
"""

import os
import sys
import time
import subprocess
import psutil
from pathlib import Path

class MediVoteSimpleRunner:
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
            
    def start_service(self, name, command):
        """Simple service starter"""
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
            time.sleep(8)  # Give time to start
            
            # Check if process is still running
            if process.poll() is None:
                self.log(f"✅ {name} started successfully")
                return True
            else:
                self.log(f"❌ {name} failed to start")
                return False
                
        except Exception as e:
            self.log(f"❌ Error starting {name}: {e}")
            return False
            
    def start_all_services(self):
        """Start all services"""
        services = [
            ("Backend", [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]),
            ("Frontend", [sys.executable, "-m", "http.server", "8080", "--directory", "frontend"]),
            ("Blockchain Node", [sys.executable, "blockchain_node.py", "--port", "8081", "--data-dir", "blockchain_data"]),
            ("Incentive System", [sys.executable, "node_incentive_system.py", "--port", "8082"]),
            ("Network Coordinator", [sys.executable, "network_coordinator.py", "--port", "8083"]),
            ("Network Dashboard", [sys.executable, "network_dashboard.py", "--port", "8084"]),
        ]
        
        results = {}
        for name, command in services:
            results[name] = self.start_service(name, command)
            time.sleep(3)  # Wait between services
            
        return results
        
    def print_system_info(self):
        """Print system information"""
        self.log("🎉 MediVote System is Starting!")
        print("\n" + "=" * 70)
        print("🌐 System Components:")
        print("  • Frontend:        http://localhost:8080")
        print("  • Backend API:     http://localhost:8001")
        print("  • Blockchain:      http://localhost:8081")
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
            self.log("🚀 Starting MediVote System...")
            
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
            self.log("🛑 Shutting down system...")
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
    runner = MediVoteSimpleRunner()
    runner.run() 