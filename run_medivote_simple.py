#!/usr/bin/env python3
"""
Simple MediVote Startup Script
Starts each component individually with proper error handling
"""

import os
import sys
import time
import subprocess
import threading
import requests
from pathlib import Path

class SimpleMediVoteRunner:
    def __init__(self):
        self.processes = {}
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
        
    def start_backend(self):
        """Start the backend server"""
        self.log("🚀 Starting Backend Server...")
        
        try:
            # Start backend in a separate process
            process = subprocess.Popen([
                sys.executable, "-m", "uvicorn", 
                "backend.main:app",
                "--host", "0.0.0.0",
                "--port", str(self.ports['backend']),
                "--reload", "false"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['backend'] = process
            time.sleep(3)  # Give it time to start
            
            # Test if it's running
            try:
                response = requests.get(f"http://localhost:{self.ports['backend']}/health", timeout=5)
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
            
    def start_blockchain_node(self):
        """Start blockchain node"""
        self.log("🚀 Starting Blockchain Node...")
        
        try:
            process = subprocess.Popen([
                sys.executable, "blockchain_node.py",
                "--port", str(self.ports['blockchain'])
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes['blockchain'] = process
            time.sleep(2)
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
            time.sleep(2)
            self.log("✅ Incentive system started")
            return True
            
        except Exception as e:
            self.log(f"❌ Error starting incentive system: {e}")
            return False
            
    def start_frontend(self):
        """Start frontend server"""
        self.log("🚀 Starting Frontend Server...")
        
        try:
            # Create a simple HTTP server for the frontend
            frontend_dir = Path("frontend")
            if frontend_dir.exists():
                process = subprocess.Popen([
                    sys.executable, "-m", "http.server", 
                    str(self.ports['frontend']),
                    "--directory", str(frontend_dir)
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes['frontend'] = process
                time.sleep(2)
                self.log("✅ Frontend server started")
                return True
            else:
                self.log("❌ Frontend directory not found")
                return False
                
        except Exception as e:
            self.log(f"❌ Error starting frontend: {e}")
            return False
            
    def print_status(self):
        """Print system status and URLs"""
        self.log("🎉 MediVote System Status")
        print("=" * 50)
        print(f"Backend API:     http://localhost:{self.ports['backend']}")
        print(f"Frontend:        http://localhost:{self.ports['frontend']}")
        print(f"Blockchain:      http://localhost:{self.ports['blockchain']}")
        print(f"Incentive:       http://localhost:{self.ports['incentive']}")
        print("=" * 50)
        print("📝 Quick Start:")
        print("1. Open http://localhost:8080 in your browser")
        print("2. Register as a voter")
        print("3. Run a blockchain node to create ballots")
        print("4. Cast your vote securely")
        print("=" * 50)
        
    def run(self):
        """Run the complete system"""
        try:
            self.log("🚀 Starting MediVote System...")
            
            # Start components
            backend_ok = self.start_backend()
            blockchain_ok = self.start_blockchain_node()
            incentive_ok = self.start_incentive_system()
            frontend_ok = self.start_frontend()
            
            if backend_ok and frontend_ok:
                self.print_status()
                
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
    runner = SimpleMediVoteRunner()
    runner.run() 