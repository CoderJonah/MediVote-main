#!/usr/bin/env python3
"""
MediVote Integrated System
Complete integration of backend, blockchain, incentive system, and frontend
"""

import os
import sys
import time
import json
import asyncio
import subprocess
import threading
import requests
from pathlib import Path
from typing import Dict, List, Optional
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class MediVoteIntegratedSystem:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.processes = {}
        self.config = {
            'backend_port': 8001,
            'frontend_port': 8080,
            'blockchain_port': 8081,
            'incentive_port': 8082,
            'coordinator_port': 8083,
            'dashboard_port': 8084
        }
        
        # Create necessary directories
        self.setup_directories()
        
    def setup_directories(self):
        """Create necessary directories for the system"""
        directories = [
            'blockchain_data',
            'network_data', 
            'logs',
            'temp'
        ]
        
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
            
    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def start_backend(self):
        """Start the FastAPI backend server"""
        self.log("Starting MediVote Backend...")
        
        try:
            # Import and run the backend
            from backend.main import app
            
            config = uvicorn.Config(
                app=app,
                host="0.0.0.0",
                port=self.config['backend_port'],
                log_level="info",
                reload=False
            )
            
            server = uvicorn.Server(config)
            
            def run_backend():
                server.run()
                
            backend_thread = threading.Thread(target=run_backend, daemon=True)
            backend_thread.start()
            
            self.processes['backend'] = backend_thread
            self.log("✅ Backend started successfully")
            
        except Exception as e:
            self.log(f"❌ Failed to start backend: {e}", "ERROR")
            
    def start_blockchain_node(self):
        """Start a blockchain node"""
        self.log("Starting Blockchain Node...")
        
        try:
            # Start blockchain node in a separate process
            node_script = self.base_dir / "blockchain_node.py"
            if node_script.exists():
                process = subprocess.Popen([
                    sys.executable, str(node_script),
                    "--port", str(self.config['blockchain_port']),
                    "--data-dir", "blockchain_data"
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes['blockchain_node'] = process
                self.log("✅ Blockchain node started successfully")
            else:
                self.log("❌ Blockchain node script not found", "ERROR")
                
        except Exception as e:
            self.log(f"❌ Failed to start blockchain node: {e}", "ERROR")
            
    def start_network_coordinator(self):
        """Start the network coordinator"""
        self.log("Starting Network Coordinator...")
        
        try:
            coordinator_script = self.base_dir / "network_coordinator.py"
            if coordinator_script.exists():
                process = subprocess.Popen([
                    sys.executable, str(coordinator_script),
                    "--port", str(self.config['coordinator_port'])
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes['network_coordinator'] = process
                self.log("✅ Network coordinator started successfully")
            else:
                self.log("❌ Network coordinator script not found", "ERROR")
                
        except Exception as e:
            self.log(f"❌ Failed to start network coordinator: {e}", "ERROR")
            
    def start_incentive_system(self):
        """Start the node incentive system"""
        self.log("Starting Node Incentive System...")
        
        try:
            incentive_script = self.base_dir / "node_incentive_system.py"
            if incentive_script.exists():
                process = subprocess.Popen([
                    sys.executable, str(incentive_script),
                    "--port", str(self.config['incentive_port'])
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes['incentive_system'] = process
                self.log("✅ Node incentive system started successfully")
            else:
                self.log("❌ Incentive system script not found", "ERROR")
                
        except Exception as e:
            self.log(f"❌ Failed to start incentive system: {e}", "ERROR")
            
    def start_network_dashboard(self):
        """Start the network dashboard"""
        self.log("Starting Network Dashboard...")
        
        try:
            dashboard_script = self.base_dir / "network_dashboard.py"
            if dashboard_script.exists():
                process = subprocess.Popen([
                    sys.executable, str(dashboard_script),
                    "--port", str(self.config['dashboard_port'])
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes['network_dashboard'] = process
                self.log("✅ Network dashboard started successfully")
            else:
                self.log("❌ Network dashboard script not found", "ERROR")
                
        except Exception as e:
            self.log(f"❌ Failed to start network dashboard: {e}", "ERROR")
            
    def start_frontend_server(self):
        """Start the frontend server"""
        self.log("Starting Frontend Server...")
        
        try:
            # Create a simple FastAPI server for the frontend
            app = FastAPI(title="MediVote Frontend")
            
            # Add CORS middleware
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
            # Mount static files
            frontend_dir = self.base_dir / "frontend"
            if frontend_dir.exists():
                app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="static")
                
                # Add API proxy endpoints
                @app.get("/api/proxy/backend")
                async def proxy_backend():
                    try:
                        response = requests.get(f"http://localhost:{self.config['backend_port']}/api/status")
                        return response.json()
                    except:
                        return {"error": "Backend not available"}
                        
                @app.get("/api/proxy/blockchain")
                async def proxy_blockchain():
                    try:
                        response = requests.get(f"http://localhost:{self.config['blockchain_port']}/status")
                        return response.json()
                    except:
                        return {"error": "Blockchain not available"}
                        
                @app.get("/api/proxy/incentive")
                async def proxy_incentive():
                    try:
                        response = requests.get(f"http://localhost:{self.config['incentive_port']}/status")
                        return response.json()
                    except:
                        return {"error": "Incentive system not available"}
                
                config = uvicorn.Config(
                    app=app,
                    host="0.0.0.0",
                    port=self.config['frontend_port'],
                    log_level="info"
                )
                
                server = uvicorn.Server(config)
                
                def run_frontend():
                    server.run()
                    
                frontend_thread = threading.Thread(target=run_frontend, daemon=True)
                frontend_thread.start()
                
                self.processes['frontend'] = frontend_thread
                self.log("✅ Frontend server started successfully")
            else:
                self.log("❌ Frontend directory not found", "ERROR")
                
        except Exception as e:
            self.log(f"❌ Failed to start frontend server: {e}", "ERROR")
            
    def wait_for_services(self):
        """Wait for all services to be ready"""
        self.log("Waiting for services to be ready...")
        
        services = [
            ("Backend", f"http://localhost:{self.config['backend_port']}/health"),
            ("Blockchain", f"http://localhost:{self.config['blockchain_port']}/status"),
            ("Incentive System", f"http://localhost:{self.config['incentive_port']}/status"),
            ("Network Coordinator", f"http://localhost:{self.config['coordinator_port']}/status"),
            ("Network Dashboard", f"http://localhost:{self.config['dashboard_port']}/status")
        ]
        
        for service_name, url in services:
            max_retries = 30
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    response = requests.get(url, timeout=2)
                    if response.status_code == 200:
                        self.log(f"✅ {service_name} is ready")
                        break
                except:
                    retry_count += 1
                    time.sleep(1)
                    
            if retry_count >= max_retries:
                self.log(f"⚠️ {service_name} may not be ready", "WARNING")
                
    def print_system_info(self):
        """Print system information and access URLs"""
        self.log("🎉 MediVote Integrated System is running!")
        self.log("=" * 60)
        self.log("System Components:")
        self.log(f"  • Backend API: http://localhost:{self.config['backend_port']}")
        self.log(f"  • Frontend: http://localhost:{self.config['frontend_port']}")
        self.log(f"  • Blockchain Node: http://localhost:{self.config['blockchain_port']}")
        self.log(f"  • Incentive System: http://localhost:{self.config['incentive_port']}")
        self.log(f"  • Network Coordinator: http://localhost:{self.config['coordinator_port']}")
        self.log(f"  • Network Dashboard: http://localhost:{self.config['dashboard_port']}")
        self.log("=" * 60)
        self.log("Quick Start:")
        self.log("  1. Open http://localhost:8080 in your browser")
        self.log("  2. Register as a voter")
        self.log("  3. Run a blockchain node to create ballots")
        self.log("  4. Cast your vote securely")
        self.log("=" * 60)
        
    def start_all_services(self):
        """Start all MediVote services"""
        self.log("🚀 Starting MediVote Integrated System...")
        
        # Start services in order
        self.start_backend()
        time.sleep(2)
        
        self.start_blockchain_node()
        time.sleep(1)
        
        self.start_network_coordinator()
        time.sleep(1)
        
        self.start_incentive_system()
        time.sleep(1)
        
        self.start_network_dashboard()
        time.sleep(1)
        
        self.start_frontend_server()
        time.sleep(2)
        
        # Wait for services to be ready
        self.wait_for_services()
        
        # Print system information
        self.print_system_info()
        
    def stop_all_services(self):
        """Stop all running services"""
        self.log("🛑 Stopping all services...")
        
        for name, process in self.processes.items():
            try:
                if hasattr(process, 'terminate'):
                    process.terminate()
                    process.wait(timeout=5)
                self.log(f"✅ Stopped {name}")
            except Exception as e:
                self.log(f"❌ Failed to stop {name}: {e}", "ERROR")
                
    def run(self):
        """Run the integrated system"""
        try:
            self.start_all_services()
            
            # Keep the main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.log("🛑 Received shutdown signal...")
            self.stop_all_services()
            self.log("👋 MediVote system shutdown complete")

if __name__ == "__main__":
    system = MediVoteIntegratedSystem()
    system.run() 