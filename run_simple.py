#!/usr/bin/env python3
"""
Simple MediVote Runner
Starts backend and frontend only
"""

import os
import sys
import time
import subprocess
import requests
from pathlib import Path

def log(message):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def start_backend():
    """Start the backend server"""
    log("🚀 Starting Backend Server...")
    
    try:
        # Start backend using uvicorn
        process = subprocess.Popen([
            sys.executable, "-m", "uvicorn", 
            "backend.main:app",
            "--host", "0.0.0.0",
            "--port", "8001",
            "--reload", "false"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(5)  # Give it time to start
        
        # Test if it's running
        try:
            response = requests.get("http://localhost:8001/health", timeout=10)
            if response.status_code == 200:
                log("✅ Backend is running")
                return process
        except:
            pass
            
        log("❌ Backend failed to start")
        return None
        
    except Exception as e:
        log(f"❌ Error starting backend: {e}")
        return None

def start_frontend():
    """Start frontend server"""
    log("🚀 Starting Frontend Server...")
    
    try:
        frontend_dir = Path("frontend")
        if frontend_dir.exists():
            process = subprocess.Popen([
                sys.executable, "-m", "http.server", 
                "8080",
                "--directory", str(frontend_dir)
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(3)
            
            # Test if it's running
            try:
                response = requests.get("http://localhost:8080/", timeout=10)
                if response.status_code == 200:
                    log("✅ Frontend is running")
                    return process
            except:
                pass
                
            log("❌ Frontend failed to start")
            return None
        else:
            log("❌ Frontend directory not found")
            return None
            
    except Exception as e:
        log(f"❌ Error starting frontend: {e}")
        return None

def main():
    """Main function"""
    log("🚀 Starting MediVote System...")
    
    # Kill existing processes
    try:
        subprocess.run(["taskkill", "/F", "/IM", "python.exe"], 
                      capture_output=True, check=False)
        time.sleep(2)
    except:
        pass
    
    # Start components
    backend_process = start_backend()
    frontend_process = start_frontend()
    
    if backend_process and frontend_process:
        log("🎉 MediVote System is Running!")
        print("\n" + "=" * 50)
        print("🌐 Access URLs:")
        print("  Frontend: http://localhost:8080")
        print("  Backend:  http://localhost:8001")
        print("=" * 50)
        print("📝 Quick Start:")
        print("1. Open http://localhost:8080 in your browser")
        print("2. Register as a voter")
        print("3. Cast your vote securely")
        print("=" * 50)
        print("💡 Press Ctrl+C to stop")
        print("=" * 50)
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log("🛑 Shutting down...")
            if backend_process:
                backend_process.terminate()
            if frontend_process:
                frontend_process.terminate()
            log("✅ Stopped all services")
    else:
        log("❌ Failed to start system")

if __name__ == "__main__":
    main() 