#!/usr/bin/env python3
"""
MediVote Demo Startup Script
Starts backend, creates demo data, and launches frontend
"""

import subprocess
import sys
import time
import os
import signal
import requests
from pathlib import Path

def check_port_available(port):
    """Check if a port is available"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            return True
        except OSError:
            return False

def wait_for_backend():
    """Wait for the backend to be ready"""
    print("⏳ Waiting for backend to start...")
    for i in range(30):  # Wait up to 30 seconds
        try:
            response = requests.get('http://localhost:8000/health', timeout=2)
            if response.status_code == 200:
                print("✅ Backend is ready!")
                return True
        except:
            pass
        time.sleep(1)
        if i % 5 == 0:
            print(f"   Still waiting... ({i+1}/30)")
    
    print("❌ Backend failed to start within 30 seconds")
    return False

def create_demo_data():
    """Create demo ballot and voter data"""
    print("📋 Creating demo data...")
    
    try:
        # Run the demo creation script
        result = subprocess.run([sys.executable, 'create_demo_ballot.py'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Demo data created successfully!")
            return True
        else:
            print(f"❌ Failed to create demo data:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Error creating demo data: {e}")
        return False

def start_backend():
    """Start the backend server"""
    print("🚀 Starting MediVote backend server...")
    
    # Check if backend is already running
    if not check_port_available(8000):
        print("⚠️  Port 8000 is already in use. Backend might already be running.")
        return None
    
    try:
        # Start backend process
        backend_process = subprocess.Popen(
            [sys.executable, 'backend/main.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("✅ Backend server started (PID: {})".format(backend_process.pid))
        return backend_process
        
    except Exception as e:
        print(f"❌ Failed to start backend: {e}")
        return None

def start_frontend():
    """Start the frontend server"""
    print("🌐 Starting frontend server...")
    
    # Check if frontend is already running
    if not check_port_available(3000):
        print("⚠️  Port 3000 is already in use. Frontend might already be running.")
        return None
    
    try:
        # Change to frontend directory
        frontend_dir = Path('frontend')
        if not frontend_dir.exists():
            print("❌ Frontend directory not found!")
            return None
        
        # Start frontend process
        frontend_process = subprocess.Popen(
            [sys.executable, 'serve.py'],
            cwd=frontend_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        print("✅ Frontend server started (PID: {})".format(frontend_process.pid))
        return frontend_process
        
    except Exception as e:
        print(f"❌ Failed to start frontend: {e}")
        return None

def cleanup_processes(processes):
    """Clean up running processes"""
    print("\n🧹 Cleaning up processes...")
    
    for name, process in processes.items():
        if process and process.poll() is None:
            print(f"   Stopping {name}...")
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except:
                pass

def main():
    """Main function to start the demo"""
    
    print("🗳️  MediVote Demo Startup")
    print("=" * 50)
    
    # Check dependencies
    required_files = ['simple_main.py', 'create_demo_ballot.py', 'frontend/index.html']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   • {file}")
        return
    
    processes = {}
    
    try:
        # Start backend
        backend_process = start_backend()
        if backend_process:
            processes['backend'] = backend_process
        
        # Wait for backend to be ready
        if not wait_for_backend():
            cleanup_processes(processes)
            return
        
        # Create demo data
        if not create_demo_data():
            print("⚠️  Demo data creation failed, but continuing with servers...")
        
        # Start frontend
        frontend_process = start_frontend()
        if frontend_process:
            processes['frontend'] = frontend_process
        
        # Wait a moment for frontend to start
        time.sleep(2)
        
        # Show status
        print("\n🎉 MediVote Demo is running!")
        print("=" * 50)
        print("📱 Frontend: http://localhost:3000")
        print("🔗 Backend API: http://localhost:8000")
        print("📖 API Documentation: http://localhost:8000/docs")
        print("\n🗳️  Demo Features:")
        print("   • Presidential Election Demo ballot")
        print("   • 4 sample candidates")
        print("   • Cryptographic vote verification")
        print("   • Real-time results display")
        print("   • Admin panel for ballot management")
        print("\n👤 Demo Voter:")
        print("   • Name: Demo User")
        print("   • Email: john.doe@example.com")
        print("\n📋 Usage:")
        print("   1. Open http://localhost:3000 in your browser")
        print("   2. Register as a voter or use the demo voter")
        print("   3. Cast votes in the demo election")
        print("   4. Verify your votes using the receipt")
        print("   5. View real-time results")
        print("   6. Try the admin panel to create more ballots")
        
        print("\n⚠️  Press Ctrl+C to stop all servers")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if backend_process and backend_process.poll() is not None:
                print("❌ Backend process died unexpectedly")
                break
                
            if frontend_process and frontend_process.poll() is not None:
                print("❌ Frontend process died unexpectedly")
                break
    
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested...")
    
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    
    finally:
        cleanup_processes(processes)
        print("✅ All processes stopped. Goodbye!")

if __name__ == "__main__":
    main() 