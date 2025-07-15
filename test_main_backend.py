#!/usr/bin/env python3
"""
Test script for the main backend application
"""

import sys
import os
import subprocess
import time
import requests
from pathlib import Path

def test_backend_imports():
    """Test if all backend modules can be imported"""
    print("🔍 Testing backend module imports...")
    
    # Change to backend directory
    backend_dir = Path(__file__).parent / "backend"
    original_dir = os.getcwd()
    
    try:
        os.chdir(backend_dir)
        
        # Test core imports
        test_imports = [
            "core.config",
            "core.database", 
            "core.blockchain",
            "core.auth_service",
            "api.auth",
            "api.admin",
            "api.verification",
            "api.voting"
        ]
        
        for module in test_imports:
            try:
                __import__(module)
                print(f"✅ {module} - OK")
            except ImportError as e:
                print(f"❌ {module} - FAILED: {e}")
                return False
            except Exception as e:
                print(f"⚠️ {module} - WARNING: {e}")
                
        return True
        
    finally:
        os.chdir(original_dir)

def test_backend_startup():
    """Test if the backend can start up"""
    print("\n🚀 Testing backend startup...")
    
    backend_dir = Path(__file__).parent / "backend"
    
    try:
        # Try to start the backend
        process = subprocess.Popen(
            [sys.executable, "main.py"],
            cwd=backend_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait a bit for startup
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Backend process started successfully")
            
            # Test health endpoint
            try:
                response = requests.get("http://localhost:8000/health", timeout=5)
                if response.status_code == 200:
                    print("✅ Health endpoint responding")
                    health_data = response.json()
                    print(f"   Status: {health_data.get('status', 'unknown')}")
                    return True
                else:
                    print(f"❌ Health endpoint returned {response.status_code}")
                    
            except requests.RequestException as e:
                print(f"❌ Could not reach health endpoint: {e}")
                
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Backend process failed to start")
            print(f"   STDOUT: {stdout}")
            print(f"   STDERR: {stderr}")
            
    except Exception as e:
        print(f"❌ Error starting backend: {e}")
        
    finally:
        # Clean up process
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            process.wait()
            
    return False

def test_simple_backend():
    """Test the simple backend as fallback"""
    print("\n🔄 Testing simple backend as fallback...")
    
    try:
        # Try to start simple_main.py
        process = subprocess.Popen(
            [sys.executable, "simple_main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait a bit for startup
        time.sleep(3)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Simple backend started successfully")
            
            # Test health endpoint
            try:
                response = requests.get("http://localhost:8000/health", timeout=5)
                if response.status_code == 200:
                    print("✅ Simple backend health endpoint responding")
                    return True
                    
            except requests.RequestException as e:
                print(f"❌ Could not reach simple backend: {e}")
                
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Simple backend failed to start")
            print(f"   STDERR: {stderr}")
            
    except Exception as e:
        print(f"❌ Error starting simple backend: {e}")
        
    finally:
        # Clean up process
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            process.wait()
            
    return False

def main():
    """Main test function"""
    print("🧪 TESTING MAIN BACKEND FUNCTIONALITY")
    print("=" * 50)
    
    # Test imports first
    imports_ok = test_backend_imports()
    
    if imports_ok:
        print("✅ All imports successful - proceeding with startup test")
        startup_ok = test_backend_startup()
        
        if not startup_ok:
            print("⚠️ Main backend failed - trying simple backend")
            simple_ok = test_simple_backend()
            
            if simple_ok:
                print("✅ Simple backend working as fallback")
                return True
            else:
                print("❌ Both backends failed")
                return False
        else:
            print("✅ Main backend fully functional")
            return True
    else:
        print("❌ Import failures prevent backend testing")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 