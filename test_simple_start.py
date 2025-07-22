#!/usr/bin/env python3
"""
Simple test to check if service manager can start
"""

import subprocess
import time
import requests

def test_simple_start():
    """Test if service manager can start"""
    print("🧪 Testing Service Manager Startup")
    print("=" * 40)
    
    try:
        # Try to start the service manager
        print("🚀 Starting service manager...")
        process = subprocess.Popen(
            ["python", "start_medivote_background.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait a bit for startup
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Service manager process is running")
            
            # Try to connect to the dashboard
            try:
                response = requests.get("http://localhost:8090", timeout=5)
                if response.status_code == 200:
                    print("✅ Dashboard is accessible")
                    return True
                else:
                    print(f"⚠️ Dashboard returned status: {response.status_code}")
            except requests.exceptions.ConnectionError:
                print("❌ Dashboard not accessible yet")
            except Exception as e:
                print(f"❌ Error accessing dashboard: {e}")
        else:
            print("❌ Service manager process stopped")
            stdout, stderr = process.communicate()
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
        
        # Clean up
        process.terminate()
        process.wait()
        
    except Exception as e:
        print(f"❌ Error starting service manager: {e}")
    
    return False

if __name__ == "__main__":
    success = test_simple_start()
    print(f"\n🎯 Test Result: {'✅ PASS' if success else '❌ FAIL'}") 