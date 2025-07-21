#!/usr/bin/env python3
"""Simple test for Stop button functionality"""

import requests
import json

# Test stopping the backend service
print("Testing Stop button functionality...")
print("=" * 50)

try:
    # First check status
    print("\n1. Checking current status...")
    response = requests.get("http://localhost:8090/status")
    if response.status_code == 200:
        status = response.json()
        backend_status = status.get('backend', {})
        print(f"Backend status: {backend_status.get('status', 'unknown')}")
    
    # Try to stop backend
    print("\n2. Sending POST /stop/backend...")
    response = requests.post("http://localhost:8090/stop/backend")
    print(f"Response status: {response.status_code}")
    print(f"Response text: {response.text}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"Success: {data.get('success')}")
        print(f"Error: {data.get('error')}")
    
    # Check status again
    print("\n3. Checking status after stop...")
    import time
    time.sleep(2)
    response = requests.get("http://localhost:8090/status")
    if response.status_code == 200:
        status = response.json()
        backend_status = status.get('backend', {})
        print(f"Backend status: {backend_status.get('status', 'unknown')}")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc() 