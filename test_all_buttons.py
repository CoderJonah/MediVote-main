#!/usr/bin/env python3
"""Test all button functionality"""

import requests
import json
import time

print("Testing MediVote Service Manager Buttons")
print("=" * 50)

# Get initial status
print("\n1. Initial Status:")
response = requests.get("http://localhost:8090/status")
status = response.json()
for service_id, info in status.items():
    print(f"   {info['name']}: {info['status']}")

# Test stopping backend
print("\n2. Testing STOP button for backend...")
response = requests.post("http://localhost:8090/stop/backend", timeout=5)
result = response.json()
print(f"   Result: {result}")
time.sleep(2)

# Check status after stop
print("\n3. Status after STOP:")
response = requests.get("http://localhost:8090/status")
backend_status = response.json().get('backend', {})
print(f"   Backend: {backend_status.get('status', 'unknown')}")

# Test starting backend
print("\n4. Testing START button for backend...")
response = requests.post("http://localhost:8090/start/backend", timeout=5)
result = response.json()
print(f"   Result: {result}")
time.sleep(3)

# Check status after start
print("\n5. Status after START:")
response = requests.get("http://localhost:8090/status")
backend_status = response.json().get('backend', {})
print(f"   Backend: {backend_status.get('status', 'unknown')}")

# Test restart
print("\n6. Testing RESTART button for frontend...")
response = requests.post("http://localhost:8090/restart/frontend", timeout=5)
result = response.json()
print(f"   Result: {result}")
time.sleep(3)

# Final status
print("\n7. Final Status:")
response = requests.get("http://localhost:8090/status")
status = response.json()
for service_id, info in status.items():
    print(f"   {info['name']}: {info['status']}")

print("\n✅ All button tests completed!") 